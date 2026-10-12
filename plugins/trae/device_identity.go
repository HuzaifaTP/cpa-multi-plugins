// device_identity.go — v0.12.77: per-ACCOUNT deterministic login device identity
// （按账号派生的固定设备身份：每个账号一套永久稳定的设备指纹，账号间互不相同）.
//
// v0.12.76 shipped a stable PER-INSTALL identity (one device shared by every
// account of a variant on this machine). User review rejected that shape:
// multiple accounts of the same provider then present ONE server-side device
// hopping between accounts — the exact fingerprint pattern upstream security
// flags, and fundamentally the wrong model for a multi-account gateway.
//
// v0.12.77 model (this file):
//   - The identity that gets REGISTERED/BIND at ExchangeToken is DERIVED from
//     the account: deriveAccountDeviceIdentity(variant, uid) is a pure
//     function — deviceId (16 digits), machineId (UUID-v4 shaped) and the
//     P-256 device key pair are all deterministic functions of
//     (variant, uid). Same account → same device, on every login, on every
//     install, forever (re-logins can never burn another device slot, which
//     is what locked accounts out with 403 code=20401 "Device limit reached").
//     Different accounts → different devices. A solo login of the same human
//     gets its own device too (solo and cn are different server lineages —
//     v0.12.60's cross-lineage poisoning).
//   - The identity is known the moment the OAuth callback echoes userInfo
//     (the account's uid — login_identity.go parses it, cockpit-tools
//     TraeCallbackPayload.userInfo). The callback handlers therefore APPLY
//     the derived identity to the login ctx before any exchange point runs.
//     Server-side, the ExchangeToken DeviceInfo is what registers the device
//     (live-proven 2026-10: the pre-v0.12.76 restore path presented a
//     DIFFERENT identity than the authorization URL and the server happily
//     registered it — the very behavior that piled devices up), so the
//     authorization-URL params do not need to match.
//   - What remains per-install is only the BOOTSTRAP identity
//     (.trae-device-identity-<variant>.json): a synthetic device for the
//     authorization-page URL, which is built BEFORE anyone knows which
//     account is logging in. It is never bound to tokens, and it is NEVER
//     adopted from a credential (v0.12.76 did seed it from credentials —
//     that would put account A's device on account B's login page).
//   - Callbacks without a userInfo echo (rare) keep the bootstrap identity
//     for that login; the credential then carries it and refreshes reuse it.
//     The account migrates to its derived identity at the next login that
//     does echo the uid (the normal path).
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/auth"
)

// deviceIdentityFilePattern is the per-variant identity file name; %s is the
// normalized variant (cn|solo|intl), matching the pending-login file's
// dot-prefix convention so the host/claim logic ignores it.
const deviceIdentityFilePattern = ".trae-device-identity-%s.json" // %s = 归一化 variant

// deviceIdentity is the stable device fingerprint one installation reuses
// for every login of a given variant. Source records where it came from
// ("seed:<file>" | "minted" | "restored") for diagnostics.
type deviceIdentity struct {
	DeviceID         string `json:"device_id"`
	MachineID        string `json:"machine_id"`
	DevicePublicKey  string `json:"device_public_key,omitempty"`
	DevicePrivateKey string `json:"device_private_key,omitempty"`
	Variant          string `json:"variant,omitempty"`
	Source           string `json:"source,omitempty"` // "seed:<file>" | "minted" | "restored"
	CreatedAt        int64  `json:"created_at,omitempty"`
}

// deviceIdentityMu serializes identity resolution + persistence: start-login,
// the four exchange points and self-completion may race on the same auth dir
// (a torn read-modify-write could mint two identities for one install).
var deviceIdentityMu sync.Mutex

// deviceIdentityPath returns the identity file path for a (raw) variant.
func deviceIdentityPath(authDir, variant string) string {
	return filepath.Join(authDir, fmt.Sprintf(deviceIdentityFilePattern, normalizeVariant(variant)))
}

// loadDeviceIdentity reads the persisted identity. Any problem (missing
// file, corrupt JSON, empty ids) degrades to nil — the caller re-seeds or
// re-mints; a broken identity file must never break the login.
func loadDeviceIdentity(authDir, variant string) *deviceIdentity {
	raw, err := os.ReadFile(deviceIdentityPath(authDir, variant))
	if err != nil {
		return nil
	}
	var id deviceIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil
	}
	if strings.TrimSpace(id.DeviceID) == "" || strings.TrimSpace(id.MachineID) == "" {
		return nil
	}
	return &id
}

// seedDeviceIdentityFromDir was v0.12.76's credential-adoption step.
// v0.12.77 REMOVED it on purpose: the bootstrap identity must stay a
// synthetic per-install device. Adopting an account credential's identity
// would put account A's real device on account B's authorization page (and,
// before the per-account derivation existed, converged every account onto
// one shared device). Account identities now come exclusively from
// deriveAccountDeviceIdentity; nothing here reads credentials anymore.

// deriveAccountDeviceIdentity returns the deterministic device identity of
// ONE account: a pure function of (normalized variant, uid). The same inputs
// always yield the same deviceId / machineId / P-256 key pair — on this
// install, on any install, on every login — so the server sees exactly one
// stable device per account (the 20401 device-cap contract) and different
// accounts never share a device. A blank uid returns nil (caller keeps the
// bootstrap identity).
func deriveAccountDeviceIdentity(variant, uid string) *deviceIdentity {
	u := strings.TrimSpace(uid)
	if u == "" {
		return nil
	}
	nv := normalizeVariant(variant)
	id := &deviceIdentity{
		DeviceID:  derivedDeviceID(nv, u),
		MachineID: derivedMachineID(nv, u),
		Variant:   nv,
		Source:    "derived:account",
		CreatedAt: time.Now().Unix(),
	}
	pub, priv, err := auth.DeterministicDeviceKeyPair(deriveSeed("device-key", nv, u))
	if err != nil {
		// Deterministic generation cannot realistically fail (no RNG,
		// no IO); if it ever does, the ids still identify the device —
		// the exchange point will surface the missing keys itself.
		log.Printf("trae device identity: derive key pair for uid=%s variant=%s: %v", u, nv, err)
		return id
	}
	id.DevicePublicKey, id.DevicePrivateKey = pub, priv
	return id
}

// deriveAccountSeed labels the derivation inputs (domain separation: a
// device id, a machine id and a key seed must never collide with each other
// or across providers/versions).
const deriveAccountSeedPrefix = "cpa-multi-plugins/trae/account-device/v1"

func deriveSeed(label, variant, uid string) []byte {
	return []byte(deriveAccountSeedPrefix + "\n" + label + "\n" + variant + "\n" + uid)
}

// derivedDeviceID maps the account into the upstream's device-id shape:
// 16 decimal digits, first digit 1-9 (newDeviceID/randomDigits(16) shape;
// cockpit-tools is_numeric_id(8, 24), real IDE ids are 16-19 digit snowflakes).
func derivedDeviceID(variant, uid string) string {
	sum := sha256.Sum256(deriveSeed("device-id", variant, uid))
	n := binary.BigEndian.Uint64(sum[:8])
	// [1e15, 1e16) → exactly 16 digits, first digit 1-9.
	return fmt.Sprintf("%016d", 1_000_000_000_000_000+n%9_000_000_000_000_000)
}

// derivedMachineID maps the account into the machine-id shape the plugin
// mints (newUUIDv4): a dashed UUID with the v4 version/variant bits set.
func derivedMachineID(variant, uid string) string {
	sum := sha256.Sum256(deriveSeed("machine-id", variant, uid))
	b := make([]byte, 16)
	copy(b, sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// applyDerivedIdentityCN swaps a cn/solo login ctx onto the account's
// derived identity. Called the moment the callback reveals WHO is logging in
// (userInfo echo) — before any exchange point, GetUserInfo call or credential
// save reads the identity, so the whole downstream chain (exchange DeviceInfo,
// saved credential, later bound refreshes) carries the account's own device.
// Idempotent: the same uid always derives the same identity, so re-pasted
// callbacks and redirect retries are harmless.
func applyDerivedIdentityCN(lc *loginCtx, uid string) {
	if lc == nil {
		return
	}
	id := deriveAccountDeviceIdentity(lc.variant, uid)
	if id == nil {
		return
	}
	lc.deviceID, lc.machineID = id.DeviceID, id.MachineID
	lc.devicePublicKey, lc.devicePrivateKey = id.DevicePublicKey, id.DevicePrivateKey
	log.Printf("trae login: per-account device identity derived (uid=%s variant=%s deviceId=%s machineId=%s)",
		strings.TrimSpace(uid), id.Variant, id.DeviceID, id.MachineID)
}

// applyDerivedIdentityIntl is the intl-flow counterpart of
// applyDerivedIdentityCN.
func applyDerivedIdentityIntl(lc *intlloginCtx, uid string) {
	if lc == nil {
		return
	}
	id := deriveAccountDeviceIdentity(variantIntl, uid)
	if id == nil {
		return
	}
	lc.deviceID, lc.machineID = id.DeviceID, id.MachineID
	lc.devicePublicKey, lc.devicePrivateKey = id.DevicePublicKey, id.DevicePrivateKey
	log.Printf("trae-intl login: per-account device identity derived (uid=%s deviceId=%s machineId=%s)",
		strings.TrimSpace(uid), id.DeviceID, id.MachineID)
}

// persistDeviceIdentity writes the identity atomically (heal.go
// atomicWriteJSON: temp + fsync + rename — a torn identity file must never
// replace a good one while the host watcher reconciles the dir).
func persistDeviceIdentity(authDir string, id *deviceIdentity) error {
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteJSON(deviceIdentityPath(authDir, id.Variant), raw)
}

// persistDeviceIdentityBestEffort logs a persistence failure instead of
// propagating it: the identity file only benefits FUTURE logins, so the
// current login proceeds with the in-memory identity regardless.
func persistDeviceIdentityBestEffort(dir string, id *deviceIdentity) {
	if err := persistDeviceIdentity(dir, id); err != nil {
		log.Printf("trae device identity: persist %s: %v — login continues with the in-memory identity", deviceIdentityPath(dir, id.Variant), err)
	}
}

// mintDeviceIdentity mints a brand-new identity (ids + EC P-256 key pair).
// A key-generation failure leaves the keys empty and only logs — callers
// that need the keys (deviceKeysForLogin) surface the error themselves.
func mintDeviceIdentity(variant string) *deviceIdentity {
	id := &deviceIdentity{
		DeviceID:  newDeviceID(),
		MachineID: newMachineID(),
		Variant:   variant,
		Source:    "minted",
		CreatedAt: time.Now().Unix(),
	}
	pub, priv, err := generateDeviceKeyPair()
	if err != nil {
		log.Printf("trae device identity: generate key pair: %v — identity minted without a device key", err)
		return id
	}
	id.DevicePublicKey, id.DevicePrivateKey = pub, priv
	return id
}

// completeDeviceKeys fills in a key pair missing from a loaded/seeded
// identity (legacy identity file or pre-v0.12.76 credential). It reports
// whether it generated a pair, so the caller can persist the completed
// identity.
func completeDeviceKeys(id *deviceIdentity) bool {
	if id.DevicePublicKey != "" && id.DevicePrivateKey != "" {
		return false
	}
	pub, priv, err := generateDeviceKeyPair()
	if err != nil {
		log.Printf("trae device identity: generate key pair: %v — reusing identity without a device key", err)
		return false
	}
	id.DevicePublicKey, id.DevicePrivateKey = pub, priv
	return true
}

// ensureLoginDeviceIdentity resolves the installation's BOOTSTRAP identity
// for a variant — the synthetic device the authorization-page URL carries
// (the page is built before anyone knows which account is logging in; it is
// never registered or bound server-side, see the file header). Resolution:
// identity file → mint. v0.12.77: NO credential seeding — an account's real
// identity must never leak into another account's login page. It NEVER
// returns nil and never fails the login on persistence problems.
func ensureLoginDeviceIdentity(authDir, variant string) *deviceIdentity {
	deviceIdentityMu.Lock()
	defer deviceIdentityMu.Unlock()

	nv := normalizeVariant(variant)
	dir := strings.TrimSpace(authDir)
	if dir == "" {
		// No host AuthDir: fall back to the remembered/cwd-derived dir
		// (pending_persist.go cachedAuthDir, incl. <cwd>/auths).
		dir = cachedAuthDir()
	}
	if dir == "" {
		// Still nothing: an EPHEMERAL in-memory identity is strictly better
		// than failing the login — it only decorates the login page URL.
		return mintDeviceIdentity(nv)
	}
	if id := loadDeviceIdentity(dir, nv); id != nil {
		if id.Variant == "" {
			id.Variant = nv
		}
		// 补齐密钥后才需要回写（身份文件已在盘上且内容未变时无需重写）。
		if completeDeviceKeys(id) {
			persistDeviceIdentityBestEffort(dir, id)
		}
		return id
	}
	id := mintDeviceIdentity(nv)
	persistDeviceIdentityBestEffort(dir, id)
	return id
}

// deviceKeysForLogin resolves the device key pair for an exchange point.
// Carried keys (resolved at start-login and carried through the login ctx /
// pending record) win; otherwise the stable login identity supplies them.
// Only a key-generation failure returns an error — identity persistence is
// never an error (see ensureLoginDeviceIdentity).
func deviceKeysForLogin(carriedPub, carriedPriv, authDir, variant string) (pub, priv string, err error) {
	if strings.TrimSpace(carriedPub) != "" && strings.TrimSpace(carriedPriv) != "" {
		return carriedPub, carriedPriv, nil
	}
	ident := ensureLoginDeviceIdentity(authDir, variant)
	if ident.DevicePublicKey == "" || ident.DevicePrivateKey == "" {
		return "", "", fmt.Errorf("device key pair unavailable for the login device identity")
	}
	return ident.DevicePublicKey, ident.DevicePrivateKey, nil
}
