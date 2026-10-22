// device_identity.go — v0.12.79: ONE sign-in device identity per login,
// from the authorization URL all the way to the bound refresh (magpie
// semantics; issue #47 hotfix).
//
// History:
//   - v0.12.75 and earlier minted a RANDOM device per login attempt — the
//     pile-up that locked accounts out with 403 code=20401 "Device limit
//     reached" (issue #38 aftermath).
//   - v0.12.76 shipped a stable PER-INSTALL identity (one device shared by
//     every account of a variant on this machine). User review rejected the
//     SHAPE (many accounts hopping on one server-side device), not the
//     stability.
//   - v0.12.77/v0.12.78 tried to square that circle by deriving the device
//     PER ACCOUNT — deriveAccountDeviceIdentity(variant, uid), applied the
//     moment the OAuth callback echoed the account's uid. That was WRONG:
//     the authorization-page URL is built BEFORE anyone knows which account
//     is logging in, so it carried the install's BOOTSTRAP device while the
//     ExchangeToken carried the DERIVED one. Upstream ties every auth code
//     to the device of the URL that requested it and now enforces the match
//     (live 2026-10-20/21, issue #47: EVERY fresh CN/intl login died with
//     HTTP 401 code=20403 "Token device not match"). The earlier
//     "live-proven 2026-10: the server happily registered a different
//     identity" observation no longer holds — the gate was tightened.
//   - v0.12.79 (this file): the sign-in identity — the bootstrap identity
//     resolved at start-login — is THE identity for the whole login: URL
//     params, ExchangeToken DeviceInfo, saved credential and every later
//     bound refresh all read the same loginCtx fields, and nothing swaps
//     them mid-flight. That is exactly what the official IDE and the magpie
//     reference do (newDevice() once at sign-in, shared by the URL and
//     signedIn()).
//
// What remains of the per-account derivation: deriveAccountDeviceIdentity
// is kept as a PURE, side-effect-free function and the callback handlers
// call noteAccountDeviceIdentityCN/Intl to log what the account's canonical
// device WOULD be — useful diagnostics for 20401/20403 reports, and the
// building block for a future two-phase login (panel-side account selection
// or a re-issued authorization with the derived device) IF per-account
// devices are ever wanted. It is never applied to a live login ctx anymore.
//
// Consequences of the one-device-per-login model:
//   - Re-logins never mint a new device, so the 20401 device-cap burn of
//     v0.12.75-and-earlier stays fixed (the bootstrap identity is stable on
//     disk per variant).
//   - Several accounts of one variant on one installation share that
//     variant's bootstrap device — the trade the 20403 gate forces on us;
//     the alternative (per-account devices) requires knowing the account
//     before the URL exists.
//   - Credentials saved by v0.12.77/v0.12.78 (derived device + derived
//     keys, tokens actually bound elsewhere) cannot refresh — they must
//     re-login once on v0.12.79+ to land on a consistent identity.
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
// v0.12.77 REMOVED it on purpose: the sign-in identity must stay the
// installation's own device. Adopting an account credential's identity
// would put account A's real device on account B's authorization page (and,
// before the per-account derivation existed, converged every account onto
// one shared device). Nothing here reads credentials anymore.

// deriveAccountDeviceIdentity returns the deterministic device identity of
// ONE account: a pure function of (normalized variant, uid). The same inputs
// always yield the same deviceId / machineId / P-256 key pair. v0.12.79:
// DIAGNOSTICS AND FUTURE USE ONLY — it is never applied to a live login
// anymore (the 20403 guard, see the file header); the callback handlers log
// the derived identity so operators can correlate 20401/20403 reports with
// what the account's canonical device would be. A blank uid returns nil.
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

// noteAccountDeviceIdentityCN records what the account's canonical device
// WOULD be, without touching the login ctx. Called the moment the callback
// reveals WHO is logging in (userInfo echo).
//
// v0.12.77/v0.12.78 used to SWAP the ctx onto this derived identity right
// here; that made the ExchangeToken present a different device than the
// authorization-page URL (built earlier, before the uid was known), and
// upstream answers that with HTTP 401 code=20403 "Token device not match"
// on every fresh login (issue #47). The sign-in identity now stays untouched
// for the whole flow; the derived value is logged for diagnostics only.
func noteAccountDeviceIdentityCN(lc *loginCtx, uid string) {
	if lc == nil {
		return
	}
	id := deriveAccountDeviceIdentity(lc.variant, uid)
	if id == nil {
		return
	}
	// NEVER swap lc's device: upstream ties the auth code to the URL's
	// device (20403). The sign-in identity flows to the exchange, the
	// saved credential and every bound refresh unchanged.
	log.Printf("trae login: keeping the sign-in device identity (uid=%s variant=%s deviceId=%s machineId=%s; derived %s NOT applied — upstream ties the auth code to the URL device)",
		strings.TrimSpace(uid), id.Variant, lc.deviceID, lc.machineID, id.DeviceID)
}

// noteAccountDeviceIdentityIntl is the intl-flow counterpart of
// noteAccountDeviceIdentityCN.
func noteAccountDeviceIdentityIntl(lc *intlloginCtx, uid string) {
	if lc == nil {
		return
	}
	id := deriveAccountDeviceIdentity(variantIntl, uid)
	if id == nil {
		return
	}
	// NEVER swap lc's device (20403 guard, see noteAccountDeviceIdentityCN).
	log.Printf("trae-intl login: keeping the sign-in device identity (uid=%s deviceId=%s machineId=%s; derived %s NOT applied — upstream ties the auth code to the URL device)",
		strings.TrimSpace(uid), lc.deviceID, lc.machineID, id.DeviceID)
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

// ensureLoginDeviceIdentity resolves the installation's SIGN-IN identity
// for a variant — v0.12.79: this is THE device of the whole login. It rides
// the authorization-page URL, the ExchangeToken DeviceInfo, the saved
// credential and every later bound refresh (see the file header: upstream
// ties the auth code to the URL's device, so nothing may swap this identity
// mid-flight). Stable on disk per variant, so re-logins never mint a new
// device (the 20401 fix). Resolution: identity file → mint. NO credential
// seeding — an account credential's device must never leak into another
// account's login. It NEVER returns nil and never fails the login on
// persistence problems.
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
		// than failing the login — the login proceeds with a device that
		// only lives for this process (next login mints a fresh one).
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
