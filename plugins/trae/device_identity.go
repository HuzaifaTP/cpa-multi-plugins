// device_identity.go — v0.12.76: stable per-installation login device identity
// （稳定设备身份：同一安装的每次登录复用同一台“设备”，不再每次铸新）.
//
// Root cause this file fixes (issue #38 余波, user-reported + live-verified):
// every login used to mint a BRAND-NEW device identity — newDeviceID() +
// newMachineID() at the login start, plus a fresh EC P-256 key pair at each
// of the four exchange points. The server registers every distinct identity
// as a separate device, so repeated logins (compounded by the v0.8.63
// stuck-login retry era) burned one device slot per attempt until the
// account hit
//
//	ExchangeToken => HTTP 403 upstream code=20401 (Device limit reached.)
//
// and was locked out of logging in at all. The official IDE's contract is
// ONE device identity per INSTALLATION: the same install reuses the same
// deviceId/machineId/key pair for every login and every bound refresh.
//
// Resolution order (per normalized variant cn/solo/intl):
//  1. the identity file <AuthDir>/.trae-device-identity-<variant>.json
//     (same dir + dot-prefix + per-variant convention as
//     .trae-pending-login.json, so the credential claim logic in adopt.go —
//     which matches prefixes "trae-cn-"/"trae-solo-cn-"/"trae-intl-" — can
//     never mistake it for a credential);
//  2. seed from an existing credential in the same dir (trae-*.json): exact
//     variant match preferred, newest mtime as the tiebreak — reconnects
//     this install to the device slot its own earlier credential already
//     registered server-side;
//  3. mint a fresh identity and persist it for future logins.
//
// The EC P-256 key pair is persisted WITH the identity: it is part of the
// device fingerprint the server binds (first exchange uploads the SPKI
// public key), not a per-login secret. Identity persistence failures NEVER
// fail the login — an in-memory identity still logs in (the pre-v0.12.76
// behavior); it just cannot be reused by the next login.
package main

import (
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

// seedDeviceIdentityFromDir adopts the device identity of an existing
// credential (trae-*.json) in authDir. Scoring: exact normalized-variant
// match = 2, anything else = 1; equal scores break on the newest ModTime.
// Files that fail auth.Parse (foreign/partial) are silently skipped. A nil
// return means "nothing to inherit".
func seedDeviceIdentityFromDir(authDir, variant string) *deviceIdentity {
	nv := normalizeVariant(variant)
	files, err := filepath.Glob(filepath.Join(authDir, "trae-*.json"))
	if err != nil {
		return nil
	}
	var best *deviceIdentity
	bestScore := 0
	var bestMod time.Time
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		a, err := auth.Parse(raw)
		if err != nil {
			continue // not one of our credentials — silently skip
		}
		if strings.TrimSpace(a.DeviceID) == "" || strings.TrimSpace(a.MachineID) == "" {
			continue
		}
		score := 1
		if normalizeVariant(a.Variant) == nv {
			score = 2
		}
		var mod time.Time
		if st, statErr := os.Stat(f); statErr == nil {
			mod = st.ModTime()
		}
		if best != nil && (score < bestScore || (score == bestScore && !mod.After(bestMod))) {
			continue
		}
		best = &deviceIdentity{
			DeviceID:         a.DeviceID,
			MachineID:        a.MachineID,
			DevicePublicKey:  a.DevicePublicKey,
			DevicePrivateKey: a.DevicePrivateKey,
			Variant:          nv,
			Source:           "seed:" + filepath.Base(f),
		}
		bestScore = score
		bestMod = mod
	}
	return best
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

// ensureLoginDeviceIdentity is the single entry point every login path uses
// to resolve this installation's device identity for a variant. Resolution
// order: identity file → seed from an existing credential → mint. It NEVER
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
		// than failing the login — it is exactly the pre-v0.12.76 behavior,
		// just confined to this one login.
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
	if id := seedDeviceIdentityFromDir(dir, nv); id != nil {
		completeDeviceKeys(id)
		// 钉盘：继承来的身份必须落盘 —— 即使日后凭证被删除，本安装仍复用
		// 同一设备位（20401 恢复承诺：直接重试即可成功）。
		persistDeviceIdentityBestEffort(dir, id)
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
