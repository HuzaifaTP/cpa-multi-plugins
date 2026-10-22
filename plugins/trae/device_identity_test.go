// device_identity_test.go — v0.12.77 per-account deterministic device identity.
//
// Pins the behaviors the fix depends on:
//  1. derivation: the same (variant, uid) always yields the EXACT identity
//     (ids + key pair) — re-logins can never burn another device slot
//     (the 20401 "Device limit reached" lockout);
//  2. separation: different accounts (and different variants of one account)
//     never share a device; shapes match what the upstream validates
//     (16-digit deviceId, UUID-v4 machineId, parseable P-256 PEM pair);
//  3. bootstrap hygiene: the per-install identity file is mint-once-reuse,
//     is NEVER adopted from an account credential, and a missing auth dir
//     degrades to an ephemeral identity instead of an error.
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// writeTestCredential writes a nested-shape trae credential file into dir
// (empty pub/priv simulates a pre-v0.12.73 credential without device keys)
// and returns its path.
func writeTestCredential(t *testing.T, dir, name, variant, deviceID, machineID, pub, priv string) string {
	t.Helper()
	authDoc := map[string]any{
		"accessToken":  "at-" + name,
		"refreshToken": "rt-" + name,
		"expiresAt":    time.Now().Add(time.Hour).Unix(),
		"domain":       "trae.cn",
		"apiHost":      "https://api.trae.cn",
		"machineId":    machineID,
		"deviceId":     deviceID,
		"variant":      variant,
	}
	if pub != "" {
		authDoc["devicePublicKey"] = pub
	}
	if priv != "" {
		authDoc["devicePrivateKey"] = priv
	}
	raw, err := json.MarshalIndent(map[string]any{
		"type":     "trae",
		"provider": "trae",
		"auth":     authDoc,
		"account":  map[string]any{"uid": "uid-" + name, "nickname": "nick-" + name},
		"disabled": false,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	return path
}

// TestDerivedIdentityStablePerAccount: two derivations for the same
// (variant, uid) — the property whose absence burned one device slot per
// login (20401). Keys included: the server binds the public key, so a
// changed pair is a changed device.
func TestDerivedIdentityStablePerAccount(t *testing.T) {
	first := deriveAccountDeviceIdentity("cn", "1237380756941412")
	if first == nil {
		t.Fatal("derive returned nil for a valid uid")
	}
	second := deriveAccountDeviceIdentity("cn", " 1237380756941412 ")
	if second == nil {
		t.Fatal("derive returned nil for a padded uid — uid must be trimmed")
	}
	if first.DeviceID != second.DeviceID || first.MachineID != second.MachineID {
		t.Fatalf("derived ids not stable: %s/%s vs %s/%s",
			first.DeviceID, first.MachineID, second.DeviceID, second.MachineID)
	}
	if first.DevicePublicKey != second.DevicePublicKey || first.DevicePrivateKey != second.DevicePrivateKey {
		t.Fatal("derived key pair not stable — the server would see a new device")
	}
	if first.Source != "derived:account" {
		t.Fatalf("Source = %q, want derived:account", first.Source)
	}
}

// TestDerivedIdentitySeparatesAccounts: every account gets its own device —
// the explicit user requirement (每个账户身份不应该一样). Also across
// variants: a solo login of the same human is a different server lineage.
func TestDerivedIdentitySeparatesAccounts(t *testing.T) {
	alice := deriveAccountDeviceIdentity("cn", "1000000000000001")
	bob := deriveAccountDeviceIdentity("cn", "1000000000000002")
	if alice.DeviceID == bob.DeviceID || alice.MachineID == bob.MachineID {
		t.Fatalf("two accounts share a device: %s/%s", alice.DeviceID, alice.MachineID)
	}
	if alice.DevicePublicKey == bob.DevicePublicKey || alice.DevicePrivateKey == bob.DevicePrivateKey {
		t.Fatal("two accounts share device key material")
	}
	solo := deriveAccountDeviceIdentity("solo", "1000000000000001")
	if solo.DeviceID == alice.DeviceID || solo.MachineID == alice.MachineID {
		t.Fatalf("cn and solo of one account share a device: %s/%s", solo.DeviceID, solo.MachineID)
	}
	intl := deriveAccountDeviceIdentity("intl", "1000000000000001")
	if intl.DeviceID == alice.DeviceID {
		t.Fatal("cn and intl of one account share a deviceId")
	}
}

// TestDerivedIdentityShapes: the derived identity must be indistinguishable
// from a minted one — 16-digit deviceId (first digit 1-9), UUID-v4 machineId,
// parseable SPKI/PKCS#8 PEM pair whose halves actually match.
func TestDerivedIdentityShapes(t *testing.T) {
	id := deriveAccountDeviceIdentity("cn", "1237380756941412")
	if ok, _ := regexp.MatchString(`^[1-9][0-9]{15}$`, id.DeviceID); !ok {
		t.Fatalf("deviceId %q is not 16 digits with a non-zero lead", id.DeviceID)
	}
	if ok, _ := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, id.MachineID); !ok {
		t.Fatalf("machineId %q is not UUID-v4 shaped", id.MachineID)
	}
	// Public half parses as SPKI P-256 and matches the private half.
	pubBlock, _ := pem.Decode([]byte(id.DevicePublicKey))
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("device public key is not a PUBLIC KEY PEM block")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse SPKI public key: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", pubAny)
	}
	privBlock, _ := pem.Decode([]byte(id.DevicePrivateKey))
	if privBlock == nil || privBlock.Type != "PRIVATE KEY" {
		t.Fatalf("device private key is not a PRIVATE KEY (PKCS#8) PEM block")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS#8 private key: %v", err)
	}
	priv, ok := privAny.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want *ecdsa.PrivateKey", privAny)
	}
	if priv.PublicKey.X.Cmp(pub.X) != 0 || priv.PublicKey.Y.Cmp(pub.Y) != 0 {
		t.Fatal("derived public key does not match the derived private key")
	}
	if !priv.Curve.IsOnCurve(pub.X, pub.Y) {
		t.Fatal("derived public point is not on P-256")
	}
}

// TestDerivedIdentityEmptyUID: a blank uid yields nil — the caller keeps the
// bootstrap identity instead of deriving a garbage "empty account" device.
func TestDerivedIdentityEmptyUID(t *testing.T) {
	if deriveAccountDeviceIdentity("cn", "") != nil {
		t.Fatal("empty uid must not derive an identity")
	}
	if deriveAccountDeviceIdentity("cn", "   ") != nil {
		t.Fatal("whitespace-only uid must not derive an identity")
	}
}

// TestNoteAccountDeviceIdentityNeverSwapsCtx: v0.12.79 (#47) — the
// callback "note" helpers must NEVER mutate the login ctx. v0.12.77/78
// swapped ids AND key pair onto the derived identity here, which made the
// ExchangeToken present a different device than the authorization URL —
// every fresh login died 401 20403.
func TestNoteAccountDeviceIdentityNeverSwapsCtx(t *testing.T) {
	lc := &loginCtx{variant: "cn", deviceID: "bootstrap-dev", machineID: "bootstrap-mach",
		devicePublicKey: "bootstrap-pub", devicePrivateKey: "bootstrap-priv"}
	noteAccountDeviceIdentityCN(lc, "1237380756941412")
	if lc.deviceID != "bootstrap-dev" || lc.machineID != "bootstrap-mach" {
		t.Fatalf("cn ctx ids swapped: %s/%s — the 20403 regression is back", lc.deviceID, lc.machineID)
	}
	if lc.devicePublicKey != "bootstrap-pub" || lc.devicePrivateKey != "bootstrap-priv" {
		t.Fatal("cn ctx key pair swapped — the 20403 regression is back")
	}
	// Re-pasted callback: still untouched (idempotent no-op).
	noteAccountDeviceIdentityCN(lc, "1237380756941412")
	if lc.deviceID != "bootstrap-dev" {
		t.Fatal("re-noted ctx mutated")
	}
	// No uid → untouched.
	noteAccountDeviceIdentityCN(lc, "")
	if lc.deviceID != "bootstrap-dev" {
		t.Fatal("empty uid mutated the ctx")
	}
	// nil ctx → no panic.
	noteAccountDeviceIdentityCN(nil, "1237380756941412")
}

// TestNoteAccountDeviceIdentityIntlCtx: the intl counterpart never swaps.
func TestNoteAccountDeviceIdentityIntlCtx(t *testing.T) {
	lc := &intlloginCtx{deviceID: "bootstrap-dev", machineID: "bootstrap-mach",
		devicePublicKey: "bootstrap-pub", devicePrivateKey: "bootstrap-priv"}
	noteAccountDeviceIdentityIntl(lc, "1b78b3c2-62f0-42e5-84fe-51e3c55e4914")
	if lc.deviceID != "bootstrap-dev" || lc.machineID != "bootstrap-mach" {
		t.Fatalf("intl ctx ids swapped: %s/%s — the 20403 regression is back", lc.deviceID, lc.machineID)
	}
	if lc.devicePublicKey != "bootstrap-pub" || lc.devicePrivateKey != "bootstrap-priv" {
		t.Fatal("intl ctx key pair swapped — the 20403 regression is back")
	}
	noteAccountDeviceIdentityIntl(nil, "1b78b3c2-62f0-42e5-84fe-51e3c55e4914")
}

// TestEnsureIdentityMintAndReuse: the sign-in identity file still mints
// once and reuses (the login device is stable per install — re-logins
// never mint a new device, the 20401 fix).
func TestEnsureIdentityMintAndReuse(t *testing.T) {
	dir := t.TempDir()
	first := ensureLoginDeviceIdentity(dir, "cn")
	if first.DeviceID == "" || first.MachineID == "" {
		t.Fatalf("minted identity missing ids: %+v", first)
	}
	if first.DevicePublicKey == "" || first.DevicePrivateKey == "" {
		t.Fatalf("minted identity missing key pair: %+v", first)
	}
	if _, err := os.Stat(deviceIdentityPath(dir, "cn")); err != nil {
		t.Fatalf("identity file not persisted: %v", err)
	}
	second := ensureLoginDeviceIdentity(dir, "cn")
	if second.DeviceID != first.DeviceID || second.MachineID != first.MachineID {
		t.Fatalf("identity ids not reused: first=%s/%s second=%s/%s",
			first.DeviceID, first.MachineID, second.DeviceID, second.MachineID)
	}
	if second.DevicePublicKey != first.DevicePublicKey || second.DevicePrivateKey != first.DevicePrivateKey {
		t.Fatal("identity key pair not reused")
	}
}

// TestBootstrapIdentityNeverAdoptsCredentials: v0.12.76 seeded the install
// identity from an existing credential; v0.12.77 forbids exactly that — an
// account's real device must never ride along on another account's login
// page. Credentials in the dir must be IGNORED by ensure.
func TestBootstrapIdentityNeverAdoptsCredentials(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	writeTestCredential(t, dir, "trae-cn-alice.json", "cn",
		"1111222233334444", "0f0e1d2c-3b4a-5968-7c8d-9e0f1a2b3c4d", pub, priv)

	id := ensureLoginDeviceIdentity(dir, "cn")
	if id.DeviceID == "1111222233334444" || id.MachineID == "0f0e1d2c-3b4a-5968-7c8d-9e0f1a2b3c4d" {
		t.Fatalf("bootstrap identity adopted a credential's device: %+v — account identities must never be shared", id)
	}
	if strings.Contains(id.Source, "seed:") {
		t.Fatalf("bootstrap identity Source = %q, seeding is removed in v0.12.77", id.Source)
	}
}

// TestIdentityNoDirEphemeral: an empty authDir (no host dir, no cache, no
// <cwd>/auths) must still yield a usable identity — logins never fail on
// identity persistence. If <cwd>/auths happens to exist the call may persist
// there; the assertion is deliberately only "non-empty ids, no panic".
func TestIdentityNoDirEphemeral(t *testing.T) {
	setAuthDirCacheForTest(t, "")
	id := ensureLoginDeviceIdentity("", "cn")
	if id == nil || id.DeviceID == "" || id.MachineID == "" {
		t.Fatalf("ephemeral identity unusable: %+v", id)
	}
}
