// device_identity_test.go — v0.12.76 stable login device identity.
//
// Pins the three behaviors the 20401 (Device limit reached) fix depends on:
//  1. mint-once-reuse-forever: a second ensure returns the EXACT identity
//     (ids + key pair) the first call persisted;
//  2. seeding: an existing same-variant credential's device identity is
//     adopted (exact variant preferred over newer mtime of another variant);
//  3. degradation: a missing key pair is generated + persisted; a missing
//     auth dir yields an ephemeral in-memory identity instead of an error.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// TestEnsureIdentityMintAndReuse: an empty dir mints a fresh identity and
// persists it; the next ensure must return the IDENTICAL ids + key pair —
// the property whose absence burned one device slot per login (20401).
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
		t.Fatal("identity key pair not reused — every login would register a new server-side device")
	}
}

// TestIdentitySeededFromCredential: with no identity file, an existing
// same-variant credential's device identity is adopted wholesale (ids AND
// key pair), reconnecting this install to the device slot its own earlier
// credential registered.
func TestIdentitySeededFromCredential(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	writeTestCredential(t, dir, "trae-cn-alice.json", "cn",
		"1111222233334444", "0f0e1d2c-3b4a-5968-7c8d-9e0f1a2b3c4d", pub, priv)

	id := ensureLoginDeviceIdentity(dir, "cn")
	if id.DeviceID != "1111222233334444" || id.MachineID != "0f0e1d2c-3b4a-5968-7c8d-9e0f1a2b3c4d" {
		t.Fatalf("seeded identity not adopted: %+v", id)
	}
	if id.DevicePublicKey != pub || id.DevicePrivateKey != priv {
		t.Fatal("seeded identity did not adopt the credential's key pair")
	}
	if !strings.Contains(id.Source, "seed:") {
		t.Fatalf("seeded identity Source = %q, want prefix seed:", id.Source)
	}
	persisted := loadDeviceIdentity(dir, "cn")
	if persisted == nil {
		t.Fatal("seeded identity not persisted")
	}
	if persisted.DevicePublicKey != pub || persisted.DevicePrivateKey != priv {
		t.Fatal("persisted seeded identity lost the key pair")
	}
}

// TestIdentityVariantPreference: cn and solo credentials coexist (solo file
// NEWER); ensure("cn") must pick the cn credential's identity (exact variant
// beats newer mtime) and ensure("solo") the solo one.
func TestIdentityVariantPreference(t *testing.T) {
	dir := t.TempDir()
	cnPath := writeTestCredential(t, dir, "trae-cn-bob.json", "cn",
		"2222333344445555", "aaaa1111-2222-3333-4444-555566667777", "", "")
	soloPath := writeTestCredential(t, dir, "trae-solo-cn-bob.json", "solo",
		"6666777788889999", "bbbb1111-2222-3333-4444-555566667777", "", "")
	// Make the solo file strictly newer: mtime must NOT outweigh an exact
	// variant match for ensure("cn").
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(soloPath, future, future); err != nil {
		t.Fatalf("chtimes solo: %v", err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cnPath, past, past); err != nil {
		t.Fatalf("chtimes cn: %v", err)
	}

	cn := ensureLoginDeviceIdentity(dir, "cn")
	if cn.DeviceID != "2222333344445555" {
		t.Fatalf("ensure(cn) picked the wrong credential: %+v", cn)
	}
	solo := ensureLoginDeviceIdentity(dir, "solo")
	if solo.DeviceID != "6666777788889999" {
		t.Fatalf("ensure(solo) picked the wrong credential: %+v", solo)
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

// TestIdentitySeededWithoutKeysGenerates: a pre-v0.12.73 credential (no
// device keys) seeds the ids; ensure generates the missing pair AND persists
// it — a reload must find the keys, so later logins reuse the same pair.
func TestIdentitySeededWithoutKeysGenerates(t *testing.T) {
	dir := t.TempDir()
	writeTestCredential(t, dir, "trae-cn-carol.json", "cn",
		"9999000011112222", "cccc1111-2222-3333-4444-555566667777", "", "")

	id := ensureLoginDeviceIdentity(dir, "cn")
	if id.DeviceID != "9999000011112222" {
		t.Fatalf("seeded ids not adopted: %+v", id)
	}
	if id.DevicePublicKey == "" || id.DevicePrivateKey == "" {
		t.Fatalf("missing key pair not generated: %+v", id)
	}
	reloaded := loadDeviceIdentity(dir, "cn")
	if reloaded == nil {
		t.Fatal("completed identity not persisted")
	}
	if reloaded.DevicePublicKey == "" || reloaded.DevicePrivateKey == "" {
		t.Fatal("persisted identity lacks the generated key pair")
	}
}
