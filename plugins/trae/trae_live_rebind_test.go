//go:build live

// trae_live_rebind_test.go — v0.12.77 per-account device identity, live leg
// (gated by TRAE_REBIND=1 + TRAE_CRED). NEGATIVE-RESULT PIN, decided live
// 2026-10-12 on uid 1237380756941412:
//
// A credential's token chain CANNOT be re-bound to a different device by any
// exchange. The bound ExchangeToken answers 20403 "Token device not match"
// for every device except the server-side record the chain was created with
// (CheckLogin names it BoundDeviceID — an internal id, NOT the
// DeviceInfo.DeviceID we send), and the binding survives legacy rotations:
// the /cloudide fallback renews fine but keeps the chain on that record.
// Device binding happens exactly ONCE, when the chain is created — i.e. at
// the auth-code ExchangeToken of a fresh login (magpie's signedIn binds the
// page-issued pair the same way). This is precisely why v0.12.77 derives the
// per-account identity BEFORE the exchange: that is the one moment the
// device can be chosen.
//
// What this leg does now (harmless, restores everything it touches):
//
//	leg 1  renew as the DERIVED device   → bound rung 20403s, legacy rotates;
//	leg 2  renew as the derived again    → same 20403 (binding is sticky);
//	check  CheckLogin.BoundDeviceID stays the chain's own device id;
//	restore the credential identity + one more renewal, persist.
//
// FAIL conditions (a FATAL here is a real regression signal):
//   - a renewal itself fails (the chain must survive every leg);
//   - the bound rung ever SUCCEEDS with the derived device — then the
//     immutability model broke and v0.12.77's login-time binding has a
//     refresh-time alternative worth building.
//
// Run:
//
//	TRAE_CRED=/path/cred.json TRAE_REBIND=1 \
//	  go test -tags live -run TestLiveRebindAccountDevice -v ./plugins/trae
package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/auth"
	"github.com/mmqz/cpa-multi-plugins/plugins/trae/upstream"
)

// rebindProbeAuth copies the credential onto the given device identity.
func rebindProbeAuth(a *auth.Auth, ident *deviceIdentity) *auth.Auth {
	return &auth.Auth{
		AccessToken:      a.AccessToken,
		RefreshToken:     a.RefreshToken,
		ExpiresAt:        a.ExpiresAt,
		APIHost:          a.APIHost,
		Domain:           a.Domain,
		UID:              a.UID,
		Nickname:         a.Nickname,
		EnterpriseID:     a.EnterpriseID,
		Variant:          a.Variant,
		DeviceID:         ident.DeviceID,
		MachineID:        ident.MachineID,
		DevicePublicKey:  ident.DevicePublicKey,
		DevicePrivateKey: ident.DevicePrivateKey,
	}
}

func TestLiveRebindAccountDevice(t *testing.T) {
	if strings.TrimSpace(os.Getenv("TRAE_REBIND")) != "1" {
		t.Skip("TRAE_REBIND != 1 — account-device rebind leg skipped")
	}
	a := liveTraeAuth(t)
	c := upstream.New()

	ident := deriveAccountDeviceIdentity(a.Variant, a.UID)
	if ident == nil {
		t.Fatalf("credential carries no uid — cannot derive the account identity (uid=%q)", a.UID)
	}
	t.Logf("derived identity for uid=%s variant=%s: deviceId=%s machineId=%s (credential: %s/%s)",
		a.UID, a.Variant, ident.DeviceID, ident.MachineID, a.DeviceID, a.MachineID)

	// The credential's own identity, for the mandatory restore at the end.
	orig := &deviceIdentity{
		DeviceID:         a.DeviceID,
		MachineID:        a.MachineID,
		DevicePublicKey:  a.DevicePublicKey,
		DevicePrivateKey: a.DevicePrivateKey,
	}

	probe := rebindProbeAuth(a, ident)

	// Leg 1: renew presenting the derived device.
	if err := c.RefreshToken(probe); err != nil {
		t.Fatalf("leg 1 renewal as the derived device failed: %v", err)
	}
	t.Logf("leg 1 OK (rt rotated=%v)", probe.RefreshToken != a.RefreshToken)

	// Leg 2: renew again — if the binding were rotatable, this one binds.
	boundNow := false
	if err := c.RefreshToken(probe); err != nil {
		t.Fatalf("leg 2 renewal as the derived device failed: %v", err)
	}
	t.Logf("leg 2 OK (expiresAt=%s)", time.Unix(probe.ExpiresAt, 0).Format(time.RFC3339))

	if cl, err := c.CheckLogin(probe); err != nil {
		t.Logf("CheckLogin failed (non-fatal): %v", err)
	} else {
		boundNow = cl.BoundDeviceID == ident.DeviceID
		t.Logf("check_login: isLogin=%v bindStatus=%q boundDevice=%q derived=%q boundToDerived=%v",
			cl.IsLogin, cl.DeviceBindStatus, cl.BoundDeviceID, ident.DeviceID, boundNow)
	}

	// Restore the credential identity and leave the chain healthy.
	restore := rebindProbeAuth(probe, orig)
	if err := c.RefreshToken(restore); err != nil {
		t.Fatalf("restore renewal failed — credential left with rt=%s: %v",
			liveTruncate(probe.RefreshToken, 24), err)
	}
	livePersistCred(t, restore)
	t.Logf("restored: credential identity renewed + persisted (rt rotated once more)")

	if boundNow {
		t.Fatalf("the chain REBOUND to the derived device — the immutability model is refuted; build the refresh-time rebind")
	}
	t.Logf("PINNED (negative result): the chain stayed bound to its own server-side device — " +
		"device binding is chose-at-login; v0.12.77's pre-exchange per-account derivation is the only lever")
}
