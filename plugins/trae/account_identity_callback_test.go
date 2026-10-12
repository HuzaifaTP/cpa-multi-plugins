// account_identity_callback_test.go — v0.12.77 wiring pins: the moment a
// callback reveals the account (userInfo echo), the login ctx must switch to
// that account's DERIVED device identity — ids AND key pair together — on
// every delivery route:
//
//   - the CPA resource route (handleOAuthCallbackResource, cn/solo + intl),
//   - the plugin's own 127.0.0.1 listener (handleCallbackConn /
//     intlHandleCallbackConn — this route never even parsed userInfo before
//     v0.12.77, so listener logins could never reach their account device).
//
// The exchange points, GetUserInfo and the credential save all read the ctx
// identity afterwards, so this swap is what makes the saved credential carry
// the account's own device (and its later bound refreshes reuse it).
package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// wantDerivedCN asserts lc carries exactly the per-account identity of
// (variant, uid).
func wantDerivedCN(t *testing.T, lc *loginCtx, variant, uid, stage string) {
	t.Helper()
	id := deriveAccountDeviceIdentity(variant, uid)
	if id == nil {
		t.Fatalf("%s: derivation returned nil", stage)
	}
	if lc.deviceID != id.DeviceID || lc.machineID != id.MachineID {
		t.Fatalf("%s: ctx ids %s/%s, want derived %s/%s", stage,
			lc.deviceID, lc.machineID, id.DeviceID, id.MachineID)
	}
	if lc.devicePublicKey != id.DevicePublicKey || lc.devicePrivateKey != id.DevicePrivateKey {
		t.Fatalf("%s: ctx key pair does not match the derived identity", stage)
	}
}

// TestResourceCallbackAppliesDerivedIdentityCN: a resource-route callback
// carrying userInfo switches the cn/solo login onto the account's device.
func TestResourceCallbackAppliesDerivedIdentityCN(t *testing.T) {
	state := "acct-cn-1"
	lc := &loginCtx{
		variant:          variantCN,
		state:            state,
		expires:          time.Now().Add(time.Minute),
		deviceID:         "bootstrap-dev",
		machineID:        "bootstrap-mach",
		devicePublicKey:  "bootstrap-pub",
		devicePrivateKey: "bootstrap-priv",
	}
	loginStates.Store(state, lc)
	defer loginStates.Delete(state) // also disarms the post-grace self-complete

	q := url.Values{}
	q.Set("state", state)
	q.Set("authCode", "ac-derived")
	q.Set("userInfo", `{"UserID":"1237380756941412","ScreenName":"用户37396015402"}`)
	body := handleOAuthCallbackResource(pluginapi.ManagementRequest{Method: "GET", Query: q})
	if !strings.Contains(string(body), "Login successful") {
		t.Fatalf("callback body = %s", body)
	}
	if lc.authCode != "ac-derived" {
		t.Fatalf("authCode not captured: %+v", lc)
	}
	if lc.cbUID != "1237380756941412" {
		t.Fatalf("cbUID = %q", lc.cbUID)
	}
	wantDerivedCN(t, lc, variantCN, "1237380756941412", "resource-route cn")
}

// TestResourceCallbackAppliesDerivedIdentityIntl: the intl flow's swap.
func TestResourceCallbackAppliesDerivedIdentityIntl(t *testing.T) {
	state := "acct-intl-1"
	lc := &intlloginCtx{
		state:            state,
		expires:          time.Now().Add(time.Minute),
		deviceID:         "bootstrap-dev",
		machineID:        "bootstrap-mach",
		devicePublicKey:  "bootstrap-pub",
		devicePrivateKey: "bootstrap-priv",
	}
	intlloginStates.Store(state, lc)
	defer intlloginStates.Delete(state)

	q := url.Values{}
	q.Set("state", state)
	q.Set("authCode", "ac-intl-derived")
	q.Set("userInfo", `{"UserID":"1b78b3c2-62f0-42e5-84fe-51e3c55e4914"}`)
	body := handleOAuthCallbackResource(pluginapi.ManagementRequest{Method: "GET", Query: q})
	if !strings.Contains(string(body), "Login successful") {
		t.Fatalf("callback body = %s", body)
	}
	id := deriveAccountDeviceIdentity(variantIntl, "1b78b3c2-62f0-42e5-84fe-51e3c55e4914")
	if lc.deviceID != id.DeviceID || lc.machineID != id.MachineID {
		t.Fatalf("intl ctx ids %s/%s, want derived %s/%s", lc.deviceID, lc.machineID, id.DeviceID, id.MachineID)
	}
	if lc.devicePublicKey != id.DevicePublicKey || lc.devicePrivateKey != id.DevicePrivateKey {
		t.Fatal("intl ctx key pair does not match the derived identity")
	}
}

// TestResourceCallbackWithoutUserInfoKeepsBootstrap: no userInfo echo → the
// bootstrap identity survives untouched (never a garbage "empty account"
// device; the account migrates to its derived device at the next echo-ing
// login).
func TestResourceCallbackWithoutUserInfoKeepsBootstrap(t *testing.T) {
	state := "acct-cn-noecho"
	lc := &loginCtx{
		variant:          variantCN,
		state:            state,
		expires:          time.Now().Add(time.Minute),
		deviceID:         "bootstrap-dev",
		machineID:        "bootstrap-mach",
		devicePublicKey:  "bootstrap-pub",
		devicePrivateKey: "bootstrap-priv",
	}
	loginStates.Store(state, lc)
	defer loginStates.Delete(state)

	q := url.Values{}
	q.Set("state", state)
	q.Set("authCode", "ac-noecho")
	_ = handleOAuthCallbackResource(pluginapi.ManagementRequest{Method: "GET", Query: q})
	if lc.deviceID != "bootstrap-dev" || lc.machineID != "bootstrap-mach" {
		t.Fatalf("bootstrap identity disturbed without a userInfo echo: %+v", lc)
	}
	if lc.devicePublicKey != "bootstrap-pub" || lc.devicePrivateKey != "bootstrap-priv" {
		t.Fatal("bootstrap key pair disturbed without a userInfo echo")
	}
}

// TestListenerCallbackAppliesDerivedIdentityCN: the LOCAL LISTENER path —
// v0.12.25 parsed userInfo only on the resource route, so listener logins
// never reached their account's device; v0.12.77 closes that gap.
func TestListenerCallbackAppliesDerivedIdentityCN(t *testing.T) {
	state := "acct-cn-listener"
	resp := driveListenerLogin(t, state,
		"state="+state+
			"&authCode=ac-listener"+
			"&userInfo="+url.QueryEscape(`{"UserID":"1237380756941412","ScreenName":"用户37396015402"}`))
	if !strings.Contains(resp, "Login successful") {
		t.Fatalf("listener response = %s", resp)
	}
	v, ok := loginStates.Load(state)
	if !ok {
		t.Fatal("listener login state missing")
	}
	defer loginStates.Delete(state)
	wantDerivedCN(t, v.(*loginCtx), variantCN, "1237380756941412", "listener cn")
}

// TestListenerCallbackWithoutUserInfoKeepsBootstrap: listener path, no echo.
func TestListenerCallbackWithoutUserInfoKeepsBootstrap(t *testing.T) {
	state := "acct-cn-listener-noecho"
	resp := driveListenerLogin(t, state, "state="+state+"&authCode=ac-listener-noecho")
	if !strings.Contains(resp, "Login successful") {
		t.Fatalf("listener response = %s", resp)
	}
	v, ok := loginStates.Load(state)
	if !ok {
		t.Fatal("listener login state missing")
	}
	defer loginStates.Delete(state)
	lc := v.(*loginCtx)
	if lc.deviceID != "" || lc.machineID != "" {
		t.Fatalf("listener login without echo should keep the (empty here) start-login identity: %+v", lc)
	}
}
