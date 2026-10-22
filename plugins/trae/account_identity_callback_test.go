// account_identity_callback_test.go — v0.12.79 wiring pins (issue #47):
// the login's sign-in device identity is IMMUTABLE from the moment the
// authorization URL is built until the credential is saved. A callback that
// echoes userInfo (the account's uid) must record the account identity
// fields (cbUID/cbNickname) and log the derived device for diagnostics, but
// it must NEVER swap the ctx's device — upstream ties every auth code to
// the device of the URL that requested it, and an ExchangeToken presenting
// a different device dies with HTTP 401 code=20403 "Token device not match"
// (the v0.12.77/v0.12.78 regression these tests guard against).
//
// Covered delivery routes:
//   - the CPA resource route (handleOAuthCallbackResource, cn/solo + intl),
//   - the plugin's own 127.0.0.1 listener (handleCallbackConn).
//
// The exchange points (main.go, pending_persist.go, intl_main.go) all build
// their DeviceInfo from the SAME loginCtx fields the URL was built from, so
// "identity unchanged after the callback" is exactly "URL device == exchange
// device == saved credential device"; TestSignInIdentityFlowsURLToExchange
// pins that end-to-end shape explicitly.
package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/upstream"
)

// newTestListener opens the plugin's real loopback callback listener.
func newTestListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// feedListenerCallback drives one raw callback request through the real
// acceptCallback loop and returns the response body the browser would see.
func feedListenerCallback(t *testing.T, ln net.Listener, query string) string {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /authorize?%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", query); err != nil {
		t.Fatalf("write callback request: %v", err)
	}
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

// wantSignInIdentityKept asserts lc still carries EXACTLY the sign-in
// identity (ids AND key pair) it was armed with at start-login.
func wantSignInIdentityKept(t *testing.T, lc *loginCtx, stage string) {
	t.Helper()
	if lc.deviceID != "bootstrap-dev" || lc.machineID != "bootstrap-mach" {
		t.Fatalf("%s: sign-in ids disturbed: got %s/%s, want bootstrap-dev/bootstrap-mach", stage, lc.deviceID, lc.machineID)
	}
	if lc.devicePublicKey != "bootstrap-pub" || lc.devicePrivateKey != "bootstrap-priv" {
		t.Fatalf("%s: sign-in key pair disturbed by the callback (20403 regression)", stage)
	}
}

// TestResourceCallbackKeepsSignInIdentityCN: a resource-route callback
// carrying userInfo leaves the cn/solo login on its sign-in device — the
// derived per-account identity is logged, NOT applied (v0.12.77/78 applied
// it and every fresh login died 401 20403, issue #47).
func TestResourceCallbackKeepsSignInIdentityCN(t *testing.T) {
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
	q.Set("authCode", "ac-keep")
	q.Set("userInfo", `{"UserID":"1237380756941412","ScreenName":"用户37396015402"}`)
	body := handleOAuthCallbackResource(pluginapi.ManagementRequest{Method: "GET", Query: q})
	if !strings.Contains(string(body), "Login successful") {
		t.Fatalf("callback body = %s", body)
	}
	if lc.authCode != "ac-keep" {
		t.Fatalf("authCode not captured: %+v", lc)
	}
	if lc.cbUID != "1237380756941412" {
		t.Fatalf("cbUID = %q (account echo must still be recorded)", lc.cbUID)
	}
	wantSignInIdentityKept(t, lc, "resource-route cn")
}

// TestResourceCallbackKeepsSignInIdentityIntl: the intl flow keeps its
// sign-in identity too.
func TestResourceCallbackKeepsSignInIdentityIntl(t *testing.T) {
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
	q.Set("authCode", "ac-intl-keep")
	q.Set("userInfo", `{"UserID":"1b78b3c2-62f0-42e5-84fe-51e3c55e4914"}`)
	body := handleOAuthCallbackResource(pluginapi.ManagementRequest{Method: "GET", Query: q})
	if !strings.Contains(string(body), "Login successful") {
		t.Fatalf("callback body = %s", body)
	}
	if lc.deviceID != "bootstrap-dev" || lc.machineID != "bootstrap-mach" {
		t.Fatalf("intl sign-in ids disturbed: got %s/%s", lc.deviceID, lc.machineID)
	}
	if lc.devicePublicKey != "bootstrap-pub" || lc.devicePrivateKey != "bootstrap-priv" {
		t.Fatal("intl sign-in key pair disturbed (20403 regression)")
	}
}

// TestResourceCallbackWithoutUserInfoKeepsBootstrap: no userInfo echo →
// nothing to note; the sign-in identity survives untouched.
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
	wantSignInIdentityKept(t, lc, "resource-route no-echo")
}

// TestListenerCallbackKeepsSignInIdentityCN: the LOCAL LISTENER path must
// not swap the identity either (v0.12.77 swapped on all four routes).
func TestListenerCallbackKeepsSignInIdentityCN(t *testing.T) {
	state := "acct-cn-listener"
	ln := newTestListener(t)
	lc := &loginCtx{
		variant:          variantCN,
		state:            state,
		loginTraceID:     state,
		expires:          time.Now().Add(time.Minute),
		listener:         ln,
		cbURL:            "http://" + ln.Addr().String() + "/authorize",
		deviceID:         "bootstrap-dev",
		machineID:        "bootstrap-mach",
		devicePublicKey:  "bootstrap-pub",
		devicePrivateKey: "bootstrap-priv",
	}
	loginStates.Store(state, lc)
	defer loginStates.Delete(state)
	go acceptCallback(state)

	resp := feedListenerCallback(t, ln, "state="+state+
		"&authCode=ac-listener-keep"+
		"&userInfo="+url.QueryEscape(`{"UserID":"1237380756941412","ScreenName":"用户37396015402"}`))
	if !strings.Contains(resp, "Login successful") {
		t.Fatalf("listener response = %s", resp)
	}
	wantSignInIdentityKept(t, lc, "listener cn")
}

// TestListenerCallbackWithoutUserInfoKeepsBootstrap: listener path, no echo.
func TestListenerCallbackWithoutUserInfoKeepsBootstrap(t *testing.T) {
	state := "acct-cn-listener-noecho"
	ln := newTestListener(t)
	lc := &loginCtx{
		variant:      variantCN,
		state:        state,
		loginTraceID: state,
		expires:      time.Now().Add(time.Minute),
		listener:     ln,
		cbURL:        "http://" + ln.Addr().String() + "/authorize",
	}
	loginStates.Store(state, lc)
	defer loginStates.Delete(state)
	go acceptCallback(state)

	resp := feedListenerCallback(t, ln, "state="+state+"&authCode=ac-listener-noecho")
	if !strings.Contains(resp, "Login successful") {
		t.Fatalf("listener response = %s", resp)
	}
	if lc.deviceID != "" || lc.machineID != "" {
		t.Fatalf("listener login without echo should keep the (empty here) start-login identity: %+v", lc)
	}
}

// TestSignInIdentityFlowsURLToExchange pins the end-to-end consistency the
// 20403 gate demands, at the exact seams upstream observes them: the
// authorization-page URL params (machine_id/device_id/x_device_id/
// x_machine_id) and the ExchangeToken DeviceInfo must carry the SAME device
// as the loginCtx — before AND after a userInfo-echoing callback. This is
// the invariant v0.12.77/v0.12.78 broke (URL=bootstrap, exchange=derived).
func TestSignInIdentityFlowsURLToExchange(t *testing.T) {
	ident := &deviceIdentity{
		DeviceID:         "5738094957779619",
		MachineID:        "cc2efe3f-c68d-4901-8eed-4135e29635b1",
		DevicePublicKey:  "sign-in-pub",
		DevicePrivateKey: "sign-in-priv",
		Variant:          variantCN,
	}

	// What start-login does: URL from the identity, ctx from the identity.
	uri := buildVerificationURI("https://login.trae.cn", verificationURIParams{
		AuthFrom: oauthAuthFor(variantCN), PluginVersion: oauthPluginVersion,
		ClientID: "ono9krqynydwx5", LoginTraceID: "trace-1",
		CallbackURL: "http://127.0.0.1:0/authorize",
		MachineID:   ident.MachineID, DeviceID: ident.DeviceID,
		DeviceBrand: oauthDeviceBrand, DeviceType: oauthDeviceType,
		OSVersion: oauthOSVersion, Env: oauthEnv,
		AppVersion: "0.1.43", AppType: oauthAppType,
		CodeChallenge: "challenge",
	})
	lc := &loginCtx{
		variant: variantCN, deviceID: ident.DeviceID, machineID: ident.MachineID,
		devicePublicKey: ident.DevicePublicKey, devicePrivateKey: ident.DevicePrivateKey,
	}

	// The callback echoes the account — v0.12.79 keeps the identity.
	noteAccountDeviceIdentityCN(lc, "2310999999999833")

	// What the exchange point does: carried keys first (deviceKeysForLogin
	// semantics), DeviceInfo from the same ctx fields.
	pub, priv, keyErr := deviceKeysForLogin(lc.devicePublicKey, lc.devicePrivateKey, "", variantCN)
	if keyErr != nil {
		t.Fatalf("deviceKeysForLogin: %v", keyErr)
	}
	if pub != "sign-in-pub" || priv != "sign-in-priv" {
		t.Fatalf("exchange keys %q/%q — the callback must not replace the sign-in key pair", pub, priv)
	}
	di := buildOfficialDeviceInfo(lc.deviceID, lc.machineID, oauthPlatformCodeFor(variantCN), oauthDeviceName,
		oauthDeviceBrand, upstream.IdeVersion, oauthDeviceType, oauthOSVersion, pub)

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse verification URI: %v", err)
	}
	q := u.Query()
	for _, k := range []string{"device_id", "x_device_id"} {
		if q.Get(k) != di.DeviceID {
			t.Fatalf("URL %s = %q, exchange DeviceInfo.DeviceID = %q — mismatch is the 20403 shape (issue #47)", k, q.Get(k), di.DeviceID)
		}
	}
	for _, k := range []string{"machine_id", "x_machine_id"} {
		if q.Get(k) != di.MachineID {
			t.Fatalf("URL %s = %q, exchange DeviceInfo.MachineID = %q — mismatch is the 20403 shape (issue #47)", k, q.Get(k), di.MachineID)
		}
	}
	if di.DeviceID == deriveAccountDeviceIdentity(variantCN, "2310999999999833").DeviceID {
		t.Fatal("exchange device equals the DERIVED account device — the swap is back (20403 regression)")
	}
}
