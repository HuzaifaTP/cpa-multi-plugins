// listener_selfcomplete_test.go — v0.12.74 regression pins for the LOCAL
// LISTENER callback path (issue #38).
//
// The v0.12.23 grace-based self-completion was armed ONLY on the
// resource-route path (handleOAuthCallbackResource → spawnSelfCompleteCN);
// the plugin's own 127.0.0.1 listener loop (acceptCallback →
// handleCallbackConn) captured the callback and closed lc.done but NEVER
// spawned the self-completion. When the host's auth.login.poll stopped
// draining the state (dialog closed, host oauth-session registry miss, poll
// HTTP timeout), the login stalled at pending+callback_received for the full
// 15-minute TTL and the janitor reaped it WITHOUT an outcome — exactly the
// issue #38 report ("callback received but ExchangeToken hangs until TTL
// expiry; login_status outcome is empty").
//
// These tests drive the REAL listener loop over a REAL TCP connection and
// assert the v0.12.74 behavior: a resolved callback on the listener path
// arms the one-shot self-completion, which after the (shrunk) grace window
// claims the state and records a login outcome. The error-callback shape is
// used deliberately: it resolves the flow WITHOUT touching the network, so
// the regression pin stays hermetic (the authCode capture path through
// selfCompleteCN is the same code the resource-route tests already drive).
package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// driveListenerLogin arms a loginCtx backed by a real loopback TCP listener,
// starts acceptCallback, and feeds it one raw callback request. Returns the
// response body the browser would have seen.
func driveListenerLogin(t *testing.T, state string, query string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dir := t.TempDir()
	lc := &loginCtx{
		variant:      variantCN,
		state:        state,
		loginTraceID: state,
		expires:      time.Now().Add(time.Minute),
		authDir:      dir,
		listener:     ln,
		cbURL:        "http://" + ln.Addr().String() + "/authorize",
	}
	loginStates.Store(state, lc)
	go acceptCallback(state)

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

// CN/SOLO: an error callback resolved on the LISTENER path must arm the
// self-completion — after the grace window the state is claimed and an
// outcome is recorded (pre-v0.12.74: pending until TTL, no outcome at all).
func TestListenerCallbackArmsSelfCompleteCN(t *testing.T) {
	prevGrace := loginSelfCompleteGrace
	loginSelfCompleteGrace = 80 * time.Millisecond
	t.Cleanup(func() { loginSelfCompleteGrace = prevGrace })

	state := "listener-selfcomplete-cn-1"
	resp := driveListenerLogin(t, state, "error=access_denied&loginTraceID="+state)
	if !strings.Contains(resp, "Login failed") {
		t.Fatalf("listener answered unexpectedly: %q", resp)
	}

	waitForGraceCompletion(t, func() bool {
		_, live := loginStates.Load(state)
		return !live
	})
	o, ok := waitForOutcome(t, state)
	if !ok {
		t.Fatal("listener-path callback never armed self-completion — issue #38 regression (no outcome recorded)")
	}
	if o.ok {
		t.Fatalf("error callback must settle as a failure outcome: %+v", o)
	}
	// v0.12.74：selfCompleteCN 先回显 lc.err —— outcome 必须携带真实回调错误，
	// 而不是误导性的「no authCode/refreshToken after restore」。
	if !strings.Contains(o.msg, "access_denied") {
		t.Fatalf("outcome message must carry the real callback error, got %q", o.msg)
	}
	t.Cleanup(func() {
		outcomeCache.Lock()
		delete(outcomeCache.m, state)
		outcomeCache.Unlock()
	})
}

// CN/SOLO: a callback the listener loop does NOT resolve (favicon probe)
// must not arm anything — the login keeps waiting for the real redirect.
func TestListenerProbeDoesNotArmSelfComplete(t *testing.T) {
	prevGrace := loginSelfCompleteGrace
	loginSelfCompleteGrace = 80 * time.Millisecond
	t.Cleanup(func() { loginSelfCompleteGrace = prevGrace })

	state := "listener-probe-cn-1"
	_ = driveListenerLogin(t, state, "") // bare "/authorize" — 404, flow unresolved
	time.Sleep(loginSelfCompleteGrace + 200*time.Millisecond)

	if _, live := loginStates.Load(state); !live {
		t.Fatal("an unresolved probe must leave the login pending")
	}
	if _, ok := lookupLoginOutcome(state); ok {
		t.Fatal("an unresolved probe must not record an outcome")
	}
	t.Cleanup(func() { loginStates.Delete(state) })
}

// Intl mirror: the intl listener loop (intlacceptCallback →
// intlHandleCallbackConn) must arm spawnSelfCompleteIntl on a resolved
// callback.
func TestListenerCallbackArmsSelfCompleteIntl(t *testing.T) {
	prevGrace := loginSelfCompleteGrace
	loginSelfCompleteGrace = 80 * time.Millisecond
	t.Cleanup(func() { loginSelfCompleteGrace = prevGrace })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	state := "listener-selfcomplete-intl-1"
	lc := &intlloginCtx{
		state:        state,
		loginTraceID: state,
		expires:      time.Now().Add(time.Minute),
		authDir:      t.TempDir(),
		listener:     ln,
		cbURL:        "http://" + ln.Addr().String() + "/authorize",
	}
	intlloginStates.Store(state, lc)
	go intlacceptCallback(state)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /authorize?error=access_denied&loginTraceID=%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", state); err != nil {
		t.Fatalf("write callback request: %v", err)
	}
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "Login failed") {
		t.Fatalf("intl listener answered unexpectedly: %q", string(buf[:n]))
	}

	waitForGraceCompletion(t, func() bool {
		_, live := intlloginStates.Load(state)
		return !live
	})
	o, ok := waitForOutcome(t, state)
	if !ok {
		t.Fatal("intl listener-path callback never armed self-completion — issue #38 regression (no outcome recorded)")
	}
	if o.ok {
		t.Fatalf("error callback must settle as a failure outcome: %+v", o)
	}
	if !strings.Contains(o.msg, "access_denied") {
		t.Fatalf("intl outcome message must carry the real callback error, got %q", o.msg)
	}
	t.Cleanup(func() {
		outcomeCache.Lock()
		delete(outcomeCache.m, state)
		outcomeCache.Unlock()
	})
}

// Compile-time guard: the resource-route submit helper stays wired for the
// paste flow (the listener fix must not regress it).
var _ = handleOAuthSubmitResource
var _ = pluginapi.ManagementRequest{}
