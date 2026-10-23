// billing_exhaustion_test.go pins the v0.9.65 ladder improvements:
//
//   - a connection-level failure demotes the cached-good dial IP so the next
//     attempt moves to a healthy candidate instead of re-dialing the same
//     TCP-good/TLS-dead edge until exhaustion;
//   - exhaustion where every attempt got an HTTP answer (upstream 5xx) is
//     reported as a server-side failure, not as "gateway unreachable";
//   - transport exhaustion keeps the actionable "unreachable" wording.
package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// billingTestAuth returns a minimal CN-realm storedAuth for billingCall.
func billingTestAuth() *storedAuth {
	return &storedAuth{
		Auth:    storedTokens{AccessToken: "test-token"},
		Account: storedAccount{UID: "uid-test"},
	}
}

// sealDialSeams redirects the resolver seams and retry cadence for hermetic
// ladder tests; returns a restore func.
func sealDialSeams(sysIPs []net.IP) func() {
	origLookup, origEndpoints, origDelays := dialSystemLookup, dialDoHEndpoints, billingRetryDelays
	dialSystemLookup = func(ctx context.Context, host string) ([]net.IP, error) {
		return sysIPs, nil
	}
	dialDoHEndpoints = nil
	billingRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	billingResetDialState()
	return func() {
		dialSystemLookup, dialDoHEndpoints, billingRetryDelays = origLookup, origEndpoints, origDelays
		billingResetDialState()
	}
}

// TestBillingCallDemotesConnLevelGoodIP is the behavioral pin for the demotion
// wiring. Two loopback IPs share one port with opposite behavior:
//
//	127.0.0.2 — accepts TCP, then closes without a response (the poisoned
//	            DNS / dead CDN edge profile: tcp=ok, session EOF)
//	127.0.0.3 — a healthy billing envelope server
//
// The sealed resolver orders the broken IP first, so attempt 0 dials it, TCP
// wins and it becomes the cached-good IP, and the request dies with EOF.
// Without the v0.9.65 demotion the good-IP stickiness re-dials 127.0.0.2 on
// every remaining attempt and the call exhausts; with it, the next attempt
// lands on 127.0.0.3 and the call succeeds.
func TestBillingCallDemotesConnLevelGoodIP(t *testing.T) {
	// Reserve a port number, then bind both listeners on it across two
	// loopback IPs (the whole 127/8 is loopback on Linux and macOS).
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback bind unavailable: %v", err)
	}
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()

	badLn, err := net.Listen("tcp4", "127.0.0.2:"+port)
	if err != nil {
		t.Skipf("127.0.0.2 not bindable on this platform: %v", err)
	}
	var badConns int32
	go func() {
		for {
			c, err := badLn.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&badConns, 1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = badLn.Close() })

	goodLn, err := net.Listen("tcp4", "127.0.0.3:"+port)
	if err != nil {
		t.Fatalf("bind healthy listener: %v", err)
	}
	var goodHits int32
	goodSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&goodHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"total_credits":42}}`))
	})}
	go func() { _ = goodSrv.Serve(goodLn) }()
	t.Cleanup(func() { _ = goodSrv.Close() })

	restoreSeams := sealDialSeams([]net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.3")})
	t.Cleanup(restoreSeams)

	restoreBase := setBillingBase("http://demote-ladder.test:" + port)
	t.Cleanup(restoreBase)

	_, err = billingCall(billingTestAuth(), "/v2/billing/meter/get-user-resource", nil)
	if err != nil {
		t.Fatalf("ladder must recover onto the healthy candidate after demotion, got: %v", err)
	}
	if atomic.LoadInt32(&goodHits) == 0 {
		t.Fatal("the healthy candidate was never dialed")
	}
	if n := atomic.LoadInt32(&badConns); n < 1 {
		t.Fatalf("expected at least one connection to the broken edge, got %d", n)
	}
}

// TestBillingExhaustion5xxIsNotReportedAsUnreachable pins the wording split:
// when every attempt got an HTTP 5xx answer (2026-10-23 field report: code
// 10000, the billing gateway's internal keycloak call failing) the exhaustion
// message must say the failure is server-side, not "gateway unreachable".
func TestBillingExhaustion5xxIsNotReportedAsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":10000,"msg":"request failed: Get \"http://keycloak-cluster-alias/auth/realms/copilot/overseas/auth_code/access_token\": EOF"}`))
	}))
	t.Cleanup(srv.Close)

	restoreSeams := sealDialSeams([]net.IP{net.ParseIP("127.0.0.1")})
	t.Cleanup(restoreSeams)
	restoreBase := setBillingBase(srv.URL)
	t.Cleanup(restoreBase)

	_, err := billingCall(billingTestAuth(), "/v2/billing/meter/get-user-resource", nil)
	if err == nil {
		t.Fatal("4x HTTP 500 must surface as an error")
	}
	msg := err.Error()
	for _, want := range []string{"HTTP 5xx on all 4 attempts", "server-side", "retries automatically", "keycloak-cluster-alias"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("5xx exhaustion message %q missing %q", msg, want)
		}
	}
	if strings.Contains(msg, "unreachable") {
		t.Fatalf("5xx exhaustion must not be reported as unreachable: %q", msg)
	}
}

// TestBillingExhaustionTransportKeepsUnreachableWording pins the other side of
// the split: transport-class exhaustion (EOFs, no HTTP answer at all) keeps the
// actionable "unreachable" wording and the proxy hint.
func TestBillingExhaustionTransportKeepsUnreachableWording(t *testing.T) {
	// An accept-then-close listener: TCP ok, no response — pure transport EOF.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	restoreSeams := sealDialSeams([]net.IP{net.ParseIP("127.0.0.1")})
	t.Cleanup(restoreSeams)
	restoreBase := setBillingBase("http://" + ln.Addr().String())
	t.Cleanup(restoreBase)

	_, err = billingCall(billingTestAuth(), "/v2/billing/meter/get-user-resource", nil)
	if err == nil {
		t.Fatal("4x EOF must surface as an error")
	}
	msg := err.Error()
	for _, want := range []string{"unreachable after 4 attempts", "proxy-url"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("transport exhaustion message %q missing %q", msg, want)
		}
	}
	if strings.Contains(msg, "HTTP 5xx on all") {
		t.Fatalf("transport exhaustion must not use the 5xx wording: %q", msg)
	}
}

// TestBillingErrClassifications unit-pins the error taxonomy the ladder now
// depends on: 5xx = server answered, conn-level = connection died, business /
// parse errors = neither.
func TestBillingErrClassifications(t *testing.T) {
	fiveHundred := errString(`http 500 from /v2/billing/meter/get-user-resource: {"code":10000,"msg":"request failed"}`)
	eof := errString(`Post "https://www.codebuddy.cn/v2/billing/meter/get-user-resource": EOF`)
	reset := errString(`Post "https://www.codebuddy.cn/v2/billing/meter/get-user-resource": read: connection reset by peer`)
	tlsErr := errString(`tls: failed to verify certificate: x509: certificate signed by unknown authority`)
	// 0.9.66 (CI flake 2026-10-23): both are the transport cutting the wire
	// under us — a pooled keep-alive conn the peer (CDN/EdgeOne idle reaping,
	// the accept-then-close test edge) closed, and a body truncated mid-read.
	// They must ride the demote/retry ladder like any other conn-level death,
	// not escape it as an unclassified one-shot error.
	idleClosed := errString(`Post "http://demote-ladder.test:36637/v2/billing/meter/get-user-resource": http: server closed idle connection`)
	truncated := errString(`Post "https://www.codebuddy.cn/v2/billing/meter/get-user-resource": unexpected EOF`)
	business := errString(`code=10000 msg=down`)
	parse := errString(`parse failed: invalid character '<'`)
	// The field-report shape under the HTTP-200 envelope: the server's own
	// internal keycloak error embedded in a business code message. The
	// transport WORKED — never classify the upstream's quoted error text as
	// our transport failure.
	internal := errString(`code=10000 msg=request failed: Get "http://keycloak-cluster-alias/auth/realms/copilot/overseas/auth_code/access_token": EOF`)

	if !is5xxBillingErr(fiveHundred) {
		t.Fatal("http 500 must classify as 5xx")
	}
	if is5xxBillingErr(eof) || is5xxBillingErr(business) {
		t.Fatal("EOF / business codes are not 5xx")
	}
	for _, e := range []error{eof, reset, tlsErr, idleClosed, truncated} {
		if !isConnLevelBillingErr(e) {
			t.Fatalf("%v must classify as connection-level", e)
		}
	}
	for _, e := range []error{fiveHundred, business, parse, nil, internal} {
		if isConnLevelBillingErr(e) {
			t.Fatalf("%v must NOT classify as connection-level", e)
		}
	}
	if isTransientBillingErr(internal) {
		t.Fatal("a business-code answer embedding the upstream's internal EOF text must not be transport-classified")
	}
	if !isTransientBillingErr(eof) || !isTransientBillingErr(fiveHundred) {
		t.Fatal("genuine transport EOF and 5xx answers must stay transient")
	}
}
