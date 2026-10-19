package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// restoreHostProxy resets the global proxy cache to a previous value. Tests
// must use this instead of rememberHostProxy(""), which is deliberately a
// no-op (empty values are ignored) and would leak a cached proxy into every
// subsequent billing test in the package.
func restoreHostProxy(proxyURL string) {
	hostProxyMu.Lock()
	hostProxyURL = proxyURL
	hostProxyMu.Unlock()
}

// TestRememberHostProxy pins the cache semantics: empty/invalid values are
// ignored, valid values are cached, changes update.
func TestRememberHostProxy(t *testing.T) {
	orig := currentHostProxyURL()
	defer restoreHostProxy(orig) // rememberHostProxy ignores "" — never use it to restore
	hostProxyMu.Lock()
	hostProxyURL = ""
	hostProxyMu.Unlock()

	rememberHostProxy("")
	if got := currentHostProxyURL(); got != "" {
		t.Fatalf("empty proxy URL must be ignored, cached %q", got)
	}
	rememberHostProxy("not a url ://")
	if got := currentHostProxyURL(); got != "" {
		t.Fatalf("invalid proxy URL must be ignored, cached %q", got)
	}
	rememberHostProxy("http://127.0.0.1:7890")
	if got := currentHostProxyURL(); got != "http://127.0.0.1:7890" {
		t.Fatalf("valid proxy URL not cached, got %q", got)
	}
	rememberHostProxy("  http://127.0.0.1:7890  ") // trimmed duplicate — no-op
	if got := currentHostProxyURL(); got != "http://127.0.0.1:7890" {
		t.Fatalf("trimmed duplicate changed cache, got %q", got)
	}
}

// TestBillingProxyFunc_ConfigWinsOverEnv pins the v0.9.52 policy: the
// host-configured proxy (config.yaml proxy-url delivered via
// HostConfigSummary) takes precedence over environment variables; with neither
// present the result is nil (plain direct — historical default).
//
// v0.9.60: http.ProxyFromEnvironment snapshots the process environment on
// its FIRST call anywhere in the process (net/http envProxyOnce) — the
// billing_* tests that run earlier have already taken that snapshot, so
// t.Setenv inside this test cannot influence what billingProxyFunc sees.
// On a proxied developer shell that snapshot is non-empty and the old
// "neither configured → nil" assertion went red for the wrong reason.
// The test now asserts against the LAUNCH environment instead: on a clean
// runner the snapshot is empty and the full ladder holds; on a proxied
// shell the config-wins leg is still genuinely exercised against the live
// launch-time proxy — which is the production guarantee being pinned.
func TestBillingProxyFunc_ConfigWinsOverEnv(t *testing.T) {
	orig := currentHostProxyURL()
	defer restoreHostProxy(orig)
	hostProxyMu.Lock()
	hostProxyURL = ""
	hostProxyMu.Unlock()

	req, _ := http.NewRequest(http.MethodPost, "https://www.codebuddy.ai/v2/billing/meter/get-user-resource", nil)

	// Neither configured → nil (direct) — only assertable on a clean
	// launch environment (a proxied shell's snapshot is immutable here).
	if envProxyAtLaunch() == "" {
		got, err := billingProxyFunc(req)
		if err != nil || got != nil {
			t.Fatalf("no proxy configured: got %q err %v, want nil/nil", got, err)
		}
	}

	// Config proxy set → wins — over an empty snapshot on CI and over the
	// live launch-time proxy on a proxied developer shell alike.
	rememberHostProxy("http://10.0.0.1:7890")
	got, err := billingProxyFunc(req)
	if err != nil {
		t.Fatalf("config proxy parse: %v", err)
	}
	if got == nil || got.Host != "10.0.0.1:7890" {
		t.Fatalf("config proxy not honored: %v", got)
	}
}

// envProxyAtLaunch reports any proxy environment variable visible to the
// test process — a faithful-enough proxy for net/http's frozen
// ProxyFromEnvironment snapshot (earlier tests' t.Setenv calls are restored
// by the time we read this).
func envProxyAtLaunch() string {
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// TestHostHTTPDo_BridgeMarkerOverridesDomainBypass pins the v0.9.52 fallback
// contract: a withHTTPBridge-marked request to a bypass-listed domain reaches
// the bridge path (in tests the bridge is unavailable → direct fallback), and
// an unmarked request still takes the direct bypass. Observable via the test
// server actually answering both.
func TestHostHTTPDo_BridgeMarkerOverridesDomainBypass(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{}}`))
	}))
	defer srv.Close()

	build := func(ctx context.Context) *http.Request {
		req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		return req.WithContext(ctx)
	}

	// Unmarked: bypass list says the host would be direct — but this test URL
	// isn't codebuddy/workbuddy, so plain path also works; the point is both
	// marker states complete successfully.
	if _, err := hostHTTPDo(build(context.Background())); err != nil {
		t.Fatalf("unmarked direct call: %v", err)
	}
	if _, err := hostHTTPDo(build(withHTTPBridge(context.Background()))); err != nil {
		t.Fatalf("bridge-marked call (no bridge in tests → direct fallback): %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 upstream calls, got %d", got)
	}
}

// TestBillingCall_BridgeAttemptLandsOnFallbackServer exercises the full
// v0.9.52 ladder end-to-end in a no-bridge environment: attempt 0 EOFs,
// attempt 1 (rescue) EOFs, attempt 2 (bridge → direct fallback in tests)
// succeeds. 3 upstream calls total, response returned.
func TestBillingCall_BridgeAttemptLandsOnFallbackServer(t *testing.T) {
	orig := billingRetryDelays
	billingRetryDelays = []time.Duration{1 * time.Millisecond, 1 * time.Millisecond}
	defer func() { billingRetryDelays = orig }()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			hj, _ := w.(http.Hijacker)
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"via":"third-attempt"}}`))
	}))
	defer srv.Close()

	restore := setBillingBase(srv.URL)
	defer restore()

	data, err := billingCall(&storedAuth{}, "/probe", nil)
	if err != nil {
		t.Fatalf("expected ladder recovery, got: %v", err)
	}
	if string(data) != `{"via":"third-attempt"}` {
		t.Fatalf("unexpected data: %s", string(data))
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}
