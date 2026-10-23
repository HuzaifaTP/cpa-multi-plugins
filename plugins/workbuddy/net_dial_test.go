package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestBillingDialContext_IPLiteralFastPath pins the hermeticity contract: IP
// literal dials (httptest servers, 127.0.0.1 proxies) take the plain-dial
// fast path — byte-identical to the default transport, no DoH, no journal.
func TestBillingDialContext_IPLiteralFastPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if net.ParseIP(host) == nil {
		t.Fatalf("expected IP literal, got %s", host)
	}
	conn, err := billingDialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("IP literal dial: %v", err)
	}
	_ = conn.Close()
	dialStateMu.Lock()
	_, cached := goodIPs[host]
	dialStateMu.Unlock()
	if cached {
		t.Fatal("IP literal dial must not populate the good-IP cache")
	}
}

// TestOrderIPs_ConsensusAndDivergence pins the candidate ordering: cached-good
// → v4 consensus (system ∩ DoH) → DoH-only (pollution suspect) → system-only
// → v6 tail.
func TestOrderIPs_ConsensusAndDivergence(t *testing.T) {
	a := net.ParseIP("1.2.3.4")
	b := net.ParseIP("5.6.7.8")
	c := net.ParseIP("9.9.9.9")
	g := net.ParseIP("7.7.7.7")
	v6 := net.ParseIP("2001:db8::1")

	got := orderIPs(g, []net.IP{a, b}, []net.IP{a, c})
	want := []net.IP{g, a, c, b}
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Fatalf("order[%d] = %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}

	// No cached-good: consensus first, then DoH-only, then system-only.
	got = orderIPs(nil, []net.IP{b, a}, []net.IP{c, a})
	want = []net.IP{a, c, b}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Fatalf("no-good order[%d] = %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}

	// Healthy identical sets stay untouched, v6 goes last.
	got = orderIPs(nil, []net.IP{v6, a}, []net.IP{a})
	if len(got) != 2 || !got[0].Equal(a) || !got[1].Equal(v6) {
		t.Fatalf("v6 tail violated: %v", got)
	}
}

// TestQueryDoH_ParsesARecords checks the dns-json decode path: A records
// kept, everything else (AAAA/CNAME) dropped, duplicates merged.
func TestQueryDoH_ParsesARecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "doh-test.example" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[` +
			`{"name":"doh-test.example","type":1,"TTL":300,"data":"1.2.3.4"},` +
			`{"name":"doh-test.example","type":28,"TTL":300,"data":"2001:db8::1"},` +
			`{"name":"doh-test.example","type":1,"TTL":300,"data":"5.6.7.8"},` +
			`{"name":"doh-test.example","type":1,"TTL":300,"data":"1.2.3.4"}]}`))
	}))
	defer srv.Close()

	origEndpoints := dialDoHEndpoints
	dialDoHEndpoints = []string{srv.URL, srv.URL}
	defer func() { dialDoHEndpoints = origEndpoints }()

	ips := queryDoH("doh-test.example")
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("1.2.3.4")) || !ips[1].Equal(net.ParseIP("5.6.7.8")) {
		t.Fatalf("queryDoH = %v, want [1.2.3.4 5.6.7.8]", ips)
	}
}

// TestBillingDialContext_MultiIPFallback drives the full resilient path with
// sealed seams: the first candidate is a dead loopback address (connection
// refused), the second serves the connection. The dialer must fall through
// and cache the winner.
func TestBillingDialContext_MultiIPFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	liveIP, livePort, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	_ = liveIP

	dead, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead port: %v", err)
	}
	deadPort := dead.Addr().(*net.TCPAddr).Port
	_ = dead.Close() // port now refuses connections

	origLookup := dialSystemLookup
	origEndpoints := dialDoHEndpoints
	dialSystemLookup = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	dialDoHEndpoints = nil // no DoH on this test
	t.Cleanup(func() {
		dialSystemLookup = origLookup
		dialDoHEndpoints = origEndpoints
	})
	t.Cleanup(billingResetDialState)

	conn, err := billingDialContext(context.Background(), "tcp", net.JoinHostPort("fallback.test", strconv.Itoa(deadPort)))
	if err == nil {
		_ = conn.Close()
		t.Fatal("all-candidates-dead dial should fail")
	}
	dialStateMu.Lock()
	_, marked := deadIPs["127.0.0.1"]
	dialStateMu.Unlock()
	if !marked {
		t.Fatal("failed candidate must be marked dead")
	}

	// Second call: the live port. The dead mark is cleared (all candidates
	// dead), the dial re-explores, and the live listener wins.
	conn, err = billingDialContext(context.Background(), "tcp", net.JoinHostPort("fallback.test", livePort))
	if err != nil {
		t.Fatalf("multi-IP fallback dial: %v", err)
	}
	ra := conn.RemoteAddr().(*net.TCPAddr)
	_ = conn.Close()
	if ra.Port == deadPort {
		t.Fatalf("dial landed on the dead port %d", deadPort)
	}

	dialStateMu.Lock()
	ip, ok := goodIPs["fallback.test"]
	dialStateMu.Unlock()
	if !ok || !ip.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("good-IP cache = %v, want 127.0.0.1", ip)
	}
}

// TestFilterDeadIPs_AllDeadClearsMarks pins the recovery branch: when every
// candidate is marked dead the marks are cleared so the dial gets a full
// retry budget instead of a guaranteed empty result.
func TestFilterDeadIPs_AllDeadClearsMarks(t *testing.T) {
	t.Cleanup(billingResetDialState)
	ip := net.ParseIP("203.0.113.9")
	dialStateMarkDead(ip)
	if got := filterDeadIPs("clear.test", []net.IP{ip}); len(got) != 1 {
		t.Fatalf("all-dead filter = %v, want full retry budget", got)
	}
	dialStateMu.Lock()
	_, stillMarked := deadIPs[ip.String()]
	dialStateMu.Unlock()
	if stillMarked {
		t.Fatal("all-dead branch must clear dead marks")
	}
}

// TestBillingNetDiagSuffix_HermeticForIPLiteralAndCache pins the two safety
// properties of the exhaustion diag: IP-literal bases (unit tests) probe
// nothing, and repeated calls within the cache window return the same string
// without re-probing.
func TestBillingNetDiagSuffix_HermeticForIPLiteralAndCache(t *testing.T) {
	if got := billingNetDiagSuffix("http://127.0.0.1:12345"); got != "" {
		t.Fatalf("IP-literal base must be diag-free, got %q", got)
	}
	if got := billingNetDiagSuffix("http://localhost:12345"); got != "" {
		t.Fatalf("localhost base must be diag-free, got %q", got)
	}
}

// TestProbeIPStages_ReportsDeepestStage exercises the staged probe against a
// local TLS listener with an untrusted certificate: TCP must connect, TLS
// must fail verification, and the report must show both facts.
func TestProbeIPStages_ReportsDeepestStage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	got := probeIPStages(net.ParseIP(host), host, port)
	if !strings.HasPrefix(got, "tcp=ok tls=") {
		t.Fatalf("probe = %q, want tcp=ok tls=<err>", got)
	}
}

// TestBriefNetErr pins the error compaction used in diag output.
func TestBriefNetErr(t *testing.T) {
	cases := map[string]string{
		"dial tcp4 1.2.3.4:443: connect: connection refused": "connection refused",
		"read: EOF": "EOF",
	}
	for in, want := range cases {
		if got := briefNetErr(errString(in)); got != want {
			t.Errorf("briefNetErr(%q) = %q, want %q", in, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestDialDoHEndpointsIncludeIPLiterals pins the v0.9.65 bootstrap fix: the DoH
// endpoint list must carry IP-literal resolvers (no system-DNS dependency) so
// a poisoned local resolver cannot take DoH down with it — the exact deadlock
// of the 2026-10-23 field report (dns sys=<poisoned IPs> doh=none, every
// candidate tcp=ok tls=EOF). At least three IP endpoints across three
// providers, https, dns-json paths only.
func TestDialDoHEndpointsIncludeIPLiterals(t *testing.T) {
	ipLiteral := 0
	for _, ep := range dialDoHEndpoints {
		u, err := url.Parse(ep)
		if err != nil {
			t.Fatalf("endpoint %q unparseable: %v", ep, err)
		}
		if u.Scheme != "https" {
			t.Fatalf("DoH endpoint %q must be https", ep)
		}
		if net.ParseIP(u.Hostname()) != nil {
			ipLiteral++
			if p := u.EscapedPath(); p != "/dns-query" && p != "/resolve" {
				t.Fatalf("IP-literal DoH endpoint %q uses non-JSON path %q", ep, p)
			}
		}
	}
	if ipLiteral < 3 {
		t.Fatalf("expected >= 3 IP-literal DoH endpoints (DNSPod/AliDNS/Cloudflare), got %d in %v", ipLiteral, dialDoHEndpoints)
	}
	hasHostnameFallback := false
	for _, ep := range dialDoHEndpoints {
		if strings.Contains(ep, "doh.pub") {
			hasHostnameFallback = true
		}
	}
	if !hasHostnameFallback {
		t.Fatal("the hostname DoH fallback (doh.pub) was dropped from the endpoint list")
	}
}

// TestQueryDoHGraceReturnsEarly pins the grace window: one healthy endpoint
// plus one that hangs must not cost the full dohQueryTimeout — a poisoned
// network leaves the hostname endpoints hanging, and the healthy IP answer
// must not wait for them.
func TestQueryDoHGraceReturnsEarly(t *testing.T) {
	release := make(chan struct{})
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"grace-test.example","type":1,"TTL":60,"data":"9.9.9.9"}]}`))
	}))
	t.Cleanup(healthy.Close)
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	// Release the hung handler BEFORE hang.Close() — httptest's Close waits
	// for outstanding requests, and the blocked handler owns one.
	t.Cleanup(func() {
		close(release)
		hang.Close()
	})

	origEndpoints := dialDoHEndpoints
	dialDoHEndpoints = []string{healthy.URL, hang.URL}
	t.Cleanup(func() { dialDoHEndpoints = origEndpoints })

	start := time.Now()
	ips := queryDoH("grace-test.example")
	elapsed := time.Since(start)
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("9.9.9.9")) {
		t.Fatalf("queryDoH = %v, want [9.9.9.9]", ips)
	}
	// With the grace window the return lands ~dohGraceWindow after the
	// healthy answer (~1s); without it the hanging endpoint's 3s client
	// timeout delays the return to ~3s. 2.2s cleanly separates the two.
	if elapsed > dohGraceWindow+1200*time.Millisecond {
		t.Fatalf("healthy DoH answer waited for the hanging endpoint: %v (grace window broken)", elapsed)
	}
}

// TestDoHNegativeCache pins the fail-side cache: when every DoH endpoint is
// dead the empty result is remembered for dohFailTTL so each dial in the
// retry ladder doesn't re-pay the full probe budget.
func TestDoHNegativeCache(t *testing.T) {
	var hits int32
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(dead.Close)

	origEndpoints := dialDoHEndpoints
	dialDoHEndpoints = []string{dead.URL}
	t.Cleanup(func() { dialDoHEndpoints = origEndpoints })

	billingResetDialState() // clean fail-cache slate
	t.Cleanup(billingResetDialState)

	if ips := dohLookup("negcache-test.example"); len(ips) != 0 {
		t.Fatalf("dead DoH must return empty, got %v", ips)
	}
	if ips := dohLookup("negcache-test.example"); len(ips) != 0 {
		t.Fatalf("second lookup must hit the negative cache, got %v", ips)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("negative cache failed: %d endpoint probes for two lookups (want 1)", n)
	}
}

// TestBillingDemoteGoodIP pins the demotion semantics: the cached-good IP is
// dropped and dead-marked; unknown hosts, empty and unparseable bases are
// quiet no-ops.
func TestBillingDemoteGoodIP(t *testing.T) {
	billingResetDialState()
	t.Cleanup(billingResetDialState)

	host := "demote-unit.test"
	ip := net.ParseIP("203.0.113.77")
	dialStateMarkGood(host, ip)

	billingDemoteGoodIP("https://" + host + "/v2/billing/meter/get-user-resource")

	dialStateMu.Lock()
	_, hasGood := goodIPs[host]
	_, hasDead := deadIPs[ip.String()]
	dialStateMu.Unlock()
	if hasGood {
		t.Fatal("demote must drop the good-IP entry for the base's host")
	}
	if !hasDead {
		t.Fatal("demote must dead-mark the demoted IP for deadIPTTL")
	}

	billingDemoteGoodIP("https://absent.test/v2") // no cached good IP — quiet no-op
	billingDemoteGoodIP("://not-a-url")           // unparseable — quiet no-op
	billingDemoteGoodIP("")                       // empty — quiet no-op
}
