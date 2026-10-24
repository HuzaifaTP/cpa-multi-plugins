package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The 0.9.68 billing 401 self-heal (magpie packages/workbuddy 0.1.31
// parity), pinned end-to-end against a fake upstream hosting BOTH the
// billing plane and the /v2/plugin/auth/token/refresh endpoint, with the
// host-auth seams stubbed so the renew path never touches the live RPC
// bridge.

func reset401RenewState(t *testing.T) {
	t.Helper()
	billing401Mu.Lock()
	billing401LastRenew = map[string]time.Time{}
	billing401Mu.Unlock()
	t.Cleanup(func() {
		billing401Mu.Lock()
		billing401LastRenew = map[string]time.Time{}
		billing401Mu.Unlock()
	})
}

func stubHostAuthGetPhysical(t *testing.T, authIndex, name string, doc func() []byte) func() {
	t.Helper()
	orig := hostAuthGetPhysicalFn
	hostAuthGetPhysicalFn = func(idx string) (*hostAuthPhysical, error) {
		if idx != authIndex {
			return nil, fmt.Errorf("unexpected auth index %q", idx)
		}
		return &hostAuthPhysical{AuthIndex: idx, Name: name, JSON: doc()}, nil
	}
	return func() { hostAuthGetPhysicalFn = orig }
}

func stubHostAuthSaveJSON(t *testing.T, save func(name string, raw []byte) error) func() {
	t.Helper()
	orig := hostAuthSaveJSONFn
	hostAuthSaveJSONFn = save
	return func() { hostAuthSaveJSONFn = orig }
}

func swapRefreshEndpoint(t *testing.T, base string) func() {
	t.Helper()
	orig := refreshEndpointOverride
	refreshEndpointOverride = base
	return func() { refreshEndpointOverride = orig }
}

// TestBillingCall_401RenewsOnceAndResends — the core heal: 401 (JSON 12153)
// → one renewal → one resend with the new token → success, with the rotated
// tokens persisted through the merge-preserving save path.
func TestBillingCall_401RenewsOnceAndResends(t *testing.T) {
	reset401RenewState(t)

	var billing, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}}`))
		default:
			billing.Add(1)
			if r.Header.Get("Authorization") == "Bearer new-at" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"k":"v"}}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		}
	}))
	defer srv.Close()

	restoreBill := setBillingBase(srv.URL)
	defer restoreBill()
	restoreUp := swapRefreshEndpoint(t, srv.URL)
	defer restoreUp()

	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	var saved [][]byte
	restorePhys := stubHostAuthGetPhysical(t, "wb-1", "workbuddy-u1.json", func() []byte { return doc })
	defer restorePhys()
	restoreSave := stubHostAuthSaveJSON(t, func(name string, raw []byte) error {
		saved = append(saved, raw)
		doc = raw
		return nil
	})
	defer restoreSave()

	sa := &storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"}
	data, err := billingCall(sa, "/v2/billing/meter/get-user-resource", nil)
	if err != nil {
		t.Fatalf("expected self-healed success, got: %v", err)
	}
	if string(data) != `{"k":"v"}` {
		t.Fatalf("data = %s", string(data))
	}
	if n := billing.Load(); n != 2 {
		t.Fatalf("billing calls = %d, want 2 (original + resend)", n)
	}
	if n := refresh.Load(); n != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1", n)
	}
	if len(saved) != 1 {
		t.Fatalf("persisted saves = %d, want 1", len(saved))
	}
	if !strings.Contains(string(saved[0]), "new-at") || !strings.Contains(string(saved[0]), "new-rt") {
		t.Fatalf("saved doc missing rotated tokens: %s", saved[0])
	}
}

// TestBillingCall_401HTMLPageRenewsAndResends — the gateway-bounce variant
// (nginx/APISIX 401 HTML page, growthHTTPError branch of the classifier)
// heals the same way.
func TestBillingCall_401HTMLPageRenewsAndResends(t *testing.T) {
	reset401RenewState(t)

	var billing, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}}`))
		default:
			billing.Add(1)
			if r.Header.Get("Authorization") == "Bearer new-at" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"k":"v"}}`))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("<html><center><h1>401 Authorization Required</h1></center></html>"))
		}
	}))
	defer srv.Close()

	restoreBill := setBillingBase(srv.URL)
	defer restoreBill()
	restoreUp := swapRefreshEndpoint(t, srv.URL)
	defer restoreUp()

	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	restorePhys := stubHostAuthGetPhysical(t, "wb-1", "workbuddy-u1.json", func() []byte { return doc })
	defer restorePhys()
	restoreSave := stubHostAuthSaveJSON(t, func(name string, raw []byte) error {
		doc = raw
		return nil
	})
	defer restoreSave()

	sa := &storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"}
	data, err := billingCall(sa, "/v2/billing/meter/get-user-resource", nil)
	if err != nil {
		t.Fatalf("expected self-healed success, got: %v", err)
	}
	if string(data) != `{"k":"v"}` {
		t.Fatalf("data = %s", string(data))
	}
	if billing.Load() != 2 || refresh.Load() != 1 {
		t.Fatalf("billing=%d refresh=%d, want 2/1", billing.Load(), refresh.Load())
	}
}

// TestBillingCall_401RenewRefusedMarksSessionDead — the only heal outcome
// that is a verdict on the credential: the refresh itself refused with the
// session-dead family. The account is flagged disabled and the surfaced
// error says to sign in again; no resend happens.
func TestBillingCall_401RenewRefusedMarksSessionDead(t *testing.T) {
	reset401RenewState(t)

	var billing, refresh atomic.Int32
	var saved atomic.Value // []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		default:
			billing.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		}
	}))
	defer srv.Close()

	restoreBill := setBillingBase(srv.URL)
	defer restoreBill()
	restoreUp := swapRefreshEndpoint(t, srv.URL)
	defer restoreUp()

	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	restorePhys := stubHostAuthGetPhysical(t, "wb-1", "workbuddy-u1.json", func() []byte { return doc })
	defer restorePhys()
	restoreSave := stubHostAuthSaveJSON(t, func(name string, raw []byte) error {
		saved.Store(raw)
		doc = raw
		return nil
	})
	defer restoreSave()

	sa := &storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"}
	_, err := billingCall(sa, "/v2/billing/meter/get-user-resource", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if n := billing.Load(); n != 1 {
		t.Fatalf("billing calls = %d, want 1 (no resend after refused renewal)", n)
	}
	if refresh.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", refresh.Load())
	}
	msg := err.Error()
	for _, want := range []string{"re-login required", "session dead"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error missing %q: %q", want, msg)
		}
	}
	raw, _ := saved.Load().([]byte)
	if len(raw) == 0 || !strings.Contains(string(raw), `"disabled":true`) {
		t.Fatalf("session-dead flag not persisted: %s", raw)
	}
}

// TestBillingCall_401TakesTokenAnotherProcessSaved — magpie 0.1.31: "a
// token another process saved since is taken first instead of spending the
// refresh token again."
func TestBillingCall_401TakesTokenAnotherProcessSaved(t *testing.T) {
	reset401RenewState(t)

	var billing, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		default:
			billing.Add(1)
			if r.Header.Get("Authorization") == "Bearer at-2" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"k":"v"}}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		}
	}))
	defer srv.Close()

	restoreBill := setBillingBase(srv.URL)
	defer restoreBill()
	restoreUp := swapRefreshEndpoint(t, srv.URL)
	defer restoreUp()

	// The on-disk doc already holds the renewed token; the caller's snapshot
	// is stale.
	doc := []byte(`{"auth":{"accessToken":"at-2","refreshToken":"rt-2"},"account":{"uid":"u1"}}`)
	restorePhys := stubHostAuthGetPhysical(t, "wb-1", "workbuddy-u1.json", func() []byte { return doc })
	defer restorePhys()
	restoreSave := stubHostAuthSaveJSON(t, func(name string, raw []byte) error { return nil })
	defer restoreSave()

	sa := &storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"}
	data, err := billingCall(sa, "/v2/billing/meter/get-user-resource", nil)
	if err != nil {
		t.Fatalf("expected healed-by-concurrent-renewal success, got: %v", err)
	}
	if string(data) != `{"k":"v"}` {
		t.Fatalf("data = %s", string(data))
	}
	if billing.Load() != 2 {
		t.Fatalf("billing calls = %d, want 2", billing.Load())
	}
	if refresh.Load() != 0 {
		t.Fatalf("refresh calls = %d, want 0 (the saved token must be taken, not re-spent)", refresh.Load())
	}
}

// TestBillingCall_401RenewThrottled — a second heal inside the window must
// not spend the refresh token again, and the surfaced error keeps the plain
// 401 shape (no re-login verdict — a concurrent renewal may already be
// fixing the credential).
func TestBillingCall_401RenewThrottled(t *testing.T) {
	reset401RenewState(t)
	billing401Mu.Lock()
	billing401LastRenew["wb-1"] = time.Now()
	billing401Mu.Unlock()

	var billing, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","expiresIn":3600}}`))
		default:
			billing.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		}
	}))
	defer srv.Close()

	restoreBill := setBillingBase(srv.URL)
	defer restoreBill()
	restoreUp := swapRefreshEndpoint(t, srv.URL)
	defer restoreUp()

	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	restorePhys := stubHostAuthGetPhysical(t, "wb-1", "workbuddy-u1.json", func() []byte { return doc })
	defer restorePhys()
	restoreSave := stubHostAuthSaveJSON(t, func(name string, raw []byte) error { return nil })
	defer restoreSave()

	sa := &storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"}
	_, err := billingCall(sa, "/v2/billing/meter/get-user-resource", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if billing.Load() != 1 || refresh.Load() != 0 {
		t.Fatalf("billing=%d refresh=%d, want 1/0", billing.Load(), refresh.Load())
	}
	if strings.Contains(err.Error(), "re-login required") {
		t.Fatalf("throttled heal must not claim a re-login verdict: %q", err.Error())
	}
}

// TestBillingCall_401SnapshotWithoutIdentitySkipsHeal — hand-built snapshots
// (no host identity, or no refresh token) keep the pre-0.9.68 behavior
// exactly: plain 401, one call, no renewal attempt.
func TestBillingCall_401SnapshotWithoutIdentitySkipsHeal(t *testing.T) {
	reset401RenewState(t)

	var billing, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			billing.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		}
	}))
	defer srv.Close()

	restoreBill := setBillingBase(srv.URL)
	defer restoreBill()
	restoreUp := swapRefreshEndpoint(t, srv.URL)
	defer restoreUp()

	_, err := billingCall(&storedAuth{}, "/test", nil)
	if err == nil || !strings.Contains(err.Error(), "code=12153") {
		t.Fatalf("err = %v", err)
	}
	if billing.Load() != 1 || refresh.Load() != 0 {
		t.Fatalf("billing=%d refresh=%d, want 1/0", billing.Load(), refresh.Load())
	}
}
