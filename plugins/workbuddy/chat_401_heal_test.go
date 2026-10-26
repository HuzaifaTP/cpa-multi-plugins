package main

// chat_401_heal_test.go — pins the 0.9.74 chat-plane 401 self-heal end to
// end against a fake upstream hosting the chat endpoint AND the
// /v2/plugin/auth/token/refresh endpoint, with the host-auth seams stubbed
// so the heal path never touches the live RPC bridge (same harness shape as
// billing_401_renew_test.go).

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// chatHealSSE is a minimal healthy upstream SSE answer (the folding fixture
// from aggregate_guard_test.go).
const chatHealSSE = "data: {\"id\":\"c1\",\"model\":\"m-test\",\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"he\"}}]}\n" +
	": keep-alive\n" +
	"data: {\"id\":\"c1\",\"model\":\"m-test\",\"choices\":[{\"delta\":{\"content\":\"llo\"},\"finish_reason\":null}]}\n" +
	"data: {\"id\":\"c1\",\"model\":\"m-test\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":5}}\n" +
	"data: [DONE]\n"

// openresty401HTML is the field-report shape: the APISIX/openresty gateway
// bouncing a dead access token with its HTML error page (no business
// envelope, "401 Authorization Required", powered-by openresty).
const openresty401HTML = "<html>\r\n<head><title>401 Authorization Required</title></head>\r\n<body>\r\n" +
	"<center><h1>401 Authorization Required</h1></center>\r\n<hr><center>openresty</center>\r\n" +
	"<p><em>Powered by APISIX</em></p>\r\n</body>\r\n</html>"

// swapChatEndpoint redirects the chat endpoint to base (the 0.9.74 test
// seam; same shape as swapRefreshEndpoint).
func swapChatEndpoint(t *testing.T, base string) func() {
	t.Helper()
	orig := chatEndpointOverride
	chatEndpointOverride = base
	return func() { chatEndpointOverride = orig }
}

// chatHealExecutorRaw builds one handleExecExecute RPC body whose
// StorageJSON snapshot carries NO authIndex — the executor's real shape, so
// the heal's identity resolution (chat401ResolveAuthIndex) is exercised.
func chatHealExecutorRaw(t *testing.T) []byte {
	t.Helper()
	req := pluginapi.ExecutorRequest{
		AuthID:      "wb-1",
		Model:       "m-test",
		Payload:     []byte(`{"model":"m-test","messages":[{"role":"user","content":"hi"}]}`),
		StorageJSON: []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`),
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal executor request: %v", err)
	}
	return raw
}

// chatHealEnv wires the standard seam set: chat + refresh endpoints on the
// fake upstream, host auth get/save stubbed around a shared doc.
func chatHealEnv(t *testing.T, srvURL string, doc *[]byte, mu *sync.Mutex, saved *[][]byte) {
	t.Helper()
	restoreChat := swapChatEndpoint(t, srvURL)
	t.Cleanup(restoreChat)
	restoreUp := swapRefreshEndpoint(t, srvURL)
	t.Cleanup(restoreUp)
	restorePhys := stubHostAuthGetPhysical(t, "wb-1", "workbuddy-u1.json", func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), (*doc)...)
	})
	t.Cleanup(restorePhys)
	restoreSave := stubHostAuthSaveJSON(t, func(name string, raw []byte) error {
		mu.Lock()
		defer mu.Unlock()
		*saved = append(*saved, append([]byte(nil), raw...))
		*doc = append([]byte(nil), raw...)
		return nil
	})
	t.Cleanup(restoreSave)
}

// decodeExecutorPayload asserts an ok envelope and returns the folded
// completion payload.
func decodeExecutorPayload(t *testing.T, raw []byte) string {
	t.Helper()
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *envelopeError  `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v (%s)", err, raw)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got error: %+v (%s)", env.Error, raw)
	}
	var resp struct {
		Payload []byte `json:"Payload"`
	}
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("unmarshal result: %v (%s)", err, env.Result)
	}
	return string(resp.Payload)
}

// chat401StatusCode asserts the error still carries the account-level 401
// for the host's cooldown layer and returns it.
func chat401StatusCode(t *testing.T, err error) int {
	t.Helper()
	var sc interface{ StatusCode() int }
	if !errors.As(err, &sc) {
		t.Fatalf("error carries no StatusCode: %v", err)
	}
	return sc.StatusCode()
}

// TestChatExecute_401HealsRenewsAndResends — the core chat-plane heal: the
// openresty 401 HTML bounce → ONE renewal → ONE resend with the new token →
// folded completion, with the rotated tokens persisted. The healed request
// produces no failed-usage entry and no cooldown notes (the bookkeeping only
// runs when no rescue happened).
func TestChatExecute_401HealsRenewsAndResends(t *testing.T) {
	reset401RenewState(t)

	var chat, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}}`))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			chat.Add(1)
			if r.Header.Get("Authorization") == "Bearer new-at" {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(chatHealSSE))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(openresty401HTML))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var mu sync.Mutex
	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	var saved [][]byte
	chatHealEnv(t, srv.URL, &doc, &mu, &saved)

	out, err := handleExecExecute(chatHealExecutorRaw(t))
	if err != nil {
		t.Fatalf("expected self-healed success, got: %v", err)
	}
	if payload := decodeExecutorPayload(t, out); !strings.Contains(payload, `"content":"hello"`) {
		t.Fatalf("folded completion missing content: %s", payload)
	}
	if chat.Load() != 2 {
		t.Fatalf("chat calls = %d, want 2 (bounced + resent)", chat.Load())
	}
	if refresh.Load() != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1", refresh.Load())
	}
	if len(saved) != 1 {
		t.Fatalf("persisted saves = %d, want 1 (the renewal)", len(saved))
	}
	if !strings.Contains(string(saved[0]), "new-at") || !strings.Contains(string(saved[0]), "new-rt") {
		t.Fatalf("saved doc missing rotated tokens: %s", saved[0])
	}
}

// TestChatExecute_401SessionDeadDisablesAndGuides — the only heal outcome
// that is a verdict on the credential: the refresh itself refused with the
// session-dead family (12153). The credential is flagged disabled and the
// surfaced error carries the bilingual re-login guidance instead of dumping
// openresty HTML; the account-level 401 status survives for the host
// cooldown.
func TestChatExecute_401SessionDeadDisablesAndGuides(t *testing.T) {
	reset401RenewState(t)

	var chat, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			chat.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(openresty401HTML))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var mu sync.Mutex
	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	var saved [][]byte
	chatHealEnv(t, srv.URL, &doc, &mu, &saved)

	_, err := handleExecExecute(chatHealExecutorRaw(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if chat.Load() != 1 || refresh.Load() != 1 {
		t.Fatalf("chat=%d refresh=%d, want 1/1 (no resend after a refused renewal)", chat.Load(), refresh.Load())
	}
	msg := err.Error()
	if !strings.Contains(msg, "重新登录") || !strings.Contains(msg, "re-login") {
		t.Fatalf("error missing the re-login guidance: %q", msg)
	}
	if !strings.Contains(msg, "upstream 401: ") {
		t.Fatalf("raw 401 shape must stay first for log parsers: %q", msg)
	}
	if got := chat401StatusCode(t, err); got != http.StatusUnauthorized {
		t.Fatalf("StatusCode = %d, want 401 (host cooldown contract)", got)
	}
	if len(saved) == 0 || !strings.Contains(string(saved[0]), `"disabled":true`) {
		t.Fatalf("session-dead flag not persisted: %v", saved)
	}
}

// TestChatExecute_401RenewedStillRefused — the renewal succeeded but the
// gateway refuses the FRESH token too: the resend's 401 becomes the primary
// failure and the copy says renewed-once / re-login.
func TestChatExecute_401RenewedStillRefused(t *testing.T) {
	reset401RenewState(t)

	var chat, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}}`))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			chat.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(openresty401HTML))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var mu sync.Mutex
	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	var saved [][]byte
	chatHealEnv(t, srv.URL, &doc, &mu, &saved)

	_, err := handleExecExecute(chatHealExecutorRaw(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if chat.Load() != 2 || refresh.Load() != 1 {
		t.Fatalf("chat=%d refresh=%d, want 2/1 (bounce + refused resend)", chat.Load(), refresh.Load())
	}
	msg := err.Error()
	if !strings.Contains(msg, "已续期一次仍被网关 401 拒绝") || !strings.Contains(msg, "Renewed once and the gateway still answers 401") {
		t.Fatalf("error missing the renewed-once guidance: %q", msg)
	}
	if got := chat401StatusCode(t, err); got != http.StatusUnauthorized {
		t.Fatalf("StatusCode = %d, want 401", got)
	}
}

// TestChatExecute_401ThrottledKeepsRaw — a heal attempt inside the 30s
// window must not spend the refresh token again, and the surfaced error
// keeps the plain raw-401 shape with NO verdict copy (a concurrent renewal
// may already be fixing the credential).
func TestChatExecute_401ThrottledKeepsRaw(t *testing.T) {
	reset401RenewState(t)
	billing401Mu.Lock()
	billing401LastRenew["wb-1"] = time.Now()
	billing401Mu.Unlock()

	var chat, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","expiresIn":3600}}`))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			chat.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(openresty401HTML))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var mu sync.Mutex
	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	var saved [][]byte
	chatHealEnv(t, srv.URL, &doc, &mu, &saved)

	_, err := handleExecExecute(chatHealExecutorRaw(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if chat.Load() != 1 || refresh.Load() != 0 {
		t.Fatalf("chat=%d refresh=%d, want 1/0 (throttled heal spends nothing)", chat.Load(), refresh.Load())
	}
	if !strings.HasPrefix(err.Error(), "upstream 401: ") {
		t.Fatalf("throttled heal must keep the raw 401 shape: %q", err.Error())
	}
	for _, verdict := range []string{"重新登录", "re-login", "已续期一次", "Renewed once"} {
		if strings.Contains(err.Error(), verdict) {
			t.Fatalf("throttled heal must not claim a verdict (%q): %q", verdict, err.Error())
		}
	}
	if got := chat401StatusCode(t, err); got != http.StatusUnauthorized {
		t.Fatalf("StatusCode = %d, want 401", got)
	}
}

// TestCollectUpstreamStream_401Heals — the stream sync-collector path heals
// the same way: bounced attempt → renewal → resend → chunks, with the retry
// invisible to the caller.
func TestCollectUpstreamStream_401Heals(t *testing.T) {
	reset401RenewState(t)

	var chat, refresh atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token/refresh"):
			refresh.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}}`))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			chat.Add(1)
			if r.Header.Get("Authorization") == "Bearer new-at" {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(chatHealSSE))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(openresty401HTML))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var mu sync.Mutex
	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	var saved [][]byte
	chatHealEnv(t, srv.URL, &doc, &mu, &saved)

	sa := &storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"}
	collector := &sseUsageCollector{}
	chunks, statusCode, err := collectUpstreamStream(
		[]byte(`{"model":"m-test","messages":[{"role":"user","content":"hi"}],"stream":true}`),
		sa, "wb-1", false, collector, "m-test")
	if err != nil {
		t.Fatalf("expected self-healed success, got: %v", err)
	}
	if statusCode >= 400 {
		t.Fatalf("statusCode = %d, want 2xx", statusCode)
	}
	if len(chunks) == 0 {
		t.Fatal("expected collected chunks")
	}
	if chat.Load() != 2 || refresh.Load() != 1 {
		t.Fatalf("chat=%d refresh=%d, want 2/1 (bounced + resent)", chat.Load(), refresh.Load())
	}
}

// TestBilling401RenewOnce_ConcurrentCallersJoinInFlight — v0.9.74's
// concurrency upgrade: callers that arrive while a renewal is running JOIN
// it (one refresh-token spend) and all leave with the token it produced,
// instead of some failing "throttled" with the raw 401.
func TestBilling401RenewOnce_ConcurrentCallersJoinInFlight(t *testing.T) {
	reset401RenewState(t)

	var refresh atomic.Int32
	blockRefresh := make(chan struct{})
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(blockRefresh) }) }
	defer unblock()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token/refresh") {
			refresh.Add(1)
			<-blockRefresh // hold the renewal so joiners pile up
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	restoreUp := swapRefreshEndpoint(t, srv.URL)
	defer restoreUp()

	var mu sync.Mutex
	doc := []byte(`{"auth":{"accessToken":"at-1","refreshToken":"rt-1"},"account":{"uid":"u1"}}`)
	restorePhys := stubHostAuthGetPhysical(t, "wb-1", "workbuddy-u1.json", func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), doc...)
	})
	defer restorePhys()
	restoreSave := stubHostAuthSaveJSON(t, func(name string, raw []byte) error {
		mu.Lock()
		defer mu.Unlock()
		doc = append([]byte(nil), raw...)
		return nil
	})
	defer restoreSave()

	// The owner starts first; wait until the refresh handler is actually
	// entered so every later caller is guaranteed to find the in-flight entry.
	ownerDone := make(chan struct{})
	var ownerFresh *storedAuth
	var ownerErr error
	go func() {
		defer close(ownerDone)
		ownerFresh, ownerErr = billing401RenewOnce(&storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for refresh.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if refresh.Load() == 0 {
		t.Fatal("owner never reached the refresh endpoint")
	}

	const joiners = 3
	freshCh := make(chan *storedAuth, joiners)
	errCh := make(chan error, joiners)
	for i := 0; i < joiners; i++ {
		go func() {
			fresh, err := billing401RenewOnce(&storedAuth{Auth: storedTokens{AccessToken: "at-1", RefreshToken: "rt-1"}, authIndex: "wb-1"})
			freshCh <- fresh
			errCh <- err
		}()
	}
	time.Sleep(100 * time.Millisecond) // let the joiners pile up on the channel
	unblock()
	<-ownerDone

	if ownerErr != nil {
		t.Fatalf("owner renewal failed: %v", ownerErr)
	}
	if ownerFresh == nil || ownerFresh.Auth.AccessToken != "new-at" {
		t.Fatalf("owner did not get the fresh token: %+v", ownerFresh)
	}
	for i := 0; i < joiners; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("joiner %d failed (must join, not throttle): %v", i, err)
		}
		fresh := <-freshCh
		if fresh == nil || fresh.Auth.AccessToken != "new-at" {
			t.Fatalf("joiner %d did not get the shared fresh token: %+v", i, fresh)
		}
	}
	if refresh.Load() != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1 (joiners must not re-spend)", refresh.Load())
	}
}
