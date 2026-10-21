package main

import (
	"net/http"
	"regexp"
	"testing"
)

var conversationUUIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TestBackendHeaders_GlobalConversationHeaders pins the Global-realm fix for
// upstream 11128 "request illegal": without the three X-Conversation-* headers
// the gateway rejects otherwise valid streaming chat calls as "not sent from
// an official client". CN and Intl realms do not check them.
func TestBackendHeaders_GlobalConversationHeaders(t *testing.T) {
	global := &storedAuth{Auth: storedTokens{AccessToken: "at", Domain: "www.workbuddy.ai"}}
	req := &http.Request{Header: http.Header{}}
	backendHeaders(req, global)

	for _, h := range []string{"X-Conversation-ID", "X-Conversation-Request-ID", "X-Conversation-Message-ID"} {
		v := req.Header.Get(h)
		if v == "" {
			t.Fatalf("Global chat request must carry %s, got %v", h, req.Header)
		}
		if !conversationUUIDShape.MatchString(v) {
			t.Fatalf("%s must be a UUID-shaped id, got %q", h, v)
		}
	}

	// Per-request ids: reusing one across unrelated calls would merge
	// unrelated turns upstream; the gateway only validates presence/shape.
	req2 := &http.Request{Header: http.Header{}}
	backendHeaders(req2, global)
	if req2.Header.Get("X-Conversation-ID") == req.Header.Get("X-Conversation-ID") {
		t.Fatal("conversation ids must differ per request")
	}

	// CN realm keeps its pre-fix headers exactly as they were.
	cn := &storedAuth{Auth: storedTokens{AccessToken: "at", Domain: "copilot.tencent.com"}}
	req3 := &http.Request{Header: http.Header{}}
	backendHeaders(req3, cn)
	if got := req3.Header.Get("X-Conversation-ID"); got != "" {
		t.Fatalf("CN realm must not gain Global-only conversation headers, got %q", got)
	}

	// An explicit caller-supplied id survives: task_chat sets X-Conversation-ID
	// before calling backendHeaders on its non-desktop path.
	preset := &http.Request{Header: http.Header{}}
	preset.Header.Set("X-Conversation-ID", "caller-owned")
	backendHeaders(preset, global)
	if got := preset.Header.Get("X-Conversation-ID"); got != "caller-owned" {
		t.Fatalf("caller-supplied conversation id must survive, got %q", got)
	}
}
