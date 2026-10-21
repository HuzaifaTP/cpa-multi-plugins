package main

import (
	"net/http"
	"regexp"
	"testing"
)

var conversationUUIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TestBackendHeaders_GlobalConversationHeaders pins the conversation-header
// fill for the whole 11128 "request illegal" wave:
//
//   - Global (PR #43, 2026-10-19): "channel verification" copy — the gateway
//     rejects otherwise valid streaming chat calls as "not sent from an
//     official client" unless the three X-Conversation-* headers are present;
//   - Intl (issue #44, same day): "Request blocked. Please send it again"
//     copy — same family, same fix, verified 11128 -> 200 on a user-first
//     probe after the extension;
//   - CN (issue #45, 2026-10-20/21): domestic users report the same family;
//     the official desktop client sends the header family on every build
//     (mcplugins field docs, production CN traffic), so the fill is
//     realm-unconditional.
//
// Blank-only semantics everywhere: caller-supplied ids survive untouched.
func TestBackendHeaders_GlobalConversationHeaders(t *testing.T) {
	realms := []struct {
		name   string
		domain string
	}{
		{"Global", "www.workbuddy.ai"},
		{"Intl", "www.codebuddy.ai"},
		{"CN", "copilot.tencent.com"},
		{"CN-legacy-empty-domain", ""},
	}
	for _, realm := range realms {
		sa := &storedAuth{Auth: storedTokens{AccessToken: "at", Domain: realm.domain}}
		req := &http.Request{Header: http.Header{}}
		backendHeaders(req, sa)

		for _, h := range []string{"X-Conversation-ID", "X-Conversation-Request-ID", "X-Conversation-Message-ID"} {
			v := req.Header.Get(h)
			if v == "" {
				t.Fatalf("%s chat request must carry %s, got %v", realm.name, h, req.Header)
			}
			if !conversationUUIDShape.MatchString(v) {
				t.Fatalf("%s: %s must be a UUID-shaped id, got %q", realm.name, h, v)
			}
		}

		// Per-request ids: reusing one across unrelated calls would merge
		// unrelated turns upstream; the gateways only validate presence/shape.
		req2 := &http.Request{Header: http.Header{}}
		backendHeaders(req2, sa)
		if req2.Header.Get("X-Conversation-ID") == req.Header.Get("X-Conversation-ID") {
			t.Fatalf("%s: conversation ids must differ per request", realm.name)
		}
	}

	// An explicit caller-supplied id survives: task_chat sets X-Conversation-ID
	// before calling backendHeaders on its non-desktop path — its wb-task-*
	// shape must not be overwritten by the UUID fill, on any realm.
	for _, domain := range []string{"www.workbuddy.ai", "www.codebuddy.ai", "copilot.tencent.com", ""} {
		preset := &http.Request{Header: http.Header{}}
		preset.Header.Set("X-Conversation-ID", "caller-owned")
		backendHeaders(preset, &storedAuth{Auth: storedTokens{AccessToken: "at", Domain: domain}})
		if got := preset.Header.Get("X-Conversation-ID"); got != "caller-owned" {
			t.Fatalf("domain=%q: caller-supplied conversation id must survive, got %q", domain, got)
		}
		// The other two headers still get filled around the preserved one.
		for _, h := range []string{"X-Conversation-Request-ID", "X-Conversation-Message-ID"} {
			if preset.Header.Get(h) == "" {
				t.Fatalf("domain=%q: %s must still be filled around the caller-supplied id", domain, h)
			}
		}
	}
}
