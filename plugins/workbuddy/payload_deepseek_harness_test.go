package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The Tencent CN gateway blocklists the DeepSeek Harness opening signature as
// an "unapproved channel" and answers code 11-128. Replaying the same request
// with only this sentence swapped out returns 200, so the sanitizer has to
// rewrite it while leaving the rest of the system prompt intact.
func TestSanitizeBlockedTemplatesDeepSeekHarness(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "verbatim",
			in:   "You are an AI agent powered by DeepSeek Harness. Follow the rules.",
			want: "You are an AI assistant. Follow the rules.",
		},
		{
			name: "no trailing period",
			in:   "You are an AI agent powered by DeepSeek Harness",
			want: "You are an AI assistant",
		},
		{
			name: "case drift",
			in:   "you are an AI agent powered by deepseek harness.",
			want: "You are an AI assistant.",
		},
		{
			name: "embedded in a long prompt",
			in:   "Intro line.\nYou are an AI agent powered by DeepSeek Harness.\nTools follow.",
			want: "Intro line.\nYou are an AI assistant.\nTools follow.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeBlockedTemplates(tc.in); got != tc.want {
				t.Fatalf("sanitizeBlockedTemplates(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Near-misses must survive untouched: only the full "You are an AI agent
// powered by DeepSeek Harness" prefix is blocklisted (verified by replay —
// each of these returned 200 against the live gateway).
func TestSanitizeBlockedTemplatesKeepsNearMisses(t *testing.T) {
	untouched := []string{
		"DeepSeek Harness",
		"powered by DeepSeek Harness",
		"You are an AI agent powered by DeepSeek.",
		"You are an AI agent powered by Acme Harness.",
		"AI agent powered by DeepSeek Harness.",
	}
	for _, in := range untouched {
		if got := sanitizeBlockedTemplates(in); got != in {
			t.Fatalf("sanitizeBlockedTemplates(%q) = %q, want it untouched", in, got)
		}
	}
}

// deepSeekHarnessBody rebuilds the captured-failure shape from PR #46's
// single-variable replay at miniature scale: a CN-realm account, a system
// message opening with the DeepSeek Harness signature followed by real
// instruction bulk, a user turn that pastes the same sentence (must NOT be
// rewritten — system-role gate), and the reasoning_effort=max marker.
func deepSeekHarnessBody(t *testing.T) []byte {
	t.Helper()
	tools := make([]map[string]any, 0, 8)
	for i := 0; i < 8; i++ {
		tools = append(tools, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        "tool_" + string(rune('a'+i)),
				"description": strings.Repeat("does something useful. ", 40),
			},
		})
	}
	body := map[string]any{
		"model":            "deepseek-chat",
		"reasoning_effort": "max",
		"stream":           false,
		"tools":            tools,
		"messages": []any{
			map[string]any{
				"role": "system",
				"content": "You are an AI agent powered by DeepSeek Harness. " +
					"Follow the repository conventions and keep diffs minimal. " +
					strings.Repeat("Operate carefully. ", 120),
			},
			map[string]any{
				"role":    "user",
				"content": "Review this agent intro I found: You are an AI agent powered by DeepSeek Harness. Keep it?",
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestPrepareUpstreamBodyDeepSeekHarnessEndToEnd drives the full pipeline
// the compiled plugin runs (prepareUpstreamBody) with a CN-realm credential,
// proving the rewrite survives body preparation and lands in the outbound
// JSON while the user-role copy of the same sentence stays verbatim.
func TestPrepareUpstreamBodyDeepSeekHarnessEndToEnd(t *testing.T) {
	sa := &storedAuth{Auth: storedTokens{Domain: "copilot.tencent.com"}}
	out := prepareUpstreamBody(deepSeekHarnessBody(t), nil, sa, "")
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	msgs, _ := body["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages len = %d, want 2 (CN: no system-first injection)", len(msgs))
	}
	sys, _ := msgs[0].(map[string]any)
	sc, _ := sys["content"].(string)
	if strings.Contains(strings.ToLower(sc), "you are an ai agent powered by deepseek harness") {
		t.Fatalf("system intro must be rewritten in the outbound body, got %q", sc[:80])
	}
	if !strings.HasPrefix(sc, "You are an AI assistant. Follow the repository") {
		t.Errorf("rewrite must preserve the remainder of the system prompt, got %q", sc[:80])
	}
	user, _ := msgs[1].(map[string]any)
	uc, _ := user["content"].(string)
	if !strings.Contains(uc, "You are an AI agent powered by DeepSeek Harness.") {
		t.Errorf("user-role copy of the sentence must stay verbatim (system-only gate), got %q", uc)
	}
	// The captured failure carried reasoning_effort=max; the pipeline mirrors
	// it to reasoning_summary but must not strip the rewrite.
	if _, ok := body["reasoning_summary"]; !ok {
		t.Errorf("reasoning_effort mirror expected in outbound body")
	}
}

// TestUpstreamStatusError11128CarriesRequestScopedStatus pins the wire shape
// the v8 host decodes: a 400/11128 rejection crosses the RPC envelope with
// http_status=400 so clienterror.IsRequestFault classifies it request-scoped
// (no rotation, no credential cooldown). Status 0 (the pre-0.9.62 shape) is
// what let the host walk and cool all 8 CN accounts into a 503 cascade.
func TestUpstreamStatusError11128CarriesRequestScopedStatus(t *testing.T) {
	payload := `{"code":11128,"msg":"Illegal API invocation from an unapproved channel","requestId":"a02219ca-9976-4475-9213-7f3dc5b21d5b"}`
	inner := translateChatUpstreamErrorFull(http.StatusBadRequest, payload, nil, nil)
	wrapped := upstreamStatusError(http.StatusBadRequest, payload, inner)
	var se *statusError
	if !errors.As(wrapped, &se) {
		t.Fatalf("11128 must wrap statusError, got %T", wrapped)
	}
	if se.StatusCode() != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", se.StatusCode())
	}
	raw := errorEnvelopeFor(wrapped)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.OK || env.Error == nil {
		t.Fatalf("expected error envelope, got ok=%v", env.OK)
	}
	if env.Error.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("envelope http_status = %d, want 400 (v8 IsRequestFault keying)", env.Error.HTTPStatus)
	}
	if !strings.Contains(env.Error.Message, "11128") {
		t.Fatalf("bilingual guidance must survive the envelope, got %q", env.Error.Message)
	}
}
