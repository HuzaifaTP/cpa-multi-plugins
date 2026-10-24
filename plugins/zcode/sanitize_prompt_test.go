package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestScrubBlockedPhrases covers the phrase table itself: each pinned trigger
// must be rewritten, and the tolerant regexes must catch case/punctuation
// drift from client releases.
func TestScrubBlockedPhrases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "claude code cli exact",
			in:   "You are Claude Code, Anthropic's official CLI for Claude.",
			want: "You are Claude Code, Anthropic's official CLI tool for Claude.",
		},
		{
			name: "claude code cli drift",
			in:   "you are claude code, anthropic official cli for claude",
			want: "you are claude code, Anthropic's official CLI tool for Claude",
		},
		{
			name: "main branch pr hint",
			in:   "- Main branch (you will usually use this for PRs): main",
			want: "- Default branch (you will usually use this for PRs): main",
		},
		{
			name: "codex cli intro",
			in:   "You are a coding agent running in the Codex CLI, a terminal-based coding assistant. Codex CLI is an open source project led by OpenAI.",
			want: "You are a helpful coding assistant running in the terminal.",
		},
		{
			name: "harness intro",
			in:   "You are an AI agent powered by DeepSeek Harness. Think rigorously.",
			want: "You are an AI assistant. Think rigorously.",
		},
		{
			name: "harness web gui four token phrase",
			in:   "- Local web GUI: http://127.0.0.1:2391 (DeepSeek Harness Web GUI)",
			want: "- Local web GUI: http://127.0.0.1:2391 (DeepSeek Harness web interface)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scrubBlockedPhrases(c.in)
			if got != c.want {
				t.Fatalf("scrubBlockedPhrases(%q)\n got: %q\nwant: %q", c.in, got, c.want)
			}
		})
	}
}

// TestScrubPromptPayloadCoversEveryRole pins the scope rule: the sibling gate
// reads the whole body, so a system-only pass is not enough — assistant
// history echoes and tool_call arguments must be scrubbed too.
func TestScrubPromptPayloadCoversEveryRole(t *testing.T) {
	payload := []byte(`{
	  "model": "zcode-glm-5.3-flash",
	  "system": "You are Claude Code, Anthropic's official CLI for Claude.",
	  "messages": [
	    {"role": "user", "content": "keep me identical"},
	    {"role": "assistant", "content": "- Main branch (you will usually use this for PRs)"},
	    {"role": "assistant", "content": [{"type": "text", "text": "You are an AI agent powered by DeepSeek Harness."}]},
	    {"role": "assistant", "content": null, "tool_calls": [
	      {"id": "c1", "type": "function", "function": {"name": "read", "arguments": "{\"path\":\".dsh\",\"note\":\"DeepSeek Harness Web GUI\"}"}}
	    ]}
	  ],
	  "max_tokens": 64
	}`)

	out := scrubPromptPayload(payload)
	if strings.Contains(string(out), "official CLI for Claude") {
		t.Fatalf("system phrase survived scrub: %s", out)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("scrubbed payload is not valid JSON: %v", err)
	}
	if got := obj["system"].(string); !strings.Contains(got, "official CLI tool for Claude") {
		t.Fatalf("system not rewritten: %q", got)
	}
	if got := obj["model"].(string); got != "zcode-glm-5.3-flash" {
		t.Fatalf("model field changed: %q", got)
	}
	msgs := obj["messages"].([]any)
	if got := msgs[0].(map[string]any)["content"].(string); got != "keep me identical" {
		t.Fatalf("clean user content changed: %q", got)
	}
	if got := msgs[1].(map[string]any)["content"].(string); strings.Contains(got, "Main branch") {
		t.Fatalf("assistant string content not scrubbed: %q", got)
	}
	part := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if strings.Contains(part, "DeepSeek Harness") {
		t.Fatalf("assistant part text not scrubbed: %q", part)
	}
	args := msgs[3].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"].(string)
	if strings.Contains(args, "Web GUI") {
		t.Fatalf("tool_calls arguments not scrubbed: %q", args)
	}
}

// TestScrubPromptPayloadNoOp: a body with no trigger phrase must pass through
// byte-identical, so the scrub can sit on the hot path.
func TestScrubPromptPayloadNoOp(t *testing.T) {
	payload := []byte(`{"model":"glm-5.3","messages":[{"role":"user","content":"hello there"}],"stream":true}`)
	if got := scrubPromptPayload(payload); string(got) != string(payload) {
		t.Fatalf("payload was rewritten without a trigger phrase:\n got: %s\nwant: %s", got, payload)
	}
}
