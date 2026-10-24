package main

import (
	"strings"
	"testing"
	"time"
)

// TestStartPlanTransformOfficialSystemOnly pins the 3012 fix: the system field
// must carry EXACTLY the three official blocks (a fourth caller block is what
// the gateway answers with 405/biz 3012), and the caller's own text must ride
// the first user turn instead so the agent still sees its instructions.
func TestStartPlanTransformOfficialSystemOnly(t *testing.T) {
	body := map[string]any{
		"messages": []map[string]any{
			{"role": "user", "content": "ping"},
		},
		"tools": []map[string]any{
			{"name": "read", "cache_control": map[string]any{"type": "ephemeral"}},
		},
	}
	userSystem := []systemBlock{
		{Type: "text", Text: "You are an AI agent powered by DeepSeek Harness."},
		{Type: "text", Text: "  "}, // blank block must be dropped
		{Type: "text", Text: "- Main branch (you will usually use this for PRs): main"},
	}

	applyStartPlanTransform(body, userSystem, "glm-5.3", "zai", "mid-123", time.Date(2026, 10, 23, 23, 30, 0, 0, time.UTC))

	sys, ok := body["system"].([]systemBlock)
	if !ok {
		t.Fatalf("system is %T, want []systemBlock", body["system"])
	}
	if len(sys) != 3 {
		t.Fatalf("system has %d blocks, want exactly the 3 official ones", len(sys))
	}
	for i, b := range sys {
		if b.CacheControl == nil || b.CacheControl.Type != "ephemeral" {
			t.Fatalf("official block %d lost its ephemeral breakpoint", i)
		}
		if strings.Contains(b.Text, "DeepSeek Harness") || strings.Contains(b.Text, "Main branch") {
			t.Fatalf("caller text leaked into official block %d: %q", i, b.Text)
		}
	}

	msgs, ok := body["messages"].([]map[string]any)
	if !ok {
		t.Fatalf("messages is %T, want []map[string]any", body["messages"])
	}
	if len(msgs) != 2 {
		t.Fatalf("messages length = %d, want 2 (context prefix + caller turn)", len(msgs))
	}
	// The prepended context prefix must keep its official single-block shape.
	prefixBlocks, ok := msgs[0]["content"].([]map[string]any)
	if !ok || len(prefixBlocks) != 1 {
		t.Fatalf("context prefix content = %#v, want a single text block", msgs[0]["content"])
	}
	if !strings.Contains(prefixBlocks[0]["text"].(string), "system-reminder") {
		t.Fatalf("context prefix text is not the system-reminder block: %q", prefixBlocks[0]["text"])
	}
	// The caller's own system text leads the first real user turn.
	turnBlocks, ok := msgs[1]["content"].([]map[string]any)
	if !ok {
		t.Fatalf("caller turn content = %T, want a block array", msgs[1]["content"])
	}
	if len(turnBlocks) != 2 {
		t.Fatalf("caller turn has %d blocks, want injected system + original text", len(turnBlocks))
	}
	injected := turnBlocks[0]["text"].(string)
	if !strings.Contains(injected, "DeepSeek Harness") || !strings.Contains(injected, "Main branch") {
		t.Fatalf("caller system text not relocated intact: %q", injected)
	}
	if strings.Contains(injected, "\n\n\n\n") {
		t.Fatalf("blank block was not dropped: %q", injected)
	}
	if got := turnBlocks[1]["text"].(string); got != "ping" {
		t.Fatalf("original user text changed: %q", got)
	}
	// metadata + tools canonicalization still happen.
	if md, ok := body["metadata"].(map[string]any); !ok || md["user_id"] == "" {
		t.Fatalf("metadata.user_id missing: %#v", body["metadata"])
	}
	if tools, ok := body["tools"].([]map[string]any); ok && len(tools) > 0 {
		if _, has := tools[0]["cache_control"]; has {
			t.Fatalf("tools cache_control was not stripped")
		}
	}
}

// TestRelocateUserSystemNoopOnEmptySystem: no caller system means no injected
// block and no unexpected extra message.
func TestRelocateUserSystemNoopOnEmptySystem(t *testing.T) {
	body := map[string]any{
		"messages": []map[string]any{{"role": "user", "content": "ping"}},
	}
	applyStartPlanTransform(body, nil, "glm-5.3", "zai", "mid", time.Now())
	msgs := body["messages"].([]map[string]any)
	if len(msgs) != 2 {
		t.Fatalf("messages length = %d, want 2", len(msgs))
	}
	// The cache-control pass converts the last non-system message's plain
	// string content into a block array (ephemeral breakpoint on the last
	// block), so the text is asserted from the block, not the raw string.
	blocks, ok := msgs[1]["content"].([]map[string]any)
	if !ok || len(blocks) != 1 {
		t.Fatalf("user content = %#v, want one cache-marked text block", msgs[1]["content"])
	}
	if got, _ := blocks[0]["text"].(string); got != "ping" {
		t.Fatalf("user content was rewritten: %q", got)
	}
}
