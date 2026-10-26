package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// issue #63 pin: compactToolDescriptions must cover all THREE tool shapes —
// the chat-completions nesting (tool.function.description), the Responses-API
// flat shape (description at the tool's own top level), and MCP namespace
// tools (functions nested under tool["tools"]). The old implementation only
// understood the first, so a Codex Desktop /v1/responses session carrying the
// mcp__rea extension (170 functions, 322KB serialized) sailed through
// UNCOMPRESSED and kimi-k3.1-pro answered upstream 400 code=11133 /
// extError 400001 on every request.

// bigDesc builds a description string that pushes a tool well past the
// 64KB toolDescriptionByteLimit on its own.
func bigDesc(prefix string) string {
	return prefix + strings.Repeat("x", 80*1024)
}

// overLimitTools serializes the tools array and reports whether it exceeds
// toolDescriptionByteLimit (the compactor's trigger).
func overLimitTools(t *testing.T, obj map[string]any) bool {
	t.Helper()
	raw, err := json.Marshal(obj["tools"])
	if err != nil {
		t.Fatal(err)
	}
	return len(raw) >= toolDescriptionByteLimit
}

func TestCompactToolDescriptionsResponsesFlatShape(t *testing.T) {
	// Responses API flat function tool: {"type":"function","name":...,
	// "description":...,"parameters":{...}} — no tool["function"] wrapper.
	obj := map[string]any{
		"tools": []any{
			map[string]any{
				"type":        "function",
				"name":        "exec_command",
				"description": bigDesc("run a shell command: "),
				"parameters":  map[string]any{"type": "object"},
			},
		},
	}
	if !overLimitTools(t, obj) {
		t.Fatal("test fixture must exceed the 64KB limit")
	}
	if !compactToolDescriptions(obj) {
		t.Fatal("flat-shape description over the limit must be stripped")
	}
	tool := obj["tools"].([]any)[0].(map[string]any)
	if _, has := tool["description"]; has {
		t.Fatal("flat-shape description survived compaction")
	}
	// The function's identity must survive — only the description goes.
	if tool["name"] != "exec_command" || tool["type"] != "function" {
		t.Fatalf("flat tool identity mangled: %v", tool)
	}
}

func TestCompactToolDescriptionsMCPNamespaceRecursion(t *testing.T) {
	// MCP namespace tool: the 170 functions live under tool["tools"], each a
	// flat function object — this is where mcp__rea's 322KB actually sits.
	ns := map[string]any{
		"type":        "namespace",
		"name":        "mcp__rea",
		"description": "reverse-engineering MCP extension",
		"tools": []any{
			map[string]any{"type": "function", "name": "rea_disasm", "description": bigDesc("disassemble: "), "parameters": map[string]any{"type": "object"}},
			map[string]any{"type": "function", "name": "rea_decompile", "description": bigDesc("decompile: "), "parameters": map[string]any{"type": "object"}},
			// A nested-inside-nested namespace (hub-style grouping) must
			// recurse too.
			map[string]any{
				"type":        "namespace",
				"name":        "mcp__rea_deep",
				"description": "sub namespace",
				"tools": []any{
					map[string]any{"type": "function", "name": "rea_xrefs", "description": bigDesc("xrefs: "), "parameters": map[string]any{"type": "object"}},
				},
			},
		},
	}
	obj := map[string]any{"tools": []any{ns}}
	if !overLimitTools(t, obj) {
		t.Fatal("test fixture must exceed the 64KB limit")
	}
	if !compactToolDescriptions(obj) {
		t.Fatal("namespace payload over the limit must be compacted")
	}
	if _, has := ns["description"]; has {
		t.Fatal("namespace-level description survived")
	}
	subs := ns["tools"].([]any)
	for i, want := range []string{"rea_disasm", "rea_decompile", "mcp__rea_deep"} {
		sub := subs[i].(map[string]any)
		if sub["name"] != want {
			t.Fatalf("sub tool %d: name mangled (%v)", i, sub["name"])
		}
		if _, has := sub["description"]; has && sub["type"] == "function" {
			t.Fatalf("sub tool %s: description survived", want)
		}
	}
	deep := subs[2].(map[string]any)
	deepFn := deep["tools"].([]any)[0].(map[string]any)
	if _, has := deepFn["description"]; has {
		t.Fatal("nested namespace function description survived recursion")
	}
	if deepFn["name"] != "rea_xrefs" {
		t.Fatalf("nested function identity mangled: %v", deepFn["name"])
	}
}

func TestCompactToolDescriptionsChatCompletionsNestingStillWorks(t *testing.T) {
	// Regression guard: the classic shape keeps working exactly as before.
	obj := map[string]any{
		"tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        "get_weather",
					"description": bigDesc("weather lookup: "),
					"parameters":  map[string]any{"type": "object"},
				},
			},
		},
	}
	if !overLimitTools(t, obj) {
		t.Fatal("test fixture must exceed the 64KB limit")
	}
	if !compactToolDescriptions(obj) {
		t.Fatal("nested-shape description over the limit must be stripped")
	}
	fn := obj["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)
	if _, has := fn["description"]; has {
		t.Fatal("nested description survived compaction")
	}
	if fn["name"] != "get_weather" {
		t.Fatal("nested function identity mangled")
	}
}

func TestCompactToolDescriptionsUnderLimitIsNoOp(t *testing.T) {
	// All three shapes, small payload: byte-for-byte untouched (the opt-in
	// threshold must not strip anything below 64KB).
	obj := map[string]any{
		"tools": []any{
			map[string]any{"type": "function", "function": map[string]any{"name": "a", "description": "small"}},
			map[string]any{"type": "function", "name": "b", "description": "small flat"},
			map[string]any{"type": "namespace", "name": "ns", "description": "small ns", "tools": []any{
				map[string]any{"type": "function", "name": "c", "description": "small nested"},
			}},
		},
	}
	before, _ := json.Marshal(obj["tools"])
	if compactToolDescriptions(obj) {
		t.Fatal("under-limit payload must not be touched")
	}
	after, _ := json.Marshal(obj["tools"])
	if string(before) != string(after) {
		t.Fatal("under-limit payload changed")
	}
}

func TestCompactToolDescriptionsIssue63FieldScale(t *testing.T) {
	// End-to-end at the issue's reported scale: one mcp__rea-style namespace
	// with 170 flat functions (description ~1.9KB each ≈ 322KB total) plus a
	// couple of ordinary tools. Before v0.9.72 the compactor returned false
	// on exactly this payload (every tool hit the `continue`).
	fns := make([]any, 0, 170)
	for i := 0; i < 170; i++ {
		fns = append(fns, map[string]any{
			"type":        "function",
			"name":        "rea_tool_" + itoa(i),
			"description": strings.Repeat("d", 1900),
			"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
		})
	}
	obj := map[string]any{
		"model": "kimi-k3.1-pro",
		"tools": []any{
			map[string]any{"type": "function", "name": "exec_command", "description": "run a command", "parameters": map[string]any{"type": "object"}},
			map[string]any{"type": "namespace", "name": "mcp__rea", "description": "RE extension", "tools": fns},
		},
		"messages": []any{map[string]any{"role": "user", "content": "hello"}},
	}
	before, _ := json.Marshal(obj["tools"])
	if len(before) < 322_000 {
		t.Fatalf("field-scale fixture too small: %d bytes", len(before))
	}
	if !compactToolDescriptions(obj) {
		t.Fatal("the exact #63 payload shape must now be compacted")
	}
	after, _ := json.Marshal(obj["tools"])
	if len(after) >= toolDescriptionByteLimit {
		t.Fatalf("post-compaction payload still over the limit: %d bytes", len(after))
	}
}

// itoa avoids importing strconv for one loop counter.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}
