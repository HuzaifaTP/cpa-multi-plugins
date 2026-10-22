package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A reasoning delta that drafted a tool call as XML must come back as prose with
// the tags gone — never as raw markup the client renders in the thinking panel.
func TestCleanChunkStripsLeakedToolXMLInReasoning(t *testing.T) {
	in := `{"choices":[{"delta":{"reasoning_content":"Let me send it.\n</parameter>\n</invoke>","role":"assistant"}}]}`
	out := cleanChunkJSON(in)
	if strings.Contains(out, "invoke") || strings.Contains(out, "parameter") {
		t.Fatalf("reasoning still carries XML tags: %s", out)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("clean output is not JSON: %v (%s)", err, out)
	}
	delta := obj["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
	got, _ := delta["reasoning_content"].(string)
	if !strings.HasPrefix(got, "Let me send it.") || strings.TrimSpace(got) != "Let me send it." {
		t.Fatalf("reasoning not preserved as prose: %q", got)
	}
}

// A content delta made of nothing but tag remnants is dropped outright, so a
// lone "</invoke>" never reaches the transcript.
func TestCleanChunkDropsTagOnlyContent(t *testing.T) {
	in := `{"choices":[{"delta":{"content":"</parameter>\n</invoke>"}}]}`
	if out := cleanChunkJSON(in); out != "" {
		t.Fatalf("tag-only content survived: %s", out)
	}
}

// Real prose that merely mentions a tag keeps its non-tag text.
func TestCleanChunkKeepsProseMentioningTags(t *testing.T) {
	in := `{"choices":[{"delta":{"content":"closing tag is </invoke> in this dialect"}}]}`
	out := cleanChunkJSON(in)
	if !strings.Contains(out, "closing tag is") {
		t.Fatalf("prose was damaged: %s", out)
	}
}

func TestChunkCarriesFinish(t *testing.T) {
	yes := `{"choices":[{"delta":{},"finish_reason":"stop"}]}`
	no := `{"choices":[{"delta":{"content":"x"},"finish_reason":null}]}`
	blank := `{"choices":[{"delta":{},"finish_reason":""}]}`
	if !chunkCarriesFinish(yes) {
		t.Fatal("finish_reason=stop not detected")
	}
	if chunkCarriesFinish(no) || chunkCarriesFinish(blank) {
		t.Fatal("empty finish_reason treated as a deliberate end")
	}
}

// The truncation error must stay in the transport-lifecycle family the cooldown
// classifier already understands (the "unexpected EOF" marker emptyStreamError
// uses): an upstream cut is not the credential's fault. The "truncated_stream:"
// prefix keeps the two distinguishable in usage rows and logs.
func TestTruncatedStreamError_TransportLifecycle(t *testing.T) {
	err := truncatedStreamError()
	msg := err.Error()
	for _, want := range []string{"truncated_stream:", "unexpected EOF"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("truncatedStreamError() = %q, missing %q", msg, want)
		}
	}
	if strings.Contains(strings.ToLower(msg), "rate limit") || strings.Contains(strings.ToLower(msg), "quota") {
		t.Fatalf("transport error must not look like a quota failure: %q", msg)
	}
}

// finish_reason=length is a deliberate upstream end and must NOT be reported as
// a truncation by this guard: the plugin keeps length (issue #36 precedent) and
// leaves the client to decide what to do with it.
func TestChunkCarriesFinish_LengthIsDeliberate(t *testing.T) {
	if !chunkCarriesFinish(`{"choices":[{"delta":{},"finish_reason":"length"}]}`) {
		t.Fatal("finish_reason=length must count as a deliberate end")
	}
	if !chunkCarriesFinish(`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`) {
		t.Fatal("finish_reason=tool_calls must count as a deliberate end")
	}
}
