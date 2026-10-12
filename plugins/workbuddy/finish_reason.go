// finish_reason.go — terminal-chunk finish_reason correction (issue #36).
//
// The intl/IDE upstream (codebuddy.ai) emits Anthropic-style stop semantics
// through its OpenAI-compat conversion: its internal end_turn maps to
// finish_reason:"stop" even when the same response carried tool_calls deltas.
// Per the OpenAI chat-completions contract a message with non-empty
// tool_calls must finish with "tool_calls" — every tool-calling agent loop
// (LangChain / AutoGen / OpenAI Agents SDK …) branches on exactly this
// contradiction and breaks: the client never executes the tools the model
// just asked for, or errors out on the inconsistent pair.
//
// The fix is deliberately narrow:
//   - Only "stop" is rewritten (the end_turn-mapping artifact). Informative
//     finish reasons — "length" (truncated mid-arguments),
//     "content_filter", an already-correct "tool_calls" — pass through
//     verbatim.
//   - A choice is only rewritten when that SAME choice index accumulated a
//     non-empty tool_calls delta earlier in the stream (or carries one in
//     the terminal chunk itself — upstream can co-locate the last fragment
//     and the finish marker in one frame).
//   - Non-JSON / non-choice payloads return unchanged; empty tool_calls
//     arrays do not count (cleanChunkJSON already deleted those shells).
//
// All three executor paths apply it: the async pump (pumpStreamFrames), the
// synchronous collector (aggregateSSEWithCollector), and the non-stream fold
// (aggregateCompletion assembles the folded finish_reason directly).
package main

import (
	"encoding/json"
	"strings"
)

// fixFinishReasonToolCalls rewrites the terminal finish_reason of one cleaned
// chunk per the policy above. toolSeen tracks, per choice index, whether a
// non-empty tool_calls delta has been observed in this stream so far; the map
// is mutated in place so callers keep one instance across the whole stream.
// Returns the (possibly re-marshaled) chunk string; unchanged input is
// returned byte-for-byte.
func fixFinishReasonToolCalls(s string, toolSeen map[int]bool) string {
	if s == "" || toolSeen == nil {
		return s
	}
	var obj map[string]any
	if json.Unmarshal([]byte(s), &obj) != nil {
		return s
	}
	choices, ok := obj["choices"].([]any)
	if !ok {
		return s
	}
	changed := false
	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		idx := choiceIndex(choice)
		if delta, ok := choice["delta"].(map[string]any); ok {
			if tcs, ok := delta["tool_calls"].([]any); ok && len(tcs) > 0 {
				toolSeen[idx] = true
			}
		}
		if fr, _ := choice["finish_reason"].(string); fr == "stop" && toolSeen[idx] {
			choice["finish_reason"] = "tool_calls"
			changed = true
		}
	}
	if !changed {
		return s
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return s
	}
	return string(out)
}

// choiceIndex extracts a choice's index member, defaulting to 0 (the
// single-choice contract every upstream realm here honors; a missing index
// and index 0 must share one toolSeen slot).
func choiceIndex(choice map[string]any) int {
	if v, ok := choice["index"].(float64); ok {
		return int(v)
	}
	return 0
}

// foldedFinishReason decides the finish_reason for the non-stream fold.
// callsKept is the post-dropTruncatedToolCalls call list: when the message
// carries tool_calls, "stop" (and an absent finish marker) must become
// "tool_calls"; "length"/"content_filter"/"tool_calls" keep their meaning.
func foldedFinishReason(upstreamFinish string, callsKept int) string {
	if callsKept > 0 && (upstreamFinish == "" || upstreamFinish == "stop") {
		return "tool_calls"
	}
	if strings.TrimSpace(upstreamFinish) == "" {
		return "stop"
	}
	return upstreamFinish
}
