package upstream

import (
	"encoding/json"
	"testing"
)

// Locks the metadata contract: Trae publishes display_name, multimodal,
// context_window_tokens and a double-encoded features string; the parser must
// surface all of them instead of flattening to bare names.
func TestParseModelListCarriesMetadata(t *testing.T) {
	raw := json.RawMessage(`{"list":[{"function":"solo_coder","models":[
		{"name":"gpt-5.4","display_name":"GPT-5.4","multimodal":true,"is_default":true,"is_beta":true,
		 "features":"{\"multimodal\":{\"enable\":true},\"reasoning\":{\"enable\":true}}",
		 "context_window_tokens":{"dev":272000,"max":272000}},
		{"name":"minimax-m2.7","display_name":"MiniMax-M2.7","multimodal":false,
		 "features":"{\"reasoning\":{\"enable\":true}}",
		 "context_window_tokens":{"dev":200000,"max":200000}},
		{"name":"gemini-3.1-pro","display_name":"Gemini-3.1-Pro-Preview","multimodal":true,
		 "features":"{}","context_window_tokens":{"dev":200000,"max":1000000}}
	]}]}`)

	ms := parseModelList(raw)
	if len(ms) != 3 {
		t.Fatalf("got %d models, want 3", len(ms))
	}
	if ms[0].DisplayName != "GPT-5.4" || !ms[0].Multimodal || !ms[0].Reasoning || !ms[0].Default || !ms[0].Beta {
		t.Fatalf("gpt-5.4 metadata wrong: %+v", ms[0])
	}
	if ms[0].ContextMax != 272000 {
		t.Fatalf("gpt-5.4 ctx = %d", ms[0].ContextMax)
	}
	if ms[1].Multimodal {
		t.Fatalf("minimax should not be multimodal")
	}
	if !ms[1].Reasoning {
		t.Fatalf("minimax should be reasoning")
	}
	if ms[2].ContextMax != 1000000 || ms[2].ContextDev != 200000 {
		t.Fatalf("gemini ctx wrong: dev=%d max=%d", ms[2].ContextDev, ms[2].ContextMax)
	}
	// Name-only legacy view must keep working for the flattening contract.
	if names := modelNamesFromData(raw); len(names) != 3 || names[0] != "gpt-5.4" {
		t.Fatalf("modelNamesFromData = %v", names)
	}
}

// Legacy array shape must still parse, with display_name defaulting to name.
func TestParseModelListLegacyShapeDefaultsDisplayName(t *testing.T) {
	ms := parseModelList(json.RawMessage(`[{"name":"gpt-5.2"}]`))
	if len(ms) != 1 || ms[0].DisplayName != "gpt-5.2" {
		t.Fatalf("legacy parse = %+v", ms)
	}
}
