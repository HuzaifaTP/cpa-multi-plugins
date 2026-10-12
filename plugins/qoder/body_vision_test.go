package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Issue #37 (onlyjco): image_url content parts were silently dropped while
// flattening content — image-only requests died with the misleading
// "no user message in request", mixed content returned 200 while the model
// answered "I don't see any image". The channel is text-only; both shapes
// now fail explicitly.

// imageOnlyMessages reproduces Repro A: a single user message carrying only
// an image_url part.
func imageOnlyMessages(t *testing.T) []openAIMessage {
	t.Helper()
	raw := `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]`
	return unmarshalMessages(t, raw)
}

// mixedMessages reproduces Repro B: text + image in the latest user turn.
func mixedMessages(t *testing.T) []openAIMessage {
	t.Helper()
	raw := `[{"role":"user","content":[{"type":"text","text":"describe this"},{"type":"image_url","image_url":{"url":"data:image/png;base64,BBBB"}}]}]`
	return unmarshalMessages(t, raw)
}

func unmarshalMessages(t *testing.T, raw string) []openAIMessage {
	t.Helper()
	var msgs []openAIMessage
	if err := json.Unmarshal([]byte(raw), &msgs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return msgs
}

func TestBuildQoderBodyRejectsImageOnly(t *testing.T) {
	// Repro A used to fail with "body build: no user message in request" —
	// the honest vision error must replace it.
	_, err := buildQoderBody(&openAIRequest{Model: "qfmodel", Messages: imageOnlyMessages(t)}, "qfmodel", "default")
	if err == nil {
		t.Fatal("image-only request must fail")
	}
	if strings.Contains(err.Error(), "no user message in request") {
		t.Fatalf("misleading legacy error must be replaced: %v", err)
	}
	for _, marker := range []string{"image_url", "text-only", "image", "qoder"} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(marker)) {
			t.Fatalf("error copy must name the %q limitation: %v", marker, err)
		}
	}
}

func TestBuildQoderBodyRejectsMixedContent(t *testing.T) {
	// Repro B: silent loss → explicit rejection.
	_, err := buildQoderBody(&openAIRequest{Model: "qfmodel", Messages: mixedMessages(t)}, "qfmodel", "default")
	if err == nil {
		t.Fatal("mixed text+image request must fail explicitly, not silently drop the image")
	}
	if !strings.Contains(err.Error(), "image_url") {
		t.Fatalf("error must name image_url: %v", err)
	}
}

func TestBuildQoderBodyPlainAndStructuredTextStillWork(t *testing.T) {
	// Plain-string content (regression).
	_, err := buildQoderBody(&openAIRequest{
		Model:    "qfmodel",
		Messages: unmarshalMessages(t, `[{"role":"system","content":"sys"},{"role":"user","content":"hello"}]`),
	}, "qfmodel", "default")
	if err != nil {
		t.Fatalf("plain text must keep working: %v", err)
	}
	// Structured content with ONLY text parts keeps working.
	_, err = buildQoderBody(&openAIRequest{
		Model:    "qfmodel",
		Messages: unmarshalMessages(t, `[{"role":"system","content":"sys"},{"role":"user","content":[{"type":"text","text":"hi there"}]}]`),
	}, "qfmodel", "default")
	if err != nil {
		t.Fatalf("text-only structured content must keep working: %v", err)
	}
}

func TestBuildQoderBodyHistoryImagesNotRetroactive(t *testing.T) {
	// An old screenshot in the HISTORY must not fail every follow-up turn —
	// the guard is scoped to the LATEST user message (history parts were
	// already forwarded-and-ignored upstream before the guard existed).
	msgs := unmarshalMessages(t, `[`+
		`{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,OLD"}}]},`+
		`{"role":"assistant","content":"cannot see images"},`+
		`{"role":"user","content":"and now just text"}`+
		`]`)
	_, err := buildQoderBody(&openAIRequest{Model: "qfmodel", Messages: msgs}, "qfmodel", "default")
	if err != nil {
		t.Fatalf("history image must not fail a text follow-up: %v", err)
	}
}

func TestLatestUserImagePartCounters(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"image only", `[{"type":"image_url","image_url":{"url":"x"}}]`, 1},
		{"two images", `[{"type":"image_url","image_url":{"url":"x"}},{"type":"image_url","image_url":{"url":"y"}}]`, 2},
		{"mixed", `[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"x"}}]`, 1},
		{"text only", `[{"type":"text","text":"a"}]`, 0},
		{"plain string", `"hello"`, 0},
		{"null", `null`, 0},
		{"not an array", `{"type":"image_url"}`, 0},
		{"unparseable", `[{"type":`, 0},
		{"other part type", `[{"type":"input_audio","input_audio":{"data":"x"}}]`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := imagePartsInContent(tc.content); got != tc.want {
				t.Fatalf("imagePartsInContent(%s) = %d, want %d", tc.content, got, tc.want)
			}
		})
	}
	// Latest-user scoping: an assistant turn with images after the user turn
	// is not the trigger.
	msgs := unmarshalMessages(t, `[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"image_url","image_url":{"url":"x"}}]}]`)
	if got := latestUserImageParts(msgs); got != 0 {
		t.Fatalf("assistant-turn images must not count: %d", got)
	}
}

func TestExtractLatestUserPromptUnchanged(t *testing.T) {
	// The vision guard must not change text extraction itself.
	msgs := mixedMessages(t)
	if got := extractLatestUserPrompt(msgs); got != "describe this" {
		t.Fatalf("prompt extraction regressed: %q", got)
	}
}
