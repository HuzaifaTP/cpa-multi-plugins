//go:build live

// qoder_live_image_test.go — issue #37 decisive experiment: which request
// shape makes the Qoder gateway actually SEE an image?
//
// Dialects (all through the production transport: qoderEncode +
// applyCosyHeaders + endpointChatFor, model qfmodel = is_vl + free):
//
//	A  plugin-current   — messages carry content:[text,image_url] blocks
//	                     (verbatim passthrough), chat_context.text.text = text
//	                     only. Expected: model says it sees no image (repro B).
//	B  official-fields  — A + top-level image_urls + chat_context.imageUrls
//	                     filled with the data URI (official template fields).
//	C  no-chat-context  — magpie style: drop chat_context entirely, the last
//	                     user message's content blocks ARE the turn.
//	D  contents-field   — official template shape: content:"" +
//	                     contents:[{type:text},{type:image_url}].
//	E  image-only       — content:[{image_url}] only, no text part at all
//	                     (repro A: hard 500 in the plugin body builder today;
//	                     upstream verdict unknown).
//
//	Assertions are informational: the probe LOGS what the model answers so the
//	fix targets the dialect that actually works. Only transport errors fail.
//
//	QD_TOKEN=dt-... QD_REGION=intl QD_UID=... go test -tags live -run TestLiveImageDialects -v ./plugins/qoder
package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const imagePrompt = "Look at the image in this message. What single color fills it? Answer with just the color word."

func liveImageAuth(t *testing.T) *storedAuth {
	t.Helper()
	sa := liveSA(t)
	if sa.Account.UID == "" {
		t.Skip("QD_UID not set — Cosy identity requires the account uid")
	}
	return sa
}

// buildBase loads the embedded template exactly like buildQoderBody, so the
// probe bodies differ from production ONLY in the fields under test.
func buildBase(t *testing.T, prompt string) map[string]any {
	t.Helper()
	var base map[string]any
	if err := json.Unmarshal(basepromptJSON, &base); err != nil {
		t.Fatalf("baseprompt decode: %v", err)
	}
	if mc, ok := base["model_config"].(map[string]any); ok {
		mc["key"] = "qfmodel"
		mc["is_reasoning"] = true
		mc["source"] = "system"
	}
	if cc, ok := base["chat_context"].(map[string]any); ok {
		if txt, ok := cc["text"].(map[string]any); ok {
			txt["text"] = prompt
		}
		if extra, ok := cc["extra"].(map[string]any); ok {
			if oc, ok := extra["originalContent"].(map[string]any); ok {
				oc["text"] = prompt
			}
			if mc, ok := extra["modelConfig"].(map[string]any); ok {
				mc["key"] = "qfmodel"
				mc["is_reasoning"] = true
			}
		}
	}
	// slim: strip template system + tools, keep the structure production uses
	delete(base, "tools")
	var outMsgs []any
	if msgs, ok := base["messages"].([]any); ok {
		for _, m := range msgs {
			if mm, ok := m.(map[string]any); ok {
				if role, _ := mm["role"].(string); role == "system" {
					outMsgs = append(outMsgs, m)
				}
			}
		}
	}
	base["messages"] = outMsgs
	base["business"].(map[string]any)["id"] = "probe-image"
	return base
}

// redPNG64 is a 64x64 solid-red PNG as a data URI (self-contained so the
// live probes run on any host).
const redPNG64 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAX0lEQVR4nO3PQQ0AIBDAMMC/50MEj4ZkVbDtWX87OuBVA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA1oDWgNaA9oFUoUBf3Xr7AgAAAAASUVORK5CYII="

func imageDataURI(t *testing.T) string {
	t.Helper()
	return redPNG64
}

// postDialect sends one dialect body through the production transport and
// returns (status, assistant answer text or raw head).
func postDialect(t *testing.T, sa *storedAuth, body map[string]any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	encoded := qoderEncode(raw)
	req, err := http.NewRequest(http.MethodPost, endpointChatFor(sa), strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("request build: %v", err)
	}
	if err := applyCosyHeaders(req, sa, encoded, endpointChatFor(sa), "qfmodel", true); err != nil {
		t.Fatalf("cosy headers: %v", err)
	}
	client := liveChatClient()
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("transport: %v (after %s)", err, time.Since(start).Truncate(time.Millisecond))
	}
	defer resp.Body.Close()
	t.Logf("[image] http %d after %s", resp.StatusCode, time.Since(start).Truncate(time.Millisecond))
	if resp.StatusCode >= 400 {
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		return resp.StatusCode, string(buf[:n])
	}
	// Aggregate the SSE answer text (decode qoderEncoding frames).
	return resp.StatusCode, readAnswer(resp.Body)
}

// readAnswer decodes the plugin's SSE dialect (nested envelope, see
// aggregateQoderSSE) and concatenates content deltas.
func readAnswer(rc interface{ Read([]byte) (int, error) }) string {
	var content strings.Builder
	br := bufio.NewReaderSize(rc, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			s := strings.TrimSpace(string(line))
			if strings.HasPrefix(s, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(s, "data:"))
				// The gateway wraps each chunk: {"headers":..,"body":"<json>",..}.
				bodyStr, _, frameErr := qoderUnwrapFrame(s)
				if frameErr != nil {
					content.WriteString(" [ERRFRAME:" + truncateRedacted(s, 160) + "]")
				} else if bodyStr != "" && bodyStr != "[DONE]" {
					payload = bodyStr
					var frame struct {
						Choices []struct {
							Delta struct {
								Content string `json:"content"`
							} `json:"delta"`
							Message struct {
								Content string `json:"content"`
							} `json:"message"`
						} `json:"choices"`
					}
					if json.Unmarshal([]byte(payload), &frame) == nil {
						for _, ch := range frame.Choices {
							content.WriteString(ch.Delta.Content)
							content.WriteString(ch.Message.Content)
						}
					}
				}
			}
		}
		if err != nil {
			break
		}
		if content.Len() > 4000 {
			break
		}
	}
	out := strings.TrimSpace(content.String())
	if len(out) > 600 {
		out = out[:600]
	}
	return out
}

// liveImageModel selects the probe model (default qfmodel = free).
func liveImageModel() string {
	if m := strings.TrimSpace(os.Getenv("QD_IMAGE_MODEL")); m != "" {
		return m
	}
	return "qfmodel"
}

// liveImageDialects returns the dialect filter (comma-separated letters,
// e.g. "A,B"); empty = all.
func liveImageDialects() map[string]bool {
	out := map[string]bool{}
	for _, d := range strings.Split(strings.TrimSpace(os.Getenv("QD_IMAGE_DIALECTS")), ",") {
		if d = strings.TrimSpace(d); d != "" {
			out[d] = true
		}
	}
	return out
}

func TestLiveImageDialects(t *testing.T) {
	sa := liveImageAuth(t)
	uri := imageDataURI(t)
	prompt := imagePrompt
	filter := liveImageDialects()

	textBlock := map[string]any{"type": "text", "text": prompt}
	imageBlock := map[string]any{"type": "image_url", "image_url": map[string]any{"url": uri}}
	want := func(d string) bool { return len(filter) == 0 || filter[d] }

	// ---------- A: plugin-current ----------
	if want("A") {
		a := buildBase(t, prompt)
		a["messages"] = append(a["messages"].([]any),
			map[string]any{"role": "user", "content": []any{textBlock, imageBlock}})
		st, answer := postDialect(t, sa, a)
		t.Logf("[A plugin-current] http=%d answer=%q", st, answer)
	}

	// ---------- B: official image_urls fields ----------
	if want("B") {
		b := buildBase(t, prompt)
		b["messages"] = append(b["messages"].([]any),
			map[string]any{"role": "user", "content": []any{textBlock, imageBlock}})
		b["image_urls"] = []string{uri}
		if cc, ok := b["chat_context"].(map[string]any); ok {
			cc["imageUrls"] = []string{uri}
		}
		st, answer := postDialect(t, sa, b)
		t.Logf("[B official-fields] http=%d answer=%q", st, answer)
	}

	// ---------- C: no chat_context (magpie style) ----------
	if want("C") {
		c := buildBase(t, prompt)
		delete(c, "chat_context")
		delete(c, "image_urls")
		c["messages"] = append(c["messages"].([]any),
			map[string]any{"role": "user", "content": []any{textBlock, imageBlock}})
		st, answer := postDialect(t, sa, c)
		t.Logf("[C no-chat-context] http=%d answer=%q", st, answer)
	}

	// ---------- D: contents field (official template) ----------
	if want("D") {
		d := buildBase(t, prompt)
		d["messages"] = append(d["messages"].([]any),
			map[string]any{"role": "user", "content": "", "contents": []any{textBlock, imageBlock}})
		st, answer := postDialect(t, sa, d)
		t.Logf("[D contents-field] http=%d answer=%q", st, answer)
	}

	// ---------- E: image-only, official fields ----------
	if want("E") {
		e := buildBase(t, "")
		if cc, ok := e["chat_context"].(map[string]any); ok {
			if txt, ok := cc["text"].(map[string]any); ok {
				txt["text"] = ""
			}
			if extra, ok := cc["extra"].(map[string]any); ok {
				if oc, ok := extra["originalContent"].(map[string]any); ok {
					oc["text"] = ""
				}
			}
			cc["imageUrls"] = []string{uri}
		}
		e["image_urls"] = []string{uri}
		e["messages"] = append(e["messages"].([]any),
			map[string]any{"role": "user", "content": "", "contents": []any{imageBlock}})
		st, answer := postDialect(t, sa, e)
		t.Logf("[E image-only-official] http=%d answer=%q", st, answer)
	}
}
