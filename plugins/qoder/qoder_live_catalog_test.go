//go:build live

// qoder_live_catalog_test.go — issue #37 pre-work: dump the account's raw
// model catalog (key/is_vl/is_reasoning/max_input_tokens) so the image
// forwarding fix targets models that actually accept image input.
//
//	QD_TOKEN=dt-... [QD_REGION=cn|intl] go test -tags live -run TestLiveCatalogDump -v ./plugins/qoder
package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLiveCatalogDump(t *testing.T) {
	sa := liveSA(t)
	region := authRegion(sa)
	t.Logf("=== live catalog dump, region=%s ===", region)

	// callModelsAPI needs Cosy signing — reuse it directly (production path).
	models, err := callModelsAPI(sa)
	if err != nil {
		t.Fatalf("models API: %v", err)
	}
	for _, m := range models {
		t.Logf("model: id=%s name=%s ctx=%d methods=%v", m.ID, m.Name, m.ContextLength, m.SupportedGenerationMethods)
	}

	// Also dump the RAW response so is_vl / price_factor / free flags are
	// visible (pluginapi.ModelInfo drops them).
	raw := rawModelsJSON(t, sa)
	t.Logf("raw catalog (%d bytes):\n%s", len(raw), raw)
}

// rawModelsJSON re-issues the models call and keeps the raw body.
func rawModelsJSON(t *testing.T, sa *storedAuth) string {
	t.Helper()
	// callModelsAPIFn is the seam; hit the same endpoint via a direct copy of
	// its dialect: encode "{}" + Cosy headers, GET, read body.
	encoded := qoderEncode([]byte("{}"))
	rawURL := endpointModelsFor(sa)
	req, headersErr := newModelsProbeRequest(sa, encoded, rawURL)
	if headersErr != nil {
		t.Fatalf("probe request: %v", headersErr)
	}
	resp, err := sharedHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("models probe transport: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 8192)
	total := 0
	for {
		n, rerr := resp.Body.Read(tmp)
		if n > 0 {
			total += n
			if total > 512*1024 {
				break
			}
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	body := string(buf)
	if resp.StatusCode != 200 {
		t.Fatalf("models probe http %d: %s", resp.StatusCode, body[:min(300, len(body))])
	}
	// The raw body is the chat-scene list only when routed through
	// callModelsAPI; here we may have the full map — normalize for logging.
	var pretty map[string]json.RawMessage
	if json.Unmarshal(buf, &pretty) == nil {
		if chat, ok := pretty["chat"]; ok {
			var entries []map[string]any
			if json.Unmarshal(chat, &entries) == nil {
				out, _ := json.MarshalIndent(entries, "", " ")
				_ = os.WriteFile(os.TempDir()+"/qoder_catalog_chat.json", out, 0o644)
				return string(out)
			}
		}
	}
	_ = os.WriteFile(os.TempDir()+"/qoder_catalog_raw.json", buf, 0o644)
	return body
}
