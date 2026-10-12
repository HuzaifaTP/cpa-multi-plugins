//go:build live

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestLiveApi2Chat probes whether api2.qoder.sh (the CLI 1.1.68 prod
// inference base) discharges datacenter-IP chats that api3 queues.
func TestLiveApi2Chat(t *testing.T) {
	sa := liveImageAuth(t)
	req := &openAIRequest{}
	raw := []byte(`{"model":"qmodel","stream":false,"messages":[{"role":"user","content":"Reply with exactly one word: pong"}]}`)
	if err := json.Unmarshal(raw, req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	body, err := buildQoderBody(req, "qmodel", uiUserType(nil))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	encoded := qoderEncode(body)
	url := "https://api2.qoder.sh" + "/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	hreq, err := http.NewRequest(http.MethodPost, url, strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	// sign against the api2 URL (path identical, so cosy sig matches)
	if err := applyCosyHeaders(hreq, sa, encoded, url, "qmodel", true); err != nil {
		t.Fatalf("cosy: %v", err)
	}
	resp, err := liveChatClient().Do(hreq)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("api2 chat http %d content-type=%s", resp.StatusCode, resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 {
		buf := make([]byte, 400)
		n, _ := resp.Body.Read(buf)
		t.Logf("body: %s", buf[:n])
		return
	}
	t.Logf("answer: %s", readAnswer(resp.Body))
}
