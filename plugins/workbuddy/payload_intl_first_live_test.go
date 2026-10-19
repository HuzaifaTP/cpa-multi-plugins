//go:build live

// payload_intl_first_live_test.go — PR #42 / issue #40 verification probe.
//
// Claim under test (2026-10-18/19, PR author + issue #40 reporter):
// the INTL upstream (www.codebuddy.ai) enforces the same messages[0]
// position check as Global — a user-first payload is rejected with code
// 11128, while the plugin's ensureSystemMessageInPlace gate skips INTL
// credentials entirely, so user-first client requests reach upstream raw.
//
//	REFRESH      — rotate the access token via the plugin's own refreshCall
//	               (Keycloak rotates the refresh token; WB_CRED_FILE is
//	               rewritten with the new pair so the credential survives).
//	CONTROL-RAW  — user-first payload exactly as an OpenAI-style client
//	               sends it. Expect: 11128 reject (the bug).
//	CONTROL-PREP — prepareUpstreamBody on CURRENT main with an intl sa:
//	               documents that no system message is injected (the gap).
//	FIX-SIM      — the same payload with a system message prepended (what
//	               the patched gate produces). Expect: 200.
//
// Run:
//
//	WB_CRED_FILE=/path/to/cred.json go test -tags live -run TestLiveIntlSystemFirstGate -v ./plugins/workbuddy
//
// Skipped unless -tags live AND WB_CRED_FILE are set, so CI stays hermetic.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type wbCredFile struct {
	Account struct {
		UID          string `json:"uid"`
		Nickname     string `json:"nickname"`
		EnterpriseID string `json:"enterpriseId"`
	} `json:"account"`
	Auth struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		Domain       string `json:"domain"`
		ExpiresAt    int64  `json:"expiresAt"`
		Region       string `json:"region"`
	} `json:"auth"`
}

func intlGatePost(t *testing.T, sa *storedAuth, raw []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpointChatFor(sa), bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	backendHeaders(req, sa)
	stream, status, _, err := hostHTTPDoStream(req)
	if err != nil {
		t.Fatalf("stream post: %v", err)
	}
	defer stream.Close()
	reader := newHostStreamReader(stream)
	payload, _ := io.ReadAll(io.LimitReader(reader, 1<<20))
	return status, string(payload)
}

func TestLiveIntlSystemFirstGate(t *testing.T) {
	credPath := os.Getenv("WB_CRED_FILE")
	if credPath == "" {
		t.Skip("WB_CRED_FILE not set — live intl system-first gate verification skipped")
	}
	credRaw, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("read cred: %v", err)
	}
	var cred wbCredFile
	if err := json.Unmarshal(credRaw, &cred); err != nil {
		t.Fatalf("parse cred: %v", err)
	}
	sa := &storedAuth{
		Auth: storedTokens{
			AccessToken:   cred.Auth.AccessToken,
			RefreshToken:  cred.Auth.RefreshToken,
			Domain:        cred.Auth.Domain,
			Region:        cred.Auth.Region,
			LoginPlatform: "ide",
		},
		Account: storedAccount{UID: cred.Account.UID, EnterpriseID: cred.Account.EnterpriseID, Nickname: cred.Account.Nickname},
	}

	// Pre-flight: is the stored access token still live?
	probeRaw, _ := json.Marshal(map[string]any{
		"model": "deepseek-v4.1-flash",
		"messages": []map[string]any{
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Reply with exactly: OK"},
		},
		"agent": "cli", "temperature": 1, "stream": true,
	})
	status0, _ := intlGatePost(t, sa, probeRaw)
	if status0 == 401 {
		t.Logf("REFRESH: stored access token rejected (401) — rotating via refreshCall")
		data, _, rstatus, rerr := refreshCall(sa)
		if rerr != nil {
			t.Fatalf("REFRESH failed (http %d): %v", rstatus, rerr)
		}
		var tok tokenData
		if err := json.Unmarshal(data, &tok); err != nil || tok.AccessToken == "" {
			t.Fatalf("REFRESH: no accessToken in response — re-login required")
		}
		sa.Auth.AccessToken = tok.AccessToken
		if tok.RefreshToken != "" {
			sa.Auth.RefreshToken = tok.RefreshToken
		}
		if tok.Domain != "" {
			sa.Auth.Domain = tok.Domain
		}
		// Persist the rotated pair BEFORE any probe can fail the test.
		cred.Auth.AccessToken = sa.Auth.AccessToken
		cred.Auth.RefreshToken = sa.Auth.RefreshToken
		cred.Auth.Domain = sa.Auth.Domain
		if tok.ExpiresIn > 0 {
			cred.Auth.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
		}
		out, _ := json.MarshalIndent(cred, "", "  ")
		if err := os.WriteFile(credPath, append(out, '\n'), 0o600); err != nil {
			t.Fatalf("persist rotated credential: %v", err)
		}
		t.Logf("REFRESH: rotated credential persisted to %s", credPath)
	} else {
		t.Logf("REFRESH: stored access token still live (pre-flight HTTP %d)", status0)
	}

	newUserFirst := func() map[string]any {
		return map[string]any{
			"model": "deepseek-v4.1-flash",
			"messages": []map[string]any{
				{"role": "user", "content": "Reply with exactly: OK"},
			},
			"agent":       "cli",
			"temperature": 1,
			"stream":      true,
		}
	}

	// CONTROL-PREP — current main: prepareUpstreamBody leaves the intl
	// user-first payload user-first (the gap PR #42 closes). On a patched
	// tree this flips to "system" — that flip IS the fix.
	raw, _ := json.Marshal(newUserFirst())
	prepped := prepareUpstreamBody(raw, raw, sa, "")
	var preppedObj map[string]any
	if err := json.Unmarshal(prepped, &preppedObj); err != nil {
		t.Fatalf("unmarshal prepped: %v", err)
	}
	msgs, _ := preppedObj["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatalf("prepped payload has no messages")
	}
	firstRole, _ := msgs[0].(map[string]any)["role"].(string)
	t.Logf("CONTROL-PREP: prepareUpstreamBody first role on current tree = %q (messages=%d)", firstRole, len(msgs))

	// CONTROL-RAW — user-first straight to the intl upstream.
	status, body := intlGatePost(t, sa, raw)
	t.Logf("CONTROL-RAW: HTTP %d body[0:300]=%s", status, clip(body, 300))

	// FIX-SIM — the payload shape the patched gate produces (system first).
	fixed := newUserFirst()
	fixed["messages"] = []map[string]any{
		{"role": "system", "content": "You are a helpful assistant."},
		{"role": "user", "content": "Reply with exactly: OK"},
	}
	fixedRaw, _ := json.Marshal(fixed)
	status2, body2 := intlGatePost(t, sa, fixedRaw)
	t.Logf("FIX-SIM: HTTP %d body[0:200]=%s", status2, clip(body2, 200))
	if status2 != 200 {
		t.Fatalf("FIX-SIM: system-first payload rejected too — the CONTROL-RAW failure is NOT position-shaped (root cause claim overturned): %s", clip(body2, 400))
	}
	switch {
	case status == 200:
		t.Logf("VERDICT: gateway accepts user-first too — PR #42 premise does NOT reproduce on this credential (evidence, not failure)")
	case strings.Contains(body, "11128"):
		t.Logf("VERDICT: user-first → 11128, system-first → 200 — PR #42 root cause VERIFIED LIVE")
	default:
		t.Logf("VERDICT: user-first → HTTP %d non-11128 (%s) — different failure family, inspect before merging", status, clip(body, 200))
	}
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
