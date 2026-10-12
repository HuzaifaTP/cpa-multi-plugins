// annotate_stale_token_test.go pins the v0.12.75 stale-token annotation
// (management.go refreshAccountCredits / refreshAccountCreditsIntl): a
// session_dead credits failure on an ALREADY-EXPIRED token must gain an
// actionable suffix (先点顶部「刷新」；若 refresh 报 code 20101 则凭证链已被
// 服务端轮换，需退出账号重新登录) plus a machine-readable token_expired
// marker — the panel previously showed the misleading bare
// "ent_usage: upstream session_dead" (pay 族 401 code 1001 is a downstream
// symptom of an expired access token, 2026-10-12 live 实测定案).
package main

import (
	"errors"
	"strings"
	"testing"
)

// staleSessionDead mirrors the CN UserEntUsage failure string: the *Error
// chain renders as "upstream session_dead (http 401): <body>".
func staleSessionDead() error {
	return errors.New(`upstream session_dead (http 401): {"code":1001,"message":"We are not able to authenticate you"}`)
}

func TestAnnotateStaleToken(t *testing.T) {
	// 过期 + session_dead → 在现有 error 后追加提示 + token_expired=true。
	err := staleSessionDead()
	base := "ent_usage: " + err.Error()
	entry := map[string]any{"error": base}
	annotateStaleToken(entry, err, 1000, 2000)
	got, _ := entry["error"].(string)
	if got == base {
		t.Fatalf("error not annotated: %q", got)
	}
	if !strings.HasPrefix(got, base) {
		t.Errorf("annotation must APPEND to the existing error, got %q", got)
	}
	if !strings.Contains(got, "access token 已过期") || !strings.Contains(got, "重新登录") {
		t.Errorf("annotated error lacks the stale-token guidance: %q", got)
	}
	if v, ok := entry["token_expired"].(bool); !ok || !v {
		t.Errorf("token_expired = %v, want true", entry["token_expired"])
	}

	// 未过期（now < expiresAt）→ 不动。
	freshErr := staleSessionDead()
	fresh := map[string]any{"error": "ent_usage: " + freshErr.Error()}
	annotateStaleToken(fresh, freshErr, 3000, 2000)
	if fresh["error"] != "ent_usage: "+freshErr.Error() {
		t.Errorf("unexpired token entry must stay untouched, got %v", fresh["error"])
	}
	if _, ok := fresh["token_expired"]; ok {
		t.Error("unexpired token entry must not gain token_expired")
	}

	// 边界 now == expiresAt：不算已过期（严格大于）→ 不动。
	edgeErr := staleSessionDead()
	edge := map[string]any{"error": "ent_usage: " + edgeErr.Error()}
	annotateStaleToken(edge, edgeErr, 2000, 2000)
	if edge["error"] != "ent_usage: "+edgeErr.Error() {
		t.Errorf("now == expiresAt entry must stay untouched (strict >), got %v", edge["error"])
	}

	// 过期但非 session_dead → 不动。
	otherErr := errors.New("upstream server (http 500): boom")
	other := map[string]any{"error": "ent_usage: " + otherErr.Error()}
	annotateStaleToken(other, otherErr, 1000, 2000)
	if other["error"] != "ent_usage: "+otherErr.Error() {
		t.Errorf("non-session_dead entry must stay untouched, got %v", other["error"])
	}
	if _, ok := other["token_expired"]; ok {
		t.Error("non-session_dead entry must not gain token_expired")
	}

	// session_dead 但未过期 → 不动（已由 fresh 覆盖；显式 nil err 补齐矩阵）。
	nilEntry := map[string]any{"error": "ent_usage: boom"}
	annotateStaleToken(nilEntry, nil, 1000, 2000)
	if nilEntry["error"] != "ent_usage: boom" {
		t.Errorf("nil err entry must stay untouched, got %v", nilEntry["error"])
	}
	if _, ok := nilEntry["token_expired"]; ok {
		t.Error("nil err entry must not gain token_expired")
	}
}
