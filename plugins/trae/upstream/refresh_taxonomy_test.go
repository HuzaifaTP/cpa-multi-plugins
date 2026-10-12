// refresh_taxonomy_test.go pins the v0.12.75 refresh-failure root-cause
// taxonomy (2026-10-12 live 实证, trae_live_payfamily_test.go): 20101 = 死 rt
// （同账号在别处刷新/登录后旧 refreshToken 即作废）、10101 = 服务器在
// ExchangeToken 交换层门禁 rt↔client 谱系、20403 = 服务端绑定设备与本地
// DeviceID/密钥不匹配。ExplainRefreshError maps each code to an actionable
// hint; refreshLocked's legacy path appends the hint with %w so the
// errors.As/Is chain (Kind==ErrSessionDead → pool 禁用) survives.
package upstream

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/auth"
)

// TestExplainRefreshError: 三码各自的 Msg（ResponseMetadata 大写 Code 信封
// 与顶层小写 code 两种形状）→ 非空提示，含对应 code 与「重新登录」或
// 「重绑」关键词；nil、普通网络错误、其它业务码（pay 族 1001 是 access
// token 过期的下游症状，不是刷新根因）→ ""。
func TestExplainRefreshError(t *testing.T) {
	threeCode := []struct {
		name string
		msg  string
		code string
	}{
		{"20101 nested envelope", `{"ResponseMetadata":{"Error":{"Code":"20101","Message":"refresh token is invalid"}}}`, "20101"},
		{"20101 flat code", `{"code":20101,"message":"refresh token is invalid"}`, "20101"},
		{"10101 flat code (live shape)", `{"code":10101,"message":"refresh token is not matched to the client"}`, "10101"},
		{"10101 nested envelope", `{"ResponseMetadata":{"Error":{"Code":"10101","Message":"refresh token is not matched to the client"}}}`, "10101"},
		{"20403 nested envelope", `{"ResponseMetadata":{"Error":{"Code":"20403","Message":"Token device not match."}},"Result":null}`, "20403"},
		{"20403 flat code", `{"code":20403,"message":"Token device not match."}`, "20403"},
	}
	for _, tc := range threeCode {
		hint := ExplainRefreshError(&Error{Kind: ErrSessionDead, Status: 401, Msg: tc.msg})
		if hint == "" {
			t.Errorf("%s: hint empty, want a root-cause hint", tc.name)
			continue
		}
		if !strings.Contains(hint, tc.code) {
			t.Errorf("%s: hint %q lacks the code %q", tc.name, hint, tc.code)
		}
		if !strings.Contains(hint, "重新登录") && !strings.Contains(hint, "重绑") {
			t.Errorf("%s: hint %q lacks an actionable re-login/re-bind keyword", tc.name, hint)
		}
	}
	// nil / 非 *Error / 其它业务码 → 无提示。
	if hint := ExplainRefreshError(nil); hint != "" {
		t.Errorf("ExplainRefreshError(nil) = %q, want empty", hint)
	}
	if hint := ExplainRefreshError(errors.New("dial tcp: connection refused")); hint != "" {
		t.Errorf("plain network error hint = %q, want empty", hint)
	}
	if hint := ExplainRefreshError(fmt.Errorf("wrapped: %w", errors.New("boom"))); hint != "" {
		t.Errorf("non-Error wrapper hint = %q, want empty", hint)
	}
	if hint := ExplainRefreshError(&Error{Kind: ErrSessionDead, Status: 401, Msg: `{"code":1001,"message":"We are not able to authenticate you"}`}); hint != "" {
		t.Errorf("pay-family 1001 hint = %q, want empty (downstream symptom, not a refresh root cause)", hint)
	}
}

// TestRefreshLockedLegacyErrorAnnotated: legacy 交换 401 code 20101（死 rt）
// → c.RefreshToken 返回的错误同时含 "20101"（原文透传，doJSON 塞入的
// body 片段不被吞）与 "重新登录"（根因提示语），且 %w 包装保持
// errors.As(&upstream.Error) 能取出 Kind==ErrSessionDead（pool 据此禁用的
// 分类语义不变）。
func TestRefreshLockedLegacyErrorAnnotated(t *testing.T) {
	c := testClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == epExchangeBound {
			// Bound ladder fully refused with the live 10101 shape → legacy.
			return jsonResp(400, `{"code":10101,"message":"refresh token is not matched to the client"}`), nil
		}
		if strings.HasSuffix(r.URL.Path, EpExchange) {
			return jsonResp(401, `{"ResponseMetadata":{"Error":{"Code":"20101","Message":"refresh token is invalid"}}}`), nil
		}
		return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
	})
	a := &auth.Auth{AccessToken: "at", RefreshToken: "deadrt", ExpiresAt: 1, APIHost: "https://oauth.example", Variant: "cn", DeviceID: "1111222233334444"}
	err := c.RefreshToken(a)
	if err == nil {
		t.Fatal("refresh: want error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "20101") {
		t.Errorf("error %q lacks the raw 20101 body passthrough", msg)
	}
	if !strings.Contains(msg, "重新登录") {
		t.Errorf("error %q lacks the re-login root-cause hint", msg)
	}
	var ue *Error
	if !errors.As(err, &ue) {
		t.Fatalf("errors.As(*upstream.Error) failed on %v", err)
	}
	if ue.Kind != ErrSessionDead {
		t.Errorf("wrapped Kind = %v, want ErrSessionDead (classification semantics unchanged)", ue.Kind)
	}
	// 失败路径原子性：a 的字段不被改写（旧 refreshToken 可重试）。
	if a.AccessToken != "at" || a.RefreshToken != "deadrt" {
		t.Errorf("failed refresh must not rewrite tokens: %q / %q", a.AccessToken, a.RefreshToken)
	}
}
