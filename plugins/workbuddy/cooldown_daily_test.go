package main

import (
	"strings"
	"testing"
	"time"
)

// TestIsDailyQuotaFrame (issue #35 supplementary tier, v0.9.58): the daily
// classifier must catch daily wording in both languages and combination
// form, while refusing 6004's reset copy, generic rate limits, hard-credit
// wording, and empty bodies.
func TestIsDailyQuotaFrame(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"combined en", `{"code":50001,"msg":"daily limit reached"}`, true},
		{"combined en 2", `{"code":50001,"msg":"you have exceeded the daily quota"}`, true},
		{"zh combined", `{"code":50001,"msg":"今日免费模型请求次数已达上限"}`, true},
		{"zh daily+quota split", `{"msg":"每日请求额度已用尽，明天再来"}`, true},
		{"split words en", "daily usage allowance exhausted", true},
		{"6004 reset copy (must NOT claim)", modelRateLimitSamplePayload, false},
		{"generic rate limit", `{"code":11120,"msg":"rate limited"}`, false},
		{"throttle wording", "too many requests, throttled", false},
		{"hard credit", "insufficient credits, 请充值", false},
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"daily alone", "every daily digest email", false},
		{"limit alone", "the sky is the limit", false},
	}
	for _, tc := range cases {
		if got := isDailyQuotaFrame(tc.body); got != tc.want {
			t.Errorf("%s: isDailyQuotaFrame(%q) = %v, want %v", tc.name, tc.body, got, tc.want)
		}
	}
}

// TestNextDailyResetUTC8 pins the midnight fallback: before midnight the
// reset is the SAME day's 00:00+1d; exactly at midnight it rolls to the NEXT
// day (the allowance refreshes AT midnight, so the hold earned at 00:00:00
// must not expire instantly).
func TestNextDailyResetUTC8(t *testing.T) {
	cases := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"evening UTC+8", time.Date(2026, 10, 12, 20, 0, 0, 0, wbDailyZone), time.Date(2026, 10, 13, 0, 0, 0, 0, wbDailyZone)},
		{"morning UTC+8", time.Date(2026, 10, 12, 9, 30, 0, 0, wbDailyZone), time.Date(2026, 10, 13, 0, 0, 0, 0, wbDailyZone)},
		{"exactly midnight", time.Date(2026, 10, 12, 0, 0, 0, 0, wbDailyZone), time.Date(2026, 10, 13, 0, 0, 0, 0, wbDailyZone)},
		{"utc instant maps to zone", time.Date(2026, 10, 12, 16, 0, 0, 0, time.UTC), time.Date(2026, 10, 14, 0, 0, 0, 0, wbDailyZone)},
	}
	for _, tc := range cases {
		if got := nextDailyResetUTC8(tc.now); !got.Equal(tc.want) {
			t.Errorf("%s: nextDailyResetUTC8(%v) = %v, want %v", tc.name, tc.now, got, tc.want)
		}
	}
}

// TestDailyQuotaFastFailCopy: the reason-aware fast-fail error names the
// daily allowance and the UTC+8 reset, never "429".
func TestDailyQuotaFastFailCopy(t *testing.T) {
	withFrozenCooldown(t, time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC))
	recordUpstreamFailure("acct-d", nil, "deepseek-v4.1-flash", 0,
		`workbuddy upstream error: {"code":50001,"msg":"daily quota reached"}`)
	err := modelCooldownError("acct-d", nil, "deepseek-v4.1-flash")
	if err == nil {
		t.Fatal("expected a fast-fail error for the daily hold")
	}
	msg := err.Error()
	if !strings.Contains(msg, "每日限额") && !strings.Contains(msg, "daily allowance") {
		t.Errorf("copy must name the daily allowance: %q", msg)
	}
	if strings.Contains(msg, "429") {
		t.Errorf("copy must never carry the literal 429: %q", msg)
	}
	if !strings.Contains(msg, "2026-10-13 00:00:00 UTC+8") {
		t.Errorf("copy must carry the UTC+8 midnight reset: %q", msg)
	}
}

// TestDailyQuotaDeclaredResetWins: a payload that DECLARES its reset instant
// ("将在 … UTC+8 重置") overrides the midnight fallback.
func TestDailyQuotaDeclaredResetWins(t *testing.T) {
	withFrozenCooldown(t, time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC))
	body := `workbuddy upstream error: {"code":50001,"msg":"每日用量已达上限，将在 2026-10-12 23:30:00 UTC+8 重置"}`
	recordUpstreamFailure("acct-r", nil, "kimi-k3", 0, body)
	cooldownMu.Lock()
	entry := cooldownTable[modelCooldownKey{AuthID: "acct-r", ModelID: "kimi-k3"}]
	cooldownMu.Unlock()
	want := time.Date(2026, 10, 12, 23, 30, 0, 0, wbDailyZone)
	if !entry.Until.Equal(want) {
		t.Fatalf("declared reset must win: until=%v want %v", entry.Until, want)
	}
	if entry.Reason != cooldownReasonDailyQuota {
		t.Fatalf("reason = %q, want daily_quota", entry.Reason)
	}
}

// TestDailyQuotaNeverShortenedByUnknown: a later 60 s unknown-tier hold on
// the same pair must not shorten the active daily window.
func TestDailyQuotaNeverShortenedByUnknown(t *testing.T) {
	withFrozenCooldown(t, time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC))
	recordUpstreamFailure("acct-n", nil, "glm-5.3-flash", 0,
		`workbuddy upstream error: {"msg":"daily quota reached"}`)
	recordUpstreamFailure("acct-n", nil, "glm-5.3-flash", 0,
		"workbuddy upstream error: service unavailable")
	cooldownMu.Lock()
	entry := cooldownTable[modelCooldownKey{AuthID: "acct-n", ModelID: "glm-5.3-flash"}]
	cooldownMu.Unlock()
	want := time.Date(2026, 10, 13, 0, 0, 0, 0, wbDailyZone)
	if !entry.Until.Equal(want) || entry.Reason != cooldownReasonDailyQuota {
		t.Fatalf("daily hold must survive the unknown-tier re-mark: %+v", entry)
	}
}
