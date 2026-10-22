// checkin_window_test.go — v0.8.62: pins the daily-round visibility-lag
// self-heal (issue #27, live evidence 2026-10-12 u673e7fcc intl):
//
//   - dailyWindowJustOpened boundaries — the lag margin is anchored to
//     Beijing 10:00 [10:00, 10:30) regardless of the host's local zone
//     (10:01:04 bare GET campaigns had no daily row; 10:04:30 the
//     production chain saw act-20261009-518 CLAIMABLE and claimed +100);
//   - checkinWithWindowRetry — the scheduler path retries NOTHING_CLAIMABLE
//     inside the margin (up to 3 retries) instead of waiting for the 15:00
//     fallback tick, and never retries other verdicts / outside the window;
//   - campaignIdleDiagnosis — inside the window the no-row verdict is the
//     visibility-lag wording, not the upstream-audience/risk-control one.
package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// bjTime builds a time in the Beijing zone the daily round anchors to.
func bjTime(hour, min int) time.Time {
	return time.Date(2026, 10, 12, hour, min, 0, 0, time.FixedZone("UTC+8", 8*3600))
}

func TestDailyWindowJustOpenedBoundaries(t *testing.T) {
	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"bj-0959", bjTime(9, 59), false},
		{"bj-1000", bjTime(10, 0), true},
		{"bj-1029", bjTime(10, 29), true},
		{"bj-1030", bjTime(10, 30), false},
		{"bj-1459", bjTime(14, 59), false},
		{"bj-0000", bjTime(0, 0), false},
		// 非北京时区输入：UTC 02:15 = 北京 10:15 → 窗口内。窗口锚定轮次
		// 刷新时刻（UTC+8 10:00），与宿主本地时区无关。
		{"utc-0215", time.Date(2026, 10, 12, 2, 15, 0, 0, time.UTC), true},
		{"utc-0230", time.Date(2026, 10, 12, 2, 30, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		if got := dailyWindowJustOpened(c.now); got != c.want {
			t.Errorf("%s: dailyWindowJustOpened(%v) = %v, want %v", c.name, c.now, got, c.want)
		}
	}
}

// withWindowTestSeams installs the test seams for the retry wrapper: a fixed
// clock, a shrunk retry gap and a scripted performCheckinCallFn. The script
// receives the 1-based call number; the returned pointer counts calls made
// through the seam.
func withWindowTestSeams(t *testing.T, now time.Time, gap time.Duration, script func(callNo int) (map[string]any, error)) *int {
	t.Helper()
	calls := 0
	prevNow, prevGap, prevFn := dailyWindowNow, windowRetryGap, performCheckinCallFn
	dailyWindowNow = func() time.Time { return now }
	windowRetryGap = gap
	performCheckinCallFn = func(sa *storedAuth) (map[string]any, error) {
		calls++
		return script(calls)
	}
	t.Cleanup(func() {
		dailyWindowNow, windowRetryGap, performCheckinCallFn = prevNow, prevGap, prevFn
	})
	return &calls
}

// 前两次 NOTHING_CLAIMABLE、第三次 success → 恰好调用 3 次，返回成功结果。
// 实弹对应：10:00:00 整点 tick 无行，10:04 第三次尝试领到 +100。
func TestCheckinWithWindowRetrySucceedsOnThirdCall(t *testing.T) {
	calls := withWindowTestSeams(t, bjTime(10, 1), time.Millisecond, func(callNo int) (map[string]any, error) {
		if callNo < 3 {
			return map[string]any{"success": false, "result": "NOTHING_CLAIMABLE", "message": "今日暂无可领取权益"}, nil
		}
		return map[string]any{"success": true, "result": "CLAIMED", "rewardCredits": float64(100)}, nil
	})
	res, err := checkinWithWindowRetry(intlAuth())
	if err != nil {
		t.Fatalf("checkinWithWindowRetry: %v", err)
	}
	if *calls != 3 {
		t.Fatalf("performCheckinCall called %d times, want exactly 3", *calls)
	}
	if ok, _ := res["success"].(bool); !ok {
		t.Fatalf("must surface the third (successful) verdict: %+v", res)
	}
	if rc, _ := res["rewardCredits"].(float64); rc != 100 {
		t.Fatalf("rewardCredits = %v, want 100", res["rewardCredits"])
	}
}

// 持续 NOTHING_CLAIMABLE：初始 1 次 + 至多 windowRetryMaxAttempts 次重试后
// 定案，不再无限打。v0.8.66：3 → 16（90s×16 ≈ 24 分钟，覆盖整个
// [10:00,10:30) 滞后边距），配合同版本落地的 10:05 UTC+8 窗口锚定 tick。
func TestCheckinWithWindowRetryCapsAtBoundedRetries(t *testing.T) {
	calls := withWindowTestSeams(t, bjTime(10, 2), time.Millisecond, func(callNo int) (map[string]any, error) {
		return map[string]any{"success": false, "result": "NOTHING_CLAIMABLE"}, nil
	})
	res, err := checkinWithWindowRetry(intlAuth())
	if err != nil {
		t.Fatalf("checkinWithWindowRetry: %v", err)
	}
	if *calls != 1+windowRetryMaxAttempts {
		t.Fatalf("performCheckinCall called %d times, want 1 initial + %d retries", *calls, windowRetryMaxAttempts)
	}
	if r, _ := res["result"].(string); r != "NOTHING_CLAIMABLE" {
		t.Fatalf("final verdict = %v, want NOTHING_CLAIMABLE (definitive after retries)", res["result"])
	}
}

// 非 NOTHING_CLAIMABLE 结果（ALREADY_CLAIMED / BLOCKED / …）是权威判定，
// 不重试。
func TestCheckinWithWindowRetryNoRetryForOtherVerdicts(t *testing.T) {
	calls := withWindowTestSeams(t, bjTime(10, 3), time.Millisecond, func(callNo int) (map[string]any, error) {
		return map[string]any{"success": false, "result": "ALREADY_CLAIMED"}, nil
	})
	res, err := checkinWithWindowRetry(intlAuth())
	if err != nil {
		t.Fatalf("checkinWithWindowRetry: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("authoritative verdict must not be retried, called %d times", *calls)
	}
	if r, _ := res["result"].(string); r != "ALREADY_CLAIMED" {
		t.Fatalf("verdict = %v, want ALREADY_CLAIMED", res["result"])
	}
}

// 窗口外（如 15:00 轮次前后）的 NOTHING_CLAIMABLE 不重试——滞后边距
// 只覆盖 10:00 开窗后的可见性窗口。
func TestCheckinWithWindowRetryOutsideWindowNoRetry(t *testing.T) {
	calls := withWindowTestSeams(t, bjTime(14, 55), time.Millisecond, func(callNo int) (map[string]any, error) {
		return map[string]any{"success": false, "result": "NOTHING_CLAIMABLE"}, nil
	})
	if _, err := checkinWithWindowRetry(intlAuth()); err != nil {
		t.Fatalf("checkinWithWindowRetry: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("outside the lag margin NOTHING_CLAIMABLE must not be retried, called %d times", *calls)
	}
}

// err 即返回：网络/解析类错误交给调度路径的既有处理，不在窗口内空转。
func TestCheckinWithWindowRetryErrorReturnsImmediately(t *testing.T) {
	sentinel := errors.New("dial tcp: connection refused")
	calls := withWindowTestSeams(t, bjTime(10, 4), time.Millisecond, func(callNo int) (map[string]any, error) {
		return nil, sentinel
	})
	res, err := checkinWithWindowRetry(intlAuth())
	if *calls != 1 {
		t.Fatalf("error must return on the first call, called %d times", *calls)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the sentinel", err)
	}
	if res != nil {
		t.Fatalf("res = %+v, want nil", res)
	}
}

// 窗口分支文案：开窗后的「无行」是可见性滞后，不是上游受众/风控。
// 10:31（窗口外）恢复原身份分叉（测试环境无桥 → derived 模拟身份文案）。
func TestCampaignIdleDiagnosisWindowLag(t *testing.T) {
	status := &campaignStatusResponse{
		ShowCampaign: true,
		Campaigns: []campaign{
			{CampaignID: "01a05bce-e800-7494-a002-806e4438f483", CampaignKey: "act-20260901-493", ActionType: "VIEW_DETAILS", ClaimStatus: "CLAIMED", StartAt: 1788247200, EndAt: 1793462340},
		},
	}
	prevNow := dailyWindowNow
	t.Cleanup(func() { dailyWindowNow = prevNow })

	// 窗口内（北京 10:05，实弹 10:04:30 见行时刻附近）
	dailyWindowNow = func() time.Time { return bjTime(10, 5) }
	msg := campaignIdleDiagnosis(status, intlAuth())
	for _, want := range []string{"可见性有数分钟滞后", "10:00（UTC+8）刚开窗", "自动重试补领"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("in-window diagnosis missing %q: %q", want, msg)
		}
	}
	if strings.Contains(msg, "每日 100 积分行未出现") {
		t.Fatalf("in-window diagnosis must not render the identity fork: %q", msg)
	}

	// 窗口外（北京 10:31）→ 原身份分叉：测试环境（QD_UMID_AUTO=0，无桥）
	// machineIdentityFor 为 derived，走「官方格式模拟身份」文案。
	dailyWindowNow = func() time.Time { return bjTime(10, 31) }
	msg = campaignIdleDiagnosis(status, intlAuth())
	if strings.Contains(msg, "可见性有数分钟滞后") {
		t.Fatalf("out-of-window diagnosis must not use the lag wording: %q", msg)
	}
	if !strings.Contains(msg, "官方格式模拟身份") {
		t.Fatalf("out-of-window diagnosis must fall back to the identity fork: %q", msg)
	}
	if !strings.Contains(msg, "每日 100 积分行未出现") {
		t.Fatalf("out-of-window diagnosis missing the identity-fork lead: %q", msg)
	}
}
