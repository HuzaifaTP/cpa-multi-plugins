// enterprise.go — the enterprise/education account's credits plane (issue #55,
// sabercomo 2026-10-24).
//
// An enterprise-space CN account (WorkBuddy 企业版 / 教育公益版; JWT carries
// token_source: enterprise_switch and an ent-member:<id> role, the stored
// account keeps a non-empty enterpriseId) answers the PERSONAL meter plane
// with HTTP 200 + empty data — TotalCount 0, Accounts null — not an error.
// The plugin used to fold that into a zero creditsSummary, so the panel read
// "余0 已用0 · free" for an account that actually holds a 2000-credit
// enterprise allowance and keeps answering chat fine; worse, shouldReenableCN
// demands TotalRemain > 0, so such an account, once disabled, would never be
// re-enabled on its own.
//
// The enterprise meter plane answers the allowance directly (same billing
// gateway, same header set — no extra enterprise headers needed, the token
// already carries the enterprise identity; measured live by the reporter):
//
//	POST /billing/meter/get-enterprise-user-usage   HTTP 200
//	{"code":0,"msg":"OK","data":{"credit":4.11,"limitNum":2000,
//	 "cycleStartTime":"2026-10-01 00:00:00","cycleEndTime":"2026-10-31 23:59:59",
//	 "cycleResetTime":"2026-11-01 00:00:00"}}
//
// credit is this cycle's consumption, limitNum the cycle's allowance. The
// cycle REFILLS at cycleResetTime — it is not a pack that expires — so the
// synthesized summary must never read as "about to lapse".
package main

import (
	"encoding/json"
	"fmt"
)

// enterpriseUsage mirrors /billing/meter/get-enterprise-user-usage's data.
// credit/limitNum arrive as JSON numbers (fractional credit observed live).
type enterpriseUsage struct {
	Credit     float64 `json:"credit"`
	LimitNum   float64 `json:"limitNum"`
	CycleStart string  `json:"cycleStartTime"`
	CycleEnd   string  `json:"cycleEndTime"`
	CycleReset string  `json:"cycleResetTime"`
}

// isEnterpriseAccount reports whether the stored account belongs to an
// enterprise space (enterpriseId set at login). Only such accounts take the
// enterprise fallback; personal accounts never touch the extra plane.
func isEnterpriseAccount(sa *storedAuth) bool {
	return sa != nil && sa.Account.EnterpriseID != ""
}

// fetchEnterpriseUsage reads the enterprise allowance for one account. The
// call rides the same billingCall ladder (identity headers, retry ladder,
// net-diag on transport exhaustion) as every other meter call.
func fetchEnterpriseUsage(sa *storedAuth) (*enterpriseUsage, error) {
	data, err := billingCall(sa, "/billing/meter/get-enterprise-user-usage", map[string]any{})
	if err != nil {
		return nil, err
	}
	var u enterpriseUsage
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, fmt.Errorf("enterprise usage parse: %w", err)
	}
	// limitNum is the cycle allowance; a non-positive one means the plane is
	// not speaking the documented shape — treat as no data rather than 0.
	if u.LimitNum <= 0 {
		return nil, fmt.Errorf("enterprise usage: no limitNum in response")
	}
	return &u, nil
}

// creditsSummary folds the enterprise usage into the panel's summary shape:
// the cycle is an allowance that refills, not a pack that expires, so it is
// rendered as one synthetic package named for the plane and the totals carry
// the live remain (limit - used, clamped at 0).
func (u *enterpriseUsage) creditsSummary() *creditsSummary {
	// Fold to whole credits FIRST so remain+used always reconciles with
	// size on the panel (a truncated 4.11 → 4 used, remain = 2000-4 = 1996;
	// mixing float remain with int used would read 1995+4 ≠ 2000).
	used := int64(u.Credit)
	if used < 0 {
		used = 0
	}
	size := int64(u.LimitNum)
	remain := size - used
	if remain < 0 {
		remain = 0
	}
	cr := &creditsSummary{
		TotalRemain: remain,
		TotalUsed:   used,
		TotalSize:   size,
		PackCount:   1,
	}
	cr.Packages = append(cr.Packages, packageSummary{
		Name:       "企业额度（周期回满）",
		Remain:     remain,
		Used:       used,
		Size:       size,
		CycleStart: u.CycleStart,
		CycleEnd:   u.CycleEnd,
	})
	return cr
}

// enterpriseCheckinRefusal is the panel answer for a manual check-in press on
// an enterprise account: the daily-checkin plane rejects such accounts with
// HTTP 400 biz 10001 "企业账号不支持该操作" (measured live by the reporter), so the
// button is short-circuited here with the reason instead of a doomed call.
func enterpriseCheckinRefusal() map[string]any {
	return map[string]any{
		"success": false,
		"message": "企业版账号不支持每日签到（企业额度按周期自动回满，无需签到）",
	}
}
