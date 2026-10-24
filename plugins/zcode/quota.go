// quota.go owns the zcode.z.ai billing plane: the live free-quota snapshot
// (GET /api/v1/zcode-plan/billing/balance) mapped onto the panel's
// creditsSummary shape. The claimable-plan preview reader (the panel's
// claim view) lives in preview.go — reading billing/preview is all it
// does; the claim POST itself is captcha-gated and stays official-client
// only.
//
// Header contract (TriDefender/zcode-api routes-quota.ts / claim/client.ts):
// the billing gateway authenticates with the plan JWT (`Authorization: Bearer
// {jwt}`) plus the full context identity set (`TV` — no X-ZCode-Agent) and a
// stable per-account `X-Device-Mid`; a missing device header makes preview
// fail with biz 3001 "parameter error" on campaign gateways.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// zcodeBalance is one balance row in the billing/balance response. Both
// snake_case and camelCase aliases are observed upstream — accept both so
// neither casing drops the field.
type zcodeBalance struct {
	ShowName       string  `json:"show_name"`
	RemainingUnits float64 `json:"remaining_units"`
	RemainingAlt   float64 `json:"remainingUnits"`
	TotalUnits     float64 `json:"total_units"`
	TotalAlt       float64 `json:"totalUnits"`
	UsedUnits      float64 `json:"used_units"`
	UsedAlt        float64 `json:"usedUnits"`
	UnitType       string  `json:"unit_type"`
	UnitTypeAlt    string  `json:"unitType"`
	ExpiresAt      float64 `json:"expires_at"`
	UserPlanID     string  `json:"user_plan_id"`
	PlanID         string  `json:"plan_id"`
	// Capabilities carries the bucket's model scope ("model:glm-5.3-flash")
	// — the entitlement-plane routing input (plane.go). Measured live
	// 2026-09-27: weekend-activity buckets name exactly the models their
	// grant covers.
	Capabilities []string `json:"capabilities"`
}

// zcodePlanRow is one entry of the balance response's plans array — the
// plan metadata the gift card reads (magpie-community/plugins zcode
// giftOf: "several plans can be active at once, and a model routes to the
// gift when any of them has a live bucket serving it"). A bucket names its
// owner through user_plan_id (preferred) or plan_id; the 1024 Dev Day /
// new-user coexistence (issue #53, magpie zcode 0.1.23) surfaced this plane:
// two live plans can each grant the same model, and without the owner link
// a spent bucket and a live one are indistinguishable on the panel.
type zcodePlanRow struct {
	UserPlanID string  `json:"user_plan_id"`
	PlanID     string  `json:"plan_id"`
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	EndsAt     float64 `json:"ends_at"`
}

func (b zcodeBalance) remaining() float64 {
	if b.RemainingUnits != 0 {
		return b.RemainingUnits
	}
	return b.RemainingAlt
}
func (b zcodeBalance) total() float64 {
	if b.TotalUnits != 0 {
		return b.TotalUnits
	}
	return b.TotalAlt
}
func (b zcodeBalance) used() float64 {
	if b.UsedUnits != 0 {
		return b.UsedUnits
	}
	return b.UsedAlt
}
func (b zcodeBalance) unitType() string {
	if b.UnitType != "" {
		return b.UnitType
	}
	return b.UnitTypeAlt
}

type balanceResponse struct {
	Code       int    `json:"code"`
	Msg        string `json:"msg"`
	ServerTime int64  `json:"server_time"`
	Data       struct {
		Balances []zcodeBalance `json:"balances"`
		Plans    []zcodePlanRow `json:"plans"`
	} `json:"data"`
}

// fetchQuotaSnapshot queries billing/balance with the stored JWT and folds
// the balances into a creditsSummary (one package per balance row).
func fetchQuotaSnapshot(sa *storedAuth) (*creditsSummary, error) {
	if strings.TrimSpace(sa.Auth.JWT) == "" {
		return nil, fmt.Errorf("not logged in — no plan JWT (re-run login)")
	}
	platform, arch := platformArch()
	q := url.Values{}
	q.Set("app_version", zcodeIdentity().appVersion)
	q.Set("platform", platform+"-"+arch)
	endpoint := zcodeAPIBase + "/zcode-plan/billing/balance?" + q.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sa.Auth.JWT)
	req.Header.Set("Accept", "application/json")
	for k, v := range buildContextIdentityHeaders(zcodeIdentity(), sa.Auth.DeviceMid) {
		req.Header.Set(k, v)
	}
	resp, err := hostHTTPDo(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("billing balance http %d body=%s", resp.StatusCode, truncateRedacted(string(resp.Body), 200))
	}
	var out balanceResponse
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("billing balance parse: %w", err)
	}
	if out.Code != 0 {
		return nil, fmt.Errorf("billing balance: code=%d msg=%s", out.Code, out.Msg)
	}
	// Entitlement-plane harvest: live-bucket capabilities feed routeFor's
	// model routing so JWT-plane packages (activity/trial buckets) pre-route
	// without waiting for a coding-plane 1113 (plane.go). Spent and expired
	// buckets no longer contribute — with two plans granting the same model
	// (issue #53) a spent bucket's capability must not shadow the live one.
	now := float64(out.ServerTime)
	if now <= 0 {
		now = float64(time.Now().Unix())
	}
	harvestStartPlaneCapabilities(sa.Account.UID, out.Data.Balances, out.Data.Plans, now)
	return summarizeBalances(out.Data.Balances, out.Data.Plans, now), nil
}

// balancePlanKey dedupes a plan by its ownership identity.
func balancePlanKey(p zcodePlanRow) string {
	return strings.TrimSpace(p.UserPlanID) + "\x00" + strings.TrimSpace(p.PlanID)
}

// sameBalancePlan mirrors magpie giftOf's `same`: a balance row and a plan
// belong together when their user_plan_id pair matches (preferred — one
// plan can be granted twice), falling back to plan_id equality.
func sameBalancePlan(b zcodeBalance, p zcodePlanRow) bool {
	bu, pu := strings.TrimSpace(b.UserPlanID), strings.TrimSpace(p.UserPlanID)
	if bu != "" && pu != "" {
		return bu == pu
	}
	return strings.TrimSpace(b.PlanID) == strings.TrimSpace(p.PlanID)
}

// planLive reports whether a plan row is live: status active and its end
// (when the server states one) still ahead. Magpie rewrites an active plan
// past its end to "expired" before matching; we compare directly.
func planLive(p zcodePlanRow, now float64) bool {
	if !strings.EqualFold(strings.TrimSpace(p.Status), "active") {
		return false
	}
	return p.EndsAt <= 0 || p.EndsAt > now
}

// bucketSpent mirrors magpie giftSpent: a bucket with no remaining units is
// spent (our tolerant parser reads an absent remaining as 0, so a bucket
// that names a total but no remainder counts as spent — the safe side for
// both display and routing).
func bucketSpent(b zcodeBalance) bool {
	return b.total() > 0 && b.remaining() <= 0
}

// bucketOwner finds the plan a balance row belongs to. live=true searches
// only live plans (magpie's gift-card read); live=false searches every plan
// (to tell "an expired plan's bucket" from "no plan at all").
func bucketOwner(b zcodeBalance, plans []zcodePlanRow, now float64, live bool) *zcodePlanRow {
	for i := range plans {
		if live && !planLive(plans[i], now) {
			continue
		}
		if sameBalancePlan(b, plans[i]) {
			return &plans[i]
		}
	}
	return nil
}

// summarizeBalances folds balance rows into the panel's creditsSummary,
// plan-aware since 0.2.3 (issue #53, magpie zcode 0.1.23 alignment):
//
//   - when more than one live plan holds buckets, every bucket is named
//     after its plan ("ZCode 1024 Dev Day · GLM-5.3") so a spent pool and
//     a live one granting the same model are told apart on the panel;
//   - buckets a request can spend now list first, spent ones next, buckets
//     of an expired/inactive plan last (each group keeps the balance's
//     order) — a spent plan listed first used to hide the live plan's
//     allowance for the same model;
//   - totals still sum every row, so a live bucket keeps an account with a
//     spent twin from reading as exhausted.
func summarizeBalances(rows []zcodeBalance, plans []zcodePlanRow, now float64) *creditsSummary {
	liveSet := map[string]struct{}{}
	for _, p := range plans {
		if planLive(p, now) {
			liveSet[balancePlanKey(p)] = struct{}{}
		}
	}
	several := len(liveSet) > 1
	type classified struct {
		pkg  packageSummary
		rank int
	}
	out := make([]classified, 0, len(rows))
	sum := &creditsSummary{PackCount: len(rows)}
	for i, b := range rows {
		remain, used, total := int64(b.remaining()), int64(b.used()), int64(b.total())
		sum.TotalRemain += remain
		sum.TotalUsed += used
		sum.TotalSize += total
		name := strings.TrimSpace(b.ShowName)
		if name == "" {
			name = fmt.Sprintf("额度池 %d", i+1)
		}
		if ut := strings.TrimSpace(b.unitType()); ut != "" {
			name += " (" + ut + ")"
		}
		rank := 2 // no plan linkage: the coding-plane buckets, unchanged
		if owner := bucketOwner(b, plans, now, true); owner != nil {
			if several {
				name = strings.TrimSpace(owner.Name) + " · " + name
			}
			if bucketSpent(b) {
				rank = 1
			} else {
				rank = 0
			}
		} else if anyOwner := bucketOwner(b, plans, now, false); anyOwner != nil {
			rank = 3 // the plan exists but is expired/inactive
			name = strings.TrimSpace(anyOwner.Name) + " · " + name
		}
		switch rank {
		case 1:
			name += "（已用尽）"
		case 3:
			name += "（已过期）"
		}
		out = append(out, classified{packageSummary{
			Name: name, Remain: remain, Used: used, Size: total,
		}, rank})
	}
	// Stable ordering by rank: spendable first, spent next, unlinked, expired.
	for r := 0; r <= 3; r++ {
		for _, c := range out {
			if c.rank == r {
				sum.Packages = append(sum.Packages, c.pkg)
			}
		}
	}
	return sum
}
