// account_restriction.go — per-credential upstream account-restriction
// registry (business code 11140).
//
// v0.9.73: the WorkBuddy gateway answers an account-level restriction with
// HTTP 403 + business code 11140 and says so in the display copy:
//
//	{"code":11140,"msg":"request illegal","displayMsg":{"en":"Your account
//	 has been restricted due to unusual activity","zh":"账号存在异常行为"}}
//
// This is the ACCOUNT being restricted upstream — not a request-level WAF
// bounce (that is the bare-403 shape, isWafBlocked), not a channel risk
// control (11128, request-shaped), and not credit exhaustion (credits can
// read perfectly healthy while the chat plane refuses the account). The
// restriction itself can only be lifted by WorkBuddy/Tencent support; nothing
// in the plugin can appeal it.
//
// What the plugin CAN do is stop re-offering a restricted credential:
// pre-0.9.73 the only brake was the host's short 403 cooldown, after which
// the scheduler picked the same account again, burned another upstream
// round trip, and surfaced another 403→500 to the user — repeated strikes
// against an account the upstream already flagged is the exact "unusual
// activity" pattern worth avoiding (field-confirmed trigger for this code
// family: parallel requests — magpie-community/plugins#339, where the
// reporter's account recovered after they stopped firing two harnesses at
// it concurrently).
//
// This file owns the whole 11140 concern:
//  1. isAccountRestricted — the 403+11140 classifier (JSON envelope first,
//     substring fallback, same shape as isModelScopedRateLimit).
//  2. An in-memory registry keyed credential id: the first 11140 quarantines
//     the credential for 1h, repeats back off exponentially (2h, 4h, 8h cap).
//     A credential that answers normally again clears its entry (lazy expiry
//     + the healthy note on the success paths), so a restriction that lifts
//     upstream self-heals without operator action.
//  3. accountRestrictionError — the executor fast-fail (plain error, no
//     StatusCode: the host must rotate, never read it as credential quota)
//     with bilingual, actionable copy.
//
// Layering: the host's own 403 cooldown (via upstreamStatusError's
// statusError) stays exactly as is — this registry adds the longer
// plugin-side quarantine on top, the same two-layer shape as the 6004
// model-scoped registry in model_ratelimit.go.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// accountRestrictedCode is the WorkBuddy business code for an account
	// restriction ("request illegal" / "unusual activity"), carried on an
	// HTTP 403.
	accountRestrictedCode = 11140
	// accountRestrictionMaxEntries bounds the registry (defensive; the
	// per-process credential count is tiny).
	accountRestrictionMaxEntries = 512
)

// accountRestrictionBackoff is the quarantine ladder: first strike 1h, then
// 2h, 4h, capped at 8h. A restriction is account-level and upstream-lifted,
// so the ladder is deliberately long compared to the 6004 model windows —
// but capped so a restriction that lifts upstream is re-probed within a
// workday without operator action.
var accountRestrictionBackoff = []time.Duration{
	time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour,
}

// isAccountRestricted reports an upstream account-level restriction: HTTP
// 403 carrying business code 11140. The JSON path is authoritative (the
// shared upstreamErrorShape, same as the 11102/11115/11128 classifiers);
// the substring path catches envelope variants whose body is not the plain
// business JSON — including the string-coded spelling — but still carries
// the same markers.
func isAccountRestricted(statusCode int, payload string) bool {
	if statusCode != http.StatusForbidden {
		return false
	}
	var shape upstreamErrorShape
	if err := json.Unmarshal([]byte(payload), &shape); err == nil {
		return shape.Code == accountRestrictedCode
	}
	low := strings.ReplaceAll(payload, " ", "")
	return strings.Contains(low, `"code":11140`) || strings.Contains(low, `"code":"11140"`)
}

// -----------------------------------------------------------------------------
// registry

type accountRestrictionEntry struct {
	until   time.Time
	strikes int
}

type accountRestrictionRegistry struct {
	mu      sync.Mutex
	entries map[string]*accountRestrictionEntry
}

// wbAccountRestrictions is the process-wide registry. In-memory only: after
// a restart the next 11140 re-arms it (a quarantine is estimative state —
// same ruling as the #61 daily counters).
var wbAccountRestrictions = &accountRestrictionRegistry{entries: map[string]*accountRestrictionEntry{}}

// accountRestrictionBackoffFor maps a strike count onto the quarantine
// ladder (1-indexed; beyond the table pins at the cap).
func accountRestrictionBackoffFor(strikes int) time.Duration {
	if strikes < 1 {
		strikes = 1
	}
	if strikes > len(accountRestrictionBackoff) {
		strikes = len(accountRestrictionBackoff)
	}
	return accountRestrictionBackoff[strikes-1]
}

// noteAccountRestrictionFromPayload is the chat-path hook: no-op unless the
// upstream response is the 11140 account restriction.
func noteAccountRestrictionFromPayload(authID string, sa *storedAuth, statusCode int, payload string) {
	if !isAccountRestricted(statusCode, payload) {
		return
	}
	noteAccountRestriction(authID, sa)
}

// noteAccountRestriction quarantines the credential: strikes escalate along
// the ladder and the window never shortens mid-quarantine.
func noteAccountRestriction(authID string, sa *storedAuth) {
	authID = restrictionAuthID(authID, sa)
	if authID == "" {
		return
	}
	now := time.Now()
	wbAccountRestrictions.mu.Lock()
	defer wbAccountRestrictions.mu.Unlock()
	if len(wbAccountRestrictions.entries) >= accountRestrictionMaxEntries {
		for k, e := range wbAccountRestrictions.entries {
			if !e.until.After(now) {
				delete(wbAccountRestrictions.entries, k)
			}
		}
	}
	e, ok := wbAccountRestrictions.entries[authID]
	if !ok {
		e = &accountRestrictionEntry{}
		wbAccountRestrictions.entries[authID] = e
	}
	e.strikes++
	until := now.Add(accountRestrictionBackoffFor(e.strikes))
	if until.After(e.until) {
		e.until = until
	}
}

// noteAccountHealthy clears any restriction state for the credential — wired
// on the executor success paths so a restriction lifted upstream self-heals
// the moment the account answers normally again.
func noteAccountHealthy(authID string, sa *storedAuth) {
	authID = restrictionAuthID(authID, sa)
	if authID == "" {
		return
	}
	wbAccountRestrictions.mu.Lock()
	delete(wbAccountRestrictions.entries, authID)
	wbAccountRestrictions.mu.Unlock()
}

// accountRestrictedUntil reports the active quarantine deadline, if any
// (lazy expiry: a lapsed entry is discarded and reports false).
func accountRestrictedUntil(authID string) (time.Time, bool) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return time.Time{}, false
	}
	wbAccountRestrictions.mu.Lock()
	defer wbAccountRestrictions.mu.Unlock()
	e, ok := wbAccountRestrictions.entries[authID]
	if !ok {
		return time.Time{}, false
	}
	if !e.until.After(time.Now()) {
		delete(wbAccountRestrictions.entries, authID)
		return time.Time{}, false
	}
	return e.until, true
}

// accountRestrictionCooling is the scheduler-pick filter: a quarantined
// credential is simply not offered as a candidate.
func accountRestrictionCooling(authID string) bool {
	_, cooling := accountRestrictedUntil(authID)
	return cooling
}

// restrictionQuarantineCount reports how many credentials are under an
// active quarantine (the scheduler's all-deferred WARN needs to distinguish
// "empty because quarantined" from "no candidates at all"; lazy expiry
// keeps the count honest).
func restrictionQuarantineCount() int {
	now := time.Now()
	wbAccountRestrictions.mu.Lock()
	defer wbAccountRestrictions.mu.Unlock()
	n := 0
	for k, e := range wbAccountRestrictions.entries {
		if !e.until.After(now) {
			delete(wbAccountRestrictions.entries, k)
			continue
		}
		n++
	}
	return n
}

// restrictionAuthID resolves the registry key: the host auth id (the pick
// candidate's ID space) with the storedAuth's account UID as fallback —
// the same resolution recordUpstreamFailure applies for the pair cooldowns.
func restrictionAuthID(authID string, sa *storedAuth) string {
	if id := strings.TrimSpace(authID); id != "" {
		return id
	}
	if sa != nil {
		if id := sanitizeUIDForFileName(sa.Account.UID); id != "" {
			return id
		}
	}
	return ""
}

// accountRestrictionError renders the executor fast-fail for a quarantined
// credential, or nil. Deliberately plain (no StatusCode() impl): every host
// version must treat it as a transient request-level failure and rotate to
// another candidate, never as credential-level quota trouble.
func accountRestrictionError(authID string, sa *storedAuth) error {
	until, ok := accountRestrictedUntil(restrictionAuthID(authID, sa))
	if !ok {
		return nil
	}
	untilStr := until.In(wbCNZone).Format("2006-01-02 15:04 UTC+8")
	return fmt.Errorf(
		"该账号被上游风控限制（code 11140 账号存在异常行为），已自动隔离至 %s——限制由上游判定，插件无法解除；已知诱因：并发请求（建议开启 account_max_concurrent: 1）或新账号立即大流量；请在官方客户端确认账号状态或申诉，恢复后将自动重新启用。"+
			" // Upstream account restriction (code 11140, unusual activity); this credential is quarantined until %s — the restriction is upstream's call and the plugin cannot lift it. Known triggers: parallel requests (consider account_max_concurrent: 1) or heavy traffic right after signup; check the account in the official client or appeal, and it re-enters rotation automatically once healthy.",
		untilStr, untilStr)
}
