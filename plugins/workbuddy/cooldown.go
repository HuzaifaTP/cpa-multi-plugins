// cooldown.go — per-(credential, model) cooldown table (issue #35).
//
// Field report (issue #35, fyzero): a workbuddy.ai Global account hitting a
// free-model (0x) DAILY LIMIT answers each request with HTTP 200 + an
// in-stream error frame (or an immediately-empty stream) in ~300 ms. The
// pre-0.9.57 surface recorded nothing the host could act on:
//
//   - usage monitoring logged failed=0 / in=0 / out=0 (the reporter's build
//     predated the v0.9.29 frame detector, but even with it the failure only
//     surfaced in-band on an already-200 stream);
//   - the host cooldown layer (statusError -> MarkResult) never fired — the
//     200 was already handed off, and stream_head_timeout defaults to off;
//   - session affinity kept pinning the conversation to the drained
//     credential; the only recovery was disabling the account by hand.
//
// The 6004 model-scoped rate limit (429 + declared reset) already had its own
// registry (model_ratelimit.go); everything else an upstream can do to a
// single (credential, model) pair had no owner. This file ports the
// qoder/zcode pattern (v0.8.18 / v0.12.76):
//
//  1. recordUpstreamFailure routes a failure body into the table:
//     rate-limit wording  -> 300 s hold,
//     in-stream error frames / empty streams -> 60 s hold,
//     hard credit exhaustion and 6004 -> deliberately NOT tabled (account
//     level stays with the lifecycle/statusError path; 6004's declared
//     reset stays authoritative in model_ratelimit.go).
//  2. The per-credential model catalog (handleModelForAuth) drops cooling
//     pairs, so the host's built-in scheduler stops re-offering them.
//  3. The opt-in scheduler picker (scheduler_mode: credits) skips cooling
//     candidates — same agreement qoder's picker has with its filter.
//  4. Executors fast-fail a cooling pair before any upstream call
//     (modelCooldownError, mirroring the 6004 fast-fail).
//
// The 60 s catch-all on in-stream frames is the honest answer to the issue's
// open question ("what does the Global gateway return for a daily limit?"):
// we cannot pattern-match wording we have never seen, but the frame detector
// (workBuddyStreamFrame) only fires on an upstream that REFUSED on a 200 —
// rotating that pair for a minute is mild, self-expiring, and strictly
// better than silently hammering the drained credential.
//
// State is process-local: it survives config reloads but not a host restart.
package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	// modelCooldownRateLimit backs off rate-limit-shaped failures: upstream
	// explicitly asked us to slow down on the pair.
	modelCooldownRateLimit = 300 * time.Second
	// modelCooldownUnknown covers empty streams and in-stream error frames:
	// short enough that a transient glitch re-probes quickly, long enough to
	// break the sticky-session retry loop the issue documents.
	modelCooldownUnknown = 60 * time.Second
	// modelCooldownMaxEntries bounds the table against a hostile upstream.
	modelCooldownMaxEntries = 4096
)

type cooldownReason string

const (
	cooldownReasonRateLimit cooldownReason = "rate_limit"
	cooldownReasonUnknown   cooldownReason = "upstream_error"
)

type modelCooldownKey struct {
	AuthID  string
	ModelID string
}

type modelCooldownEntry struct {
	Reason    cooldownReason
	Until     time.Time
	UpdatedAt time.Time
}

var (
	cooldownMu    sync.Mutex
	cooldownTable = make(map[modelCooldownKey]modelCooldownEntry)
	cooldownNowFn = time.Now
)

// cooldownAuthIDFor derives the cooldown key for a credential, mirroring the
// host auth ID convention in toAuthDataOptsWithNote (sanitized UID, else
// provider name). Scheduler candidates carry the same identifier in
// SchedulerAuthCandidate.ID, and model.for_auth carries it in req.AuthID, so
// keys recorded at failure time match keys queried by every consumer.
func cooldownAuthIDFor(sa *storedAuth) string {
	if sa != nil {
		if id := sanitizeUIDForFileName(sa.Account.UID); id != "" {
			return id
		}
	}
	return providerName
}

// markModelCooldown records (or re-arms) a throttled (credential, model)
// pair. Empty halves are ignored: without a model the entry would freeze the
// credential, without an auth id it would freeze the model everywhere.
func markModelCooldown(authID, model string, reason cooldownReason) {
	authID = strings.TrimSpace(authID)
	model = strings.ToLower(strings.TrimSpace(model))
	if authID == "" || model == "" {
		return
	}
	ttl := modelCooldownUnknown
	if reason == cooldownReasonRateLimit {
		ttl = modelCooldownRateLimit
	}
	now := cooldownNowFn()
	cooldownMu.Lock()
	cooldownSweepLocked(now)
	if len(cooldownTable) >= modelCooldownMaxEntries {
		// Table full: evict the entry closest to natural expiry.
		var oldestKey modelCooldownKey
		oldestUntil := time.Time{}
		first := true
		for k, v := range cooldownTable {
			if first || v.Until.Before(oldestUntil) {
				oldestKey, oldestUntil, first = k, v.Until, false
			}
		}
		delete(cooldownTable, oldestKey)
	}
	// Never shorten an active window: an earlier, larger hold stays.
	if existing, ok := cooldownTable[modelCooldownKey{AuthID: authID, ModelID: model}]; ok && existing.Until.After(now.Add(ttl)) {
		cooldownMu.Unlock()
		return
	}
	cooldownTable[modelCooldownKey{AuthID: authID, ModelID: model}] = modelCooldownEntry{
		Reason:    reason,
		Until:     now.Add(ttl),
		UpdatedAt: now,
	}
	cooldownMu.Unlock()
}

// modelCoolingUntil reports when the pair becomes usable again (zero time =
// not cooling). Lazy expiry on read.
func modelCoolingUntil(authID, model string) time.Time {
	authID = strings.TrimSpace(authID)
	model = strings.ToLower(strings.TrimSpace(model))
	if authID == "" || model == "" {
		return time.Time{}
	}
	now := cooldownNowFn()
	key := modelCooldownKey{AuthID: authID, ModelID: model}
	cooldownMu.Lock()
	defer cooldownMu.Unlock()
	entry, ok := cooldownTable[key]
	if !ok {
		return time.Time{}
	}
	if !entry.Until.After(now) {
		delete(cooldownTable, key)
		return time.Time{}
	}
	return entry.Until
}

// modelIsCooling reports whether the pair is cooling right now.
func modelIsCooling(authID, model string) bool {
	return !modelCoolingUntil(authID, model).IsZero()
}

// clearModelCooldown removes one pair, or every pair for the account when
// model is empty. Returns how many entries were removed.
func clearModelCooldown(authID, model string) int {
	authID = strings.TrimSpace(authID)
	model = strings.ToLower(strings.TrimSpace(model))
	if authID == "" {
		return 0
	}
	cooldownMu.Lock()
	defer cooldownMu.Unlock()
	removed := 0
	if model != "" {
		key := modelCooldownKey{AuthID: authID, ModelID: model}
		if _, ok := cooldownTable[key]; ok {
			delete(cooldownTable, key)
			removed++
		}
		return removed
	}
	for k := range cooldownTable {
		if k.AuthID == authID {
			delete(cooldownTable, k)
			removed++
		}
	}
	return removed
}

// cooldownSnapshotFor lists the still-active pairs for one account.
func cooldownSnapshotFor(authID string) []map[string]any {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil
	}
	now := cooldownNowFn()
	cooldownMu.Lock()
	out := make([]map[string]any, 0)
	for k, v := range cooldownTable {
		if k.AuthID != authID || !v.Until.After(now) {
			continue
		}
		out = append(out, cooldownEntryView(k, v, now, false))
	}
	cooldownMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		a, _ := out[i]["model"].(string)
		b, _ := out[j]["model"].(string)
		return a < b
	})
	return out
}

// cooldownSnapshotAll lists every active pair across accounts.
func cooldownSnapshotAll() []map[string]any {
	now := cooldownNowFn()
	cooldownMu.Lock()
	out := make([]map[string]any, 0)
	for k, v := range cooldownTable {
		if !v.Until.After(now) {
			continue
		}
		out = append(out, cooldownEntryView(k, v, now, true))
	}
	cooldownMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		a, _ := out[i]["auth_id"].(string)
		b, _ := out[j]["auth_id"].(string)
		if a != b {
			return a < b
		}
		am, _ := out[i]["model"].(string)
		bm, _ := out[j]["model"].(string)
		return am < bm
	})
	return out
}

func cooldownEntryView(k modelCooldownKey, v modelCooldownEntry, now time.Time, withAuth bool) map[string]any {
	row := map[string]any{
		"model":      k.ModelID,
		"reason":     string(v.Reason),
		"until":      v.Until.UTC().Format(time.RFC3339),
		"seconds":    int(v.Until.Sub(now).Round(time.Second) / time.Second),
		"updated_at": v.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if withAuth {
		row["auth_id"] = k.AuthID
	}
	return row
}

// cooldownSweepLocked drops expired entries. Callers must hold cooldownMu.
func cooldownSweepLocked(now time.Time) {
	for k, v := range cooldownTable {
		if !v.Until.After(now) {
			delete(cooldownTable, k)
		}
	}
}

// recordUpstreamFailure routes one upstream failure into the model-scoped
// cooldown table. authID is the host auth id when known ("" = derive from
// sa); model is the upstream model id the request actually used.
func recordUpstreamFailure(authID string, sa *storedAuth, model string, status int, body string) {
	if authID == "" {
		authID = cooldownAuthIDFor(sa)
	}
	model = strings.ToLower(strings.TrimSpace(model))
	if authID == "" || model == "" {
		return
	}
	// 6004 model-scoped rate limit: model_ratelimit.go owns it with the
	// upstream-declared reset; a second, blunter table entry would only
	// fight the precise one.
	if isModelScopedRateLimit(status, body) {
		return
	}
	// Hard credit exhaustion is account-level: the lifecycle/reconcile and
	// statusError envelope paths own it — cooling only the model would
	// UNDER-react (other models on a dead account must not keep firing).
	if isHardCreditError(status, body) {
		return
	}
	if status == http.StatusTooManyRequests || isSoftRateLimit(status, body) {
		markModelCooldown(authID, model, cooldownReasonRateLimit)
		return
	}
	// Empty streams and detected in-stream error frames (the 200-refused
	// family, issue #35's exact shape) rotate the pair briefly. The body is
	// the reliable discriminator — status may be 0 on both paths.
	if isEmptyStreamFailure(body) || isInStreamErrorFailure(body) {
		markModelCooldown(authID, model, cooldownReasonUnknown)
	}
}

// isEmptyStreamFailure matches the emptyStreamError wording (also carried by
// the sync collector's error return).
func isEmptyStreamFailure(body string) bool {
	body = strings.ToLower(strings.TrimSpace(body))
	return strings.Contains(body, "empty_stream") ||
		strings.Contains(body, "stream closed before first payload")
}

// isInStreamErrorFailure matches the workBuddyStreamFrame error family — the
// upstream answered 200 and then refused in-band. This is the honest
// catch-all for quota wordings nobody has captured yet (issue #35's open
// question): rotate the pair for the short unknown window.
func isInStreamErrorFailure(body string) bool {
	body = strings.ToLower(strings.TrimSpace(body))
	return strings.Contains(body, "workbuddy upstream error")
}

// noteModelCooldownFailure is the failure-site hook used by the stream paths
// (pump, collector tail, executor branches). authID may be "" when only the
// stored auth is in scope; the resolver inside falls back to it.
func noteModelCooldownFailure(authID string, sa *storedAuth, model string, status int, body string) {
	recordUpstreamFailure(authID, sa, model, status, body)
}

// modelCooldownError renders the fast-fail error for a pair with an active
// window, or nil. Deliberately plain (no StatusCode() impl): every host
// version must treat it as a transient request-level failure, never as
// credential-level quota — the pair cools, the credential stays healthy.
func modelCooldownError(authID string, sa *storedAuth, model string) error {
	if authID == "" {
		authID = cooldownAuthIDFor(sa)
	}
	until := modelCoolingUntil(authID, model)
	if until.IsZero() {
		return nil
	}
	remaining := int(until.Sub(cooldownNowFn()).Round(time.Second) / time.Second)
	if remaining < 1 {
		remaining = 1
	}
	return &cooldownFastFailError{authID: authID, model: strings.TrimSpace(model), seconds: remaining, until: until}
}

// cooldownFastFailError carries the fields for its message; kept as a type
// so tests can assert on the shape without string-matching the whole copy.
type cooldownFastFailError struct {
	authID  string
	model   string
	seconds int
	until   time.Time
}

func (e *cooldownFastFailError) Error() string {
	return "该 (账号, 模型) 对处于上游失败冷却中——仅此组合暂停约 " + strconv.Itoa(e.seconds) +
		" 秒（至 " + e.until.UTC().Format(time.RFC3339) + "），同账号其他模型与池内其他账号不受影响；期间调度器会自动改用其他候选，无需更换凭证。" +
		" // This (credential, model) pair is cooling after an upstream failure — paused for ~" + strconv.Itoa(e.seconds) +
		"s, other models on the account and other credentials in the pool are unaffected; the scheduler rotates automatically meanwhile."
}

// filterCoolingModels removes models currently cooling for THIS credential
// so the host's built-in scheduler is never offered a degraded (auth, model)
// pair. A credential with no active cooldowns returns the list untouched.
func filterCoolingModels(authID string, models []pluginapi.ModelInfo) []pluginapi.ModelInfo {
	authID = strings.TrimSpace(authID)
	if authID == "" || len(models) == 0 || len(cooldownSnapshotFor(authID)) == 0 {
		return models
	}
	out := make([]pluginapi.ModelInfo, 0, len(models))
	for _, m := range models {
		if modelIsCooling(authID, m.ID) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// handleCooldownList reports every active pair, or one account's pairs when
// auth_id is given. State lives in memory, so the response says so.
func handleCooldownList(req pluginapi.ManagementRequest) map[string]any {
	if vals := req.Query["auth_id"]; len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
		entries := cooldownSnapshotFor(vals[0])
		return map[string]any{
			"entries":    entries,
			"count":      len(entries),
			"persistent": false,
		}
	}
	entries := cooldownSnapshotAll()
	return map[string]any{
		"entries":    entries,
		"count":      len(entries),
		"persistent": false,
	}
}

// handleCooldownClear clears one pair (auth_id + model) or the whole account
// (auth_id only). Panel action: "give this model another chance now".
func handleCooldownClear(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		AuthID string `json:"auth_id"`
		Model  string `json:"model"`
	}
	_ = json.Unmarshal(req.Body, &body)
	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		return map[string]any{"error": "auth_id required"}
	}
	removed := clearModelCooldown(authID, body.Model)
	return map[string]any{"success": true, "removed": removed}
}
