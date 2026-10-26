// identity_switch.go — opt-in 429-triggered outbound-identity family switch
// (#59, design answers 2026-10-25).
//
// The outbound identity family (CLI vs adopted-IDE) is fixed at login time per
// credential; on a 429 the plugin cools the (credential, model) pair and the
// host rotates to another auth. This adds the opt-in lane switch: treat the two
// families' quota lanes as separate lines and, when the account-level 429
// family hits, flip the credential's family so the NEXT requests on it speak
// the other lane.
//
// Design decisions encoded here (mmqz's #59 answer, 2026-10-25):
//
//   - Opt-in, default off: `identity_switch_on_429: true`. The value
//     concentrates in 1–2-account deployments that want to drain every quota
//     lane on the account they have; multi-account pools already have the
//     right ceiling (cool the pair, host rotates).
//   - Sticky, credential-level. Official clients are long-lived identities —
//     holding one family steadily looks more like a real device than
//     oscillating between two. Per-request switching is rejected: it makes the
//     effective cooldown key (credential, model, family) and turns "why is
//     this account slow" into archaeology. Natural switch points: next 429,
//     or next re-login (a fresh login carries no sticky field and resets to
//     the login family).
//   - Persisted alongside the credential record: `identity_family` inside the
//     auth object rides every persistAuthTokens merge, so a restart must not
//     forget which lane is hot. Without an authIndex (hand-built snapshots)
//     there is nowhere to persist — an unpersisted flip would be per-request
//     oscillation, the thing the design rejects, so no-persist means no-switch.
//   - Switch order CLI → IDE → CLI with a per-day cap: hub's
//     MAX_PRODUCT_SWITCHES = 4 parity, but per-credential per-UTC+8-day (the
//     metering day, same day-key machinery as the #61 guardrails) to bound
//     oscillation on accounts that flap.
//   - Whole-family switch, atomically: CLI Stainless set out, IDE
//     CodeBuddyIDE set in (or back) — the families stay internally coherent
//     either way; mixing header families within one request is what the
//     v0.9.69 invariant forbids, and this never mixes.
//
// Scope (conservative, first-implementation): CN-realm credentials only. Both
// families are field-proven on the CN gateway (workbuddy login + CodeBuddyIDE
// adoption speak their own families there); the Intl realm owns its header
// family outright (applyRealmHeaders overrides after the platform headers),
// and the Global realm's proven working shape is the desktop/CLI family
// (#43/#44/#45 conversation-header gates) — switching there would fight
// field-proven gates nobody has captures for. Field reports decide any widening.
package main

import (
	"log"
	"strings"
	"sync"
)

// identitySwitchDailyCap bounds family flips per credential per UTC+8 day.
// Hub's per-request MAX_PRODUCT_SWITCHES = 4 parity, day-scoped: a flapping
// account can burn at most this many lane changes per metering day.
const identitySwitchDailyCap = 4

// Global knob, applied by configure(); false = off.
var (
	identitySwitchMu sync.RWMutex
	identitySwitchOn bool
)

// setIdentitySwitchOn is the test seam (setSchedulerMode shape).
func setIdentitySwitchOn(v bool) func() {
	identitySwitchMu.Lock()
	old := identitySwitchOn
	identitySwitchOn = v
	identitySwitchMu.Unlock()
	return func() { identitySwitchMu.Lock(); identitySwitchOn = old; identitySwitchMu.Unlock() }
}

func identitySwitchEnabled() bool {
	identitySwitchMu.RLock()
	defer identitySwitchMu.RUnlock()
	return identitySwitchOn
}

// switchDayState tracks per-credential switch counts per UTC+8 day, mirroring
// guardDayState's day-key machinery (beijingDayNow).
type switchDayState struct {
	mu       sync.Mutex
	day      string
	switches map[string]int
}

var switchSpend = &switchDayState{switches: map[string]int{}}

// resetSwitchCountForTest clears the counter (test seam).
func resetSwitchCountForTest() {
	switchSpend.mu.Lock()
	switchSpend.day = ""
	switchSpend.switches = map[string]int{}
	switchSpend.mu.Unlock()
}

// takeSwitchBudget consumes one switch slot for authID on today's UTC+8 day;
// false when the daily cap is exhausted (and whether it was newly capped, for
// the once-per-day log line).
func (s *switchDayState) takeSwitchBudget(authID string) (ok bool, newlyCapped bool) {
	day := beijingDayNow()
	s.mu.Lock()
	defer s.mu.Unlock()
	if day != s.day {
		s.day = day
		s.switches = map[string]int{}
	}
	s.switches[authID]++
	if s.switches[authID] > identitySwitchDailyCap {
		return false, s.switches[authID] == identitySwitchDailyCap+1
	}
	return true, false
}

// identityFamilyFor returns the credential's effective outbound family:
// the sticky identity_family field when set, else the login family
// (loginPlatform "ide" → "ide", everything else → "cli").
func identityFamilyFor(sa *storedAuth) string {
	if sa != nil {
		switch strings.ToLower(strings.TrimSpace(sa.Auth.IdentityFamily)) {
		case "cli", "ide":
			return strings.ToLower(strings.TrimSpace(sa.Auth.IdentityFamily))
		}
		if isIDEPlatform(sa.Auth.LoginPlatform) {
			return "ide"
		}
	}
	return "cli"
}

// familyPlatformFor maps the effective family onto the platform vocabulary
// applyPlatformHeaders understands, so the chat plane's family application
// follows the sticky field wherever it goes.
func familyPlatformFor(sa *storedAuth) string {
	if identityFamilyFor(sa) == "ide" {
		return "ide"
	}
	return "CLI"
}

// identitySwitchRealmEligible scopes switching to CN-realm credentials (see
// the file header): Intl owns its header family, Global's proven shape is the
// desktop/CLI family.
func identitySwitchRealmEligible(sa *storedAuth) bool {
	return sa != nil && accountRegion(sa) == "cn"
}

// maybeSwitchIdentityFamily flips the credential's outbound family after an
// account-level 429 (the same rate-limit family that cools the (credential,
// model) pair). Sticky + persisted: the flip writes identity_family into the
// auth record through the standard persistAuthTokens merge, so it survives
// restarts and resets on re-login. Returns the new family, "" when no switch
// happened (knob off / non-CN realm / nowhere to persist / daily cap).
func maybeSwitchIdentityFamily(authID string, sa *storedAuth) string {
	if sa == nil || !identitySwitchEnabled() {
		return ""
	}
	if !identitySwitchRealmEligible(sa) {
		return ""
	}
	if strings.TrimSpace(sa.authIndex) == "" {
		// No host-side identity: hand-built snapshot (tests, pre-persist login
		// flows). An unpersisted flip is per-request oscillation — the exact
		// shape the design rejects. Sticky means persisted or nothing.
		return ""
	}
	cur := identityFamilyFor(sa)
	next := "cli"
	if cur == "cli" {
		next = "ide"
	}
	ok, newlyCapped := switchSpend.takeSwitchBudget(authIDOf(sa, authID))
	if !ok {
		if newlyCapped {
			log.Printf("workbuddy: identity switch (%s): daily cap %d reached — staying on the %s lane for the rest of the UTC+8 day (#59)", authID, identitySwitchDailyCap, cur)
		}
		return ""
	}
	sa.Auth.IdentityFamily = next
	if err := persistAuthTokens(sa.authIndex, sa); err != nil {
		// The persist failed: do not leave an in-memory-only flip riding the
		// caller's snapshot. Revert the field — sticky means persisted, and a
		// lost race for the save funnel is a no-switch, not a half-switch.
		sa.Auth.IdentityFamily = cur
		log.Printf("workbuddy: identity switch (%s): persist failed, staying on the %s lane: %v", authID, cur, err)
		return ""
	}
	log.Printf("workbuddy: identity switch (%s): %s -> %s after a 429 (quota lane change, sticky until next 429 or re-login, %d/%d today) (#59)", authID, cur, next, switchSpend.switches[authID], identitySwitchDailyCap)
	return next
}

// authIDOf prefers the explicit authID and falls back to the cooldown
// resolver's identity derivation (same fallback as recordUpstreamFailure).
func authIDOf(sa *storedAuth, authID string) string {
	if strings.TrimSpace(authID) != "" {
		return strings.TrimSpace(authID)
	}
	return cooldownAuthIDFor(sa)
}
