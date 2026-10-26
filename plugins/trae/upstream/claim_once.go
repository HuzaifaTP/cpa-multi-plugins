package upstream

import (
	"sync"
	"time"
)

// claim_once.go — v0.12.81: a claim that answered code:0 is never re-sent the
// same day (magpie trae 0.2.22, 4ac4766, #333/#361 discipline).
//
// Magpie's measured premise (2026-10-25): a claim's own code 0 is not proof
// the day is in — Trae answers code:0 for a claim that registered nothing,
// and code:0 is also the idempotent echo for a day already checked. So
// success is what the STATUS says after the claim, and once a claim has been
// ACCEPTED (code:0), what the read-back says is the day's answer and nothing
// is claimed again for that account that day:
//
//   - a read-back that lags a claim that did land must not multiply claims
//     (magpie: "a claim answered code 0 while the status still says the day
//     is out is the very case that would multiply");
//   - a read-back that fails (network, unreadable) is not a `failed` either —
//     the claim WAS made, so it is ineligible, not to be claimed again.
//
// Multi-claiming one day is exactly the "unusual request patterns" family
// upstream risk control flags (workbuddy 0.9.73's 403+11140 field evidence:
// an account restricted for parallel/unusual request patterns survived on a
// fresh account once the pattern stopped). The same-day registry keeps the
// claim plane to one accepted send per account per metering day.
//
// What still retries today (unchanged, our evidence-based value-add): 9074
// refusals — the server REFUSED to take those claims, so no claim was made;
// the same-day retry ladder with device rotation (v0.12.73) keeps its
// behavior, and magpie's own capture (2026-10-23: the same account and
// headers were taken on a device id Trae had never seen while this
// account's own id answered 9074) is the evidence base for it.
//
// Day key: the UTC+8 metering day (Trae CN's daily reset is the Beijing
// calendar day; the workbuddy plugin's guardrails use the same key
// discipline). In-memory only: a restart re-reads the upstream status —
// which is the authoritative day answer — before any claim, so the worst
// case after a restart is a status read, not a blind re-claim.

var (
	claimOnceMu   sync.Mutex
	claimOnceDay  string
	claimOnceSent = map[string]bool{}
)

// claimOnceClock is the day-key clock (test seam).
var claimOnceClock = time.Now

// claimOnceDayKey renders the UTC+8 calendar day of t.
func claimOnceDayKey(t time.Time) string {
	return t.In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02")
}

// ClaimSentToday reports whether an accepted (code:0) claim was already
// recorded for id on today's UTC+8 metering day.
func ClaimSentToday(id string) bool {
	day := claimOnceDayKey(claimOnceClock())
	claimOnceMu.Lock()
	defer claimOnceMu.Unlock()
	if day != claimOnceDay {
		return false // a new metering day: nothing was sent today
	}
	return claimOnceSent[id]
}

// NoteClaimSent records that an accepted (code:0) claim was sent for id on
// today's UTC+8 metering day.
func NoteClaimSent(id string) {
	day := claimOnceDayKey(claimOnceClock())
	claimOnceMu.Lock()
	defer claimOnceMu.Unlock()
	if day != claimOnceDay {
		claimOnceDay = day
		claimOnceSent = map[string]bool{}
	}
	claimOnceSent[id] = true
}

// ResetClaimOnceForTest clears the registry and clock seam (test seam).
func ResetClaimOnceForTest() {
	claimOnceMu.Lock()
	claimOnceDay = ""
	claimOnceSent = map[string]bool{}
	claimOnceMu.Unlock()
	claimOnceClock = time.Now
}

// ClaimGate is the claim decision for one account this round (pure, for
// testability): a claim fires only when the day is enabled and not yet in,
// AND no accepted claim was already sent today (magpie 0.2.22: once sent,
// the day's answer is the read-back's — the next round is a status read,
// never another claim).
func ClaimGate(checkedIn, enable, claimSentToday bool) bool {
	return enable && !checkedIn && !claimSentToday
}
