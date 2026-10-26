package upstream

import (
	"testing"
	"time"
)

// claimOnceFrozenDay freezes the day-key clock at the given UTC+8 date and
// returns a restore func.
func claimOnceFrozenDay(day string) func() {
	orig := claimOnceClock
	t, err := time.Parse(time.RFC3339, day+"T12:00:00+08:00")
	if err != nil {
		panic(err)
	}
	claimOnceClock = func() time.Time { return t }
	return func() { claimOnceClock = orig }
}

// TestClaimOnceRegistry — the magpie 0.2.22 discipline's storage: an accepted
// (code:0) claim is recorded per account per UTC+8 metering day; a new day
// starts clean; a restart (registry reset) starts clean too because the
// status re-read is the authoritative day answer before any claim.
func TestClaimOnceRegistry(t *testing.T) {
	ResetClaimOnceForTest()
	restore := claimOnceFrozenDay("2026-10-26")
	defer restore()

	if ClaimSentToday("uid-a") {
		t.Fatal("nothing sent yet")
	}
	NoteClaimSent("uid-a")
	if !ClaimSentToday("uid-a") {
		t.Fatal("uid-a's accepted claim must be recorded for today")
	}
	if ClaimSentToday("uid-b") {
		t.Fatal("the registry is per-account: uid-b has sent nothing")
	}

	// Same UTC+8 day, later hour — still recorded.
	t2, _ := time.Parse(time.RFC3339, "2026-10-26T23:30:00+08:00")
	claimOnceClock = func() time.Time { return t2 }
	if !ClaimSentToday("uid-a") {
		t.Fatal("still the same UTC+8 day: the claim must stand")
	}

	// Day rollover (UTC+8 midnight) — the new metering day starts clean.
	t3, _ := time.Parse(time.RFC3339, "2026-10-27T00:05:00+08:00")
	claimOnceClock = func() time.Time { return t3 }
	if ClaimSentToday("uid-a") {
		t.Fatal("a new UTC+8 metering day must start clean")
	}

	// The UTC+8 boundary itself: 2026-10-26 23:59 CST vs 2026-10-27 00:00 CST.
	t4, _ := time.Parse(time.RFC3339, "2026-10-26T15:59:00Z") // 23:59 UTC+8
	claimOnceClock = func() time.Time { return t4 }
	ResetClaimOnceForTest()
	NoteClaimSent("uid-boundary")
	t5, _ := time.Parse(time.RFC3339, "2026-10-26T16:01:00Z") // 00:01 UTC+8 next day
	claimOnceClock = func() time.Time { return t5 }
	if ClaimSentToday("uid-boundary") {
		t.Fatal("crossing UTC+8 midnight must roll the metering day")
	}
	ResetClaimOnceForTest()
}

// TestClaimGate — the claim decision's truth table (magpie trae 0.2.22):
// a claim fires only when the day is enabled, not yet checked, and no
// accepted claim was already sent today.
func TestClaimGate(t *testing.T) {
	cases := []struct {
		name                    string
		checkedIn, enable, sent bool
		want                    bool
	}{
		{"plain day: claim", false, true, false, true},
		{"already checked: read-only", true, true, false, false},
		{"disabled upstream: nothing", false, false, false, false},
		{"accepted claim already sent today: read-only (magpie 0.2.22)", false, true, true, false},
		{"sent + checked: read-only", true, true, true, false},
		{"sent + disabled: nothing", false, false, true, false},
	}
	for _, c := range cases {
		if got := ClaimGate(c.checkedIn, c.enable, c.sent); got != c.want {
			t.Errorf("%s: ClaimGate(checkedIn=%v, enable=%v, sent=%v) = %v, want %v", c.name, c.checkedIn, c.enable, c.sent, got, c.want)
		}
	}
}

// TestClaimOnceRegistryRestart — a restart (in-memory registry reset) starts
// clean: the status re-read upstream is the authoritative day answer, so the
// first round after a restart is a status read, and a claim only re-fires if
// the day is genuinely still out (registry empty ⇒ gate open).
func TestClaimOnceRegistryRestart(t *testing.T) {
	ResetClaimOnceForTest()
	defer ResetClaimOnceForTest()
	restore := claimOnceFrozenDay("2026-10-26")
	defer restore()

	NoteClaimSent("uid-r")
	if !ClaimSentToday("uid-r") {
		t.Fatal("sent before restart")
	}
	ResetClaimOnceForTest() // simulate a plugin restart
	if ClaimSentToday("uid-r") {
		t.Fatal("after a restart the registry is clean — the status re-read decides")
	}
	if !ClaimGate(false, true, ClaimSentToday("uid-r")) {
		t.Fatal("gate must be open after restart when the day is genuinely out")
	}
}
