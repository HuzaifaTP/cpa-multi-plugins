//go:build live

// trae_live_checkin_test.go — v0.12.77 final-purpose leg (gated by
// TRAE_CHECKIN=1 + TRAE_CRED): perform the REAL daily check-in claim with
// the credential as it stands, and record which face answers.
//
// Why this matters for the per-account identity work: the bound-exchange
// 20403 live evidence (trae_live_rebind_test.go) shows this credential's
// token chain is bound to a server-side device whose keys the credential
// does NOT carry — every renewal therefore falls back to the legacy
// /cloudide path, whose JWT carries no device binding, and the v0.12.73
// finding says the check-in CLAIM answers such tokens with 9074 (while
// status queries stay code:0). This leg decides what to tell the user:
//   - claim succeeds  → the credential is fully functional as-is;
//   - claim 9074s     → the account needs ONE fresh login on v0.12.77+
//     (which registers + binds the per-account derived
//     device) for check-ins to work again.
//
// Run:
//
//	TRAE_CRED=/path/cred.json TRAE_CHECKIN=1 \
//	  go test -tags live -run TestLiveCheckinClaim -v ./plugins/trae
package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/upstream"
)

func TestLiveCheckinClaim(t *testing.T) {
	if strings.TrimSpace(os.Getenv("TRAE_CHECKIN")) != "1" {
		t.Skip("TRAE_CHECKIN != 1 — real check-in claim leg skipped")
	}
	a := liveTraeAuth(t)
	c := upstream.New()

	if cs, err := c.CheckinStatus(a); err != nil {
		t.Logf("pre-claim status FAIL: %v", err)
	} else {
		t.Logf("pre-claim status: checked_in=%v credits=%d extra=%d", cs.CheckedIn, cs.Credits, cs.ExtraCredits)
		if cs.CheckedIn || cs.DidCheckedIn {
			t.Skip("already checked in today — nothing to claim, skip")
		}
	}

	resp, err := c.CheckinClaim(a)
	if err != nil {
		t.Logf("check-in CLAIM refused: %v", err)
		t.Logf("=> if this is 9074「当前参与用户太多」: the token is device-unbound (legacy renewal path).")
		t.Logf("   Fix: ONE fresh panel login on trae v0.12.77+ binds the per-account derived device; bound renewals then claim fine.")
		return
	}
	t.Logf("check-in CLAIM OK: %+v", resp)
	if cs, err := c.CheckinStatus(a); err == nil {
		t.Logf("post-claim status: checked_in=%v credits=%d extra=%d", cs.CheckedIn, cs.Credits, cs.ExtraCredits)
	}
}
