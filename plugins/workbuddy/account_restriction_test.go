package main

import (
	"strings"
	"testing"
	"time"
)

// v0.9.73 pins: the 403+11140 account restriction ("Your account has been
// restricted due to unusual activity") gets its own classifier, an escalating
// quarantine registry, a pick filter, an executor fast-fail, and bilingual
// actionable copy. Field context: magpie-community/plugins#339 (account
// restricted after PARALLEL requests from two harnesses; the reporter's
// second account survived once they stopped firing concurrently).

const restrictionFieldPayload = `{"code":11140,"msg":"request illegal","requestId":"f2251393-ae99-497b-93d9-a708da9d9b66","displayMsg":{"en":"Your account has been restricted due to unusual activity","zh":"账号存在异常行为"}}`

func TestIsAccountRestrictedClassifier(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		payload string
		want    bool
	}{
		{"field payload 403", 403, restrictionFieldPayload, true},
		{"string-coded 403", 403, `{"code":"11140","msg":"request illegal"}`, true},
		{"non-JSON envelope carrying marker 403", 403, `<html>"code":11140</html>`, true},
		{"11140 on 429 is not the restriction", 429, `{"code":11140}`, false},
		{"11128 channel risk control is not 11140", 403, `{"code":11128,"msg":"unapproved channel"}`, false},
		{"bare 403 WAF shape (no envelope)", 403, `<html>APISIX challenge</html>`, false},
		{"other business 403", 403, `{"code":11133,"msg":"Invalid request parameters"}`, false},
		{"200 with 11140 text", 200, `{"code":11140}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isAccountRestricted(c.status, c.payload); got != c.want {
				t.Fatalf("isAccountRestricted(%d, %q) = %v, want %v", c.status, c.payload, got, c.want)
			}
		})
	}
}

func TestAccountRestrictionBackoffLadder(t *testing.T) {
	reset := func() {
		wbAccountRestrictions.mu.Lock()
		wbAccountRestrictions.entries = map[string]*accountRestrictionEntry{}
		wbAccountRestrictions.mu.Unlock()
	}
	t.Cleanup(reset)
	reset()

	const id = "wb-restricted-test"
	// First strike: 1h. Within the window the credential reports cooling.
	noteAccountRestriction(id, nil)
	until, ok := accountRestrictedUntil(id)
	if !ok {
		t.Fatal("first 11140 must quarantine")
	}
	if d := time.Until(until); d <= 0 || d > time.Hour+time.Minute {
		t.Fatalf("first strike window = %v, want ~1h", d)
	}
	if !accountRestrictionCooling(id) {
		t.Fatal("cooling filter must report true inside the window")
	}
	// Escalation: repeated strikes climb the ladder (2h, 4h) and never
	// shorten.
	for i, want := range []time.Duration{2 * time.Hour, 4 * time.Hour} {
		before, _ := accountRestrictedUntil(id)
		noteAccountRestriction(id, nil)
		after, _ := accountRestrictedUntil(id)
		if !after.After(before) {
			t.Fatalf("strike %d: window shortened (%v -> %v)", i+2, before, after)
		}
		if d := after.Sub(time.Now()); d > want+time.Minute {
			t.Fatalf("strike %d: window %v exceeds ladder %v", i+2, d, want)
		}
	}
	// Cap: strikes beyond the table pin at 8h.
	for i := 0; i < 5; i++ {
		noteAccountRestriction(id, nil)
	}
	until, _ = accountRestrictedUntil(id)
	if d := time.Until(until); d > 8*time.Hour+time.Minute {
		t.Fatalf("capped window = %v, want <= 8h", d)
	}
	// Healthy answer clears state entirely — and a later re-restriction
	// starts over at the first rung.
	noteAccountHealthy(id, nil)
	if _, ok := accountRestrictedUntil(id); ok {
		t.Fatal("healthy answer must clear the quarantine")
	}
	noteAccountRestriction(id, nil)
	until, _ = accountRestrictedUntil(id)
	if d := time.Until(until); d > time.Hour+time.Minute {
		t.Fatalf("post-recovery strike window = %v, want first rung ~1h", d)
	}
}

func TestNoteAccountRestrictionFromPayloadNoOpForOthers(t *testing.T) {
	reset := func() {
		wbAccountRestrictions.mu.Lock()
		wbAccountRestrictions.entries = map[string]*accountRestrictionEntry{}
		wbAccountRestrictions.mu.Unlock()
	}
	t.Cleanup(reset)
	reset()

	// The hook is a no-op for every non-11140 shape (including the 11133
	// payload from issue #63 and plain 429s) and for empty credentials.
	noteAccountRestrictionFromPayload("wb-x", nil, 400, `{"code":11133,"msg":"Invalid request parameters"}`)
	noteAccountRestrictionFromPayload("wb-x", nil, 429, `{"code":6004,"msg":"您的使用量已超出频率限制"}`)
	noteAccountRestrictionFromPayload("", nil, 403, restrictionFieldPayload) // no resolvable id
	if restrictionQuarantineCount() != 0 {
		t.Fatalf("non-11140 / unresolvable-id hooks must not quarantine (count=%d)", restrictionQuarantineCount())
	}
	// The real payload quarantines.
	noteAccountRestrictionFromPayload("wb-x", nil, 403, restrictionFieldPayload)
	if !accountRestrictionCooling("wb-x") {
		t.Fatal("403+11140 must quarantine via the payload hook")
	}
}

func TestAccountRestrictionErrorCopyIsPlainAndActionable(t *testing.T) {
	reset := func() {
		wbAccountRestrictions.mu.Lock()
		wbAccountRestrictions.entries = map[string]*accountRestrictionEntry{}
		wbAccountRestrictions.mu.Unlock()
	}
	t.Cleanup(reset)
	reset()

	if err := accountRestrictionError("wb-copy", nil); err != nil {
		t.Fatal("no quarantine -> no fast-fail error")
	}
	noteAccountRestriction("wb-copy", nil)
	err := accountRestrictionError("wb-copy", nil)
	if err == nil {
		t.Fatal("quarantined credential must fast-fail")
	}
	// Plain-error discipline: no StatusCode, so no host version can read the
	// fast-fail as credential-level quota.
	var sc interface{ StatusCode() int }
	if ok := asStatusCode(err, &sc); ok {
		t.Fatal("fast-fail must stay a plain error (no StatusCode impl)")
	}
	msg := err.Error()
	for _, want := range []string{"11140", "account_max_concurrent", "官方客户端", "official client"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("fast-fail copy missing %q: %s", want, msg)
		}
	}
	// The translated upstream error carries the same guidance.
	full := translateChatUpstreamErrorFull(403, restrictionFieldPayload, nil, nil)
	for _, want := range []string{"11140", "account_max_concurrent", "raw:"} {
		if !strings.Contains(full.Error(), want) {
			t.Fatalf("translated copy missing %q: %s", want, full.Error())
		}
	}
}

func asStatusCode(err error, target *interface{ StatusCode() int }) bool {
	if sc, ok := err.(interface{ StatusCode() int }); ok {
		*target = sc
		return true
	}
	return false
}

func TestSchedulerPickSkipsQuarantinedCredential(t *testing.T) {
	reset := func() {
		wbAccountRestrictions.mu.Lock()
		wbAccountRestrictions.entries = map[string]*accountRestrictionEntry{}
		wbAccountRestrictions.mu.Unlock()
	}
	t.Cleanup(reset)
	reset()

	// Clean slate sanity: nothing is cooling yet.
	if accountRestrictionCooling("wb-noted") {
		t.Fatal("test requires a clean registry")
	}
	noteAccountRestriction("wb-noted", nil)
	if accountRestrictionCooling("wb-healthy") {
		t.Fatal("healthy credential must not be cooling")
	}
	if !accountRestrictionCooling("wb-noted") {
		t.Fatal("restricted credential must be cooling")
	}
}
