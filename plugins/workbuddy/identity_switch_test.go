package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// identitySwitchTestAuth builds a CN-realm CLI-login credential with a host
// authIndex (the executor shape) for switch tests.
func identitySwitchTestAuth(authIndex string) *storedAuth {
	sa := &storedAuth{
		Auth:    storedTokens{AccessToken: "tok", Domain: "www.codebuddy.cn"},
		Account: storedAccount{UID: "uid-sw"},
	}
	sa.authIndex = authIndex
	return sa
}

// sealSwitchSeams turns the knob on, resets the daily counter, and freezes
// the day key; returns a restore func.
func sealSwitchSeams(day string) func() {
	restoreKnob := setIdentitySwitchOn(true)
	resetSwitchCountForTest()
	realDay := beijingDayNow
	beijingDayNow = func() string { return day }
	return func() {
		beijingDayNow = realDay
		resetSwitchCountForTest()
		restoreKnob()
	}
}

// TestIdentitySwitchDisabledByDefault — the knob ships off: a 429 must not
// flip anything, byte-for-byte old behavior.
func TestIdentitySwitchDisabledByDefault(t *testing.T) {
	restoreKnob := setIdentitySwitchOn(false)
	defer restoreKnob()
	resetSwitchCountForTest()
	defer resetSwitchCountForTest()

	sa := identitySwitchTestAuth("0")
	recordUpstreamFailure("sw-off", sa, "deepseek-v4", http.StatusTooManyRequests, `{"code":1000}`)
	if sa.Auth.IdentityFamily != "" {
		t.Fatalf("family must stay untouched with the knob off, got %q", sa.Auth.IdentityFamily)
	}
	if identityFamilyFor(sa) != "cli" {
		t.Fatalf("effective family must stay cli, got %q", identityFamilyFor(sa))
	}
}

// TestIdentitySwitchOn429FlipsCLItoIDE — the happy lane change: an opt-in
// 429 on a CN CLI-family credential flips to the IDE family and persists the
// sticky field through the standard merge.
func TestIdentitySwitchOn429FlipsCLItoIDE(t *testing.T) {
	restoreSeams := sealSwitchSeams("2026-10-26")
	defer restoreSeams()

	doc := `{"type":"workbuddy","auth":{"accessToken":"tok","domain":"www.codebuddy.cn"},"account":{"uid":"uid-sw"}}`
	restorePersist := stubPersistSeams(t, map[string][]byte{"0": []byte(doc)})
	defer restorePersist()

	sa := identitySwitchTestAuth("0")
	recordUpstreamFailure("sw-1", sa, "deepseek-v4", http.StatusTooManyRequests, `{"code":1000}`)
	if sa.Auth.IdentityFamily != "ide" {
		t.Fatalf("429 must flip CLI -> ide, got %q", sa.Auth.IdentityFamily)
	}
	if identityFamilyFor(sa) != "ide" {
		t.Fatalf("effective family must be ide after the flip")
	}
	if len(capturedSaves) == 0 {
		t.Fatal("the switch must persist identity_family through host save")
	}
	var saved map[string]any
	if err := json.Unmarshal([]byte(capturedSaves[len(capturedSaves)-1][strings.Index(capturedSaves[len(capturedSaves)-1], "=")+1:]), &saved); err != nil {
		t.Fatalf("saved doc unreadable: %v", err)
	}
	authObj, _ := saved["auth"].(map[string]any)
	if authObj == nil || authObj["identity_family"] != "ide" {
		t.Fatalf("persisted auth.identity_family must read ide, got %v", saved["auth"])
	}
}

// TestIdentitySwitchIDEtoCLI — the toggle order CLI -> IDE -> CLI: a second
// 429 (same day, budget remaining) flips back. Pinned on an IDE-login
// credential the other direction too.
func TestIdentitySwitchIDEtoCLI(t *testing.T) {
	restoreSeams := sealSwitchSeams("2026-10-26")
	defer restoreSeams()

	doc := `{"type":"workbuddy","auth":{"accessToken":"tok","domain":"www.codebuddy.cn","loginPlatform":"ide","identity_family":"ide"},"account":{"uid":"uid-sw"}}`
	restorePersist := stubPersistSeams(t, map[string][]byte{"0": []byte(doc)})
	defer restorePersist()

	sa := identitySwitchTestAuth("0")
	sa.Auth.LoginPlatform = "ide"
	sa.Auth.IdentityFamily = "ide"
	recordUpstreamFailure("sw-2", sa, "deepseek-v4", http.StatusTooManyRequests, `{"code":1000}`)
	if sa.Auth.IdentityFamily != "cli" {
		t.Fatalf("second 429 must flip ide -> cli, got %q", sa.Auth.IdentityFamily)
	}
	if identityFamilyFor(sa) != "cli" {
		t.Fatalf("effective family must be cli after the flip back")
	}
}

// TestIdentitySwitchDailyCap — hub's MAX_PRODUCT_SWITCHES=4 parity, day-scoped:
// the fifth flip attempt in one UTC+8 day is refused, and the day rollover
// resets the budget.
func TestIdentitySwitchDailyCap(t *testing.T) {
	restoreSeams := sealSwitchSeams("2026-10-26")
	defer restoreSeams()

	doc := `{"type":"workbuddy","auth":{"accessToken":"tok","domain":"www.codebuddy.cn"},"account":{"uid":"uid-sw"}}`
	restorePersist := stubPersistSeams(t, map[string][]byte{"0": []byte(doc)})
	defer restorePersist()

	sa := identitySwitchTestAuth("0")
	for i := 0; i < identitySwitchDailyCap; i++ {
		if got := maybeSwitchIdentityFamily("sw-cap", sa); got == "" {
			t.Fatalf("flip %d must be allowed", i+1)
		}
	}
	if got := maybeSwitchIdentityFamily("sw-cap", sa); got != "" {
		t.Fatalf("flip %d must hit the daily cap, got %q", identitySwitchDailyCap+1, got)
	}
	// Day rollover resets the budget (new UTC+8 day key).
	beijingDayNow = func() string { return "2026-10-27" }
	if got := maybeSwitchIdentityFamily("sw-cap", sa); got == "" {
		t.Fatal("the next UTC+8 day must reset the switch budget")
	}
}

// TestIdentitySwitchRealmScope — Global and Intl credentials never switch:
// Global's proven shape is the desktop/CLI family, Intl owns its header
// family outright (applyRealmHeaders).
func TestIdentitySwitchRealmScope(t *testing.T) {
	restoreSeams := sealSwitchSeams("2026-10-26")
	defer restoreSeams()

	for _, domain := range []string{"www.workbuddy.ai", "www.codebuddy.ai"} {
		sa := identitySwitchTestAuth("0")
		sa.Auth.Domain = domain
		if got := maybeSwitchIdentityFamily("sw-realm-"+domain, sa); got != "" {
			t.Fatalf("%s credential must never switch, got %q", domain, got)
		}
		if sa.Auth.IdentityFamily != "" {
			t.Fatalf("%s family field must stay untouched, got %q", domain, sa.Auth.IdentityFamily)
		}
	}
}

// TestIdentitySwitchNoAuthIndexNoSwitch — sticky means persisted or nothing:
// a hand-built snapshot without a host identity has nowhere to persist the
// flip, and an unpersisted flip is per-request oscillation (the rejected
// shape). No authIndex = no switch.
func TestIdentitySwitchNoAuthIndexNoSwitch(t *testing.T) {
	restoreSeams := sealSwitchSeams("2026-10-26")
	defer restoreSeams()

	sa := identitySwitchTestAuth("")
	if got := maybeSwitchIdentityFamily("sw-noindex", sa); got != "" {
		t.Fatalf("snapshot without authIndex must not switch, got %q", got)
	}
	if sa.Auth.IdentityFamily != "" {
		t.Fatalf("snapshot family must stay untouched, got %q", sa.Auth.IdentityFamily)
	}
}

// TestIdentityFamilyHeadersCoherence — the whole-family switch, atomically:
// a CLI-login credential flipped to ide speaks the CodeBuddyIDE X-IDE set and
// drops the Stainless family; an IDE-login credential flipped to cli gains
// the WorkBuddy trio plus Stainless. Never mixed.
func TestIdentityFamilyHeadersCoherence(t *testing.T) {
	build := func(sa *storedAuth) http.Header {
		req := httptest.NewRequest(http.MethodPost, "https://www.codebuddy.cn/v2/chat/completions", nil)
		backendHeaders(req, sa)
		return req.Header
	}

	cliFlippedToIDE := identitySwitchTestAuth("")
	cliFlippedToIDE.Auth.IdentityFamily = "ide"
	h := build(cliFlippedToIDE)
	if h.Get("X-IDE-Type") != "CodeBuddyIDE" {
		t.Fatalf("switched-to-IDE credential must speak CodeBuddyIDE, got %q", h.Get("X-IDE-Type"))
	}
	if h.Get("X-Stainless-Lang") != "" {
		t.Fatal("switched-to-IDE credential must drop the CLI Stainless set")
	}

	ideFlippedToCLI := identitySwitchTestAuth("")
	ideFlippedToCLI.Auth.LoginPlatform = "ide"
	ideFlippedToCLI.Auth.IdentityFamily = "cli"
	h = build(ideFlippedToCLI)
	if h.Get("X-IDE-Name") != "WorkBuddy" {
		t.Fatalf("switched-to-CLI credential must speak the WorkBuddy trio, got %q", h.Get("X-IDE-Name"))
	}
	if h.Get("X-Stainless-Lang") == "" {
		t.Fatal("switched-to-CLI credential must gain the Stainless family")
	}

	// Login families unchanged when no switch has ever fired.
	h = build(identitySwitchTestAuth(""))
	if h.Get("X-IDE-Name") != "WorkBuddy" || h.Get("X-Stainless-Lang") == "" {
		t.Fatal("plain CLI credential keeps the CLI family")
	}
	plainIDE := identitySwitchTestAuth("")
	plainIDE.Auth.LoginPlatform = "ide"
	h = build(plainIDE)
	if h.Get("X-IDE-Type") != "CodeBuddyIDE" || h.Get("X-Stainless-Lang") != "" {
		t.Fatal("plain IDE credential keeps the IDE family")
	}
}

// TestIdentityFamilyStickySurvivesRefreshMerge — the sticky field rides every
// persistAuthTokens merge (a token refresh must not forget the lane), and a
// fresh login (no field) resets to the login family.
func TestIdentityFamilyStickySurvivesRefreshMerge(t *testing.T) {
	doc := []byte(`{"type":"workbuddy","proxy_url":"http://panel-managed","auth":{"accessToken":"old","domain":"www.codebuddy.cn","identity_family":"ide"},"account":{"uid":"uid-sw"}}`)
	sa := identitySwitchTestAuth("0")
	sa.Auth.IdentityFamily = "ide"
	sa.Auth.AccessToken = "fresh"
	raw, err := mergeStoredAuthIntoDoc(doc, sa)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var merged map[string]any
	if err := json.Unmarshal(raw, &merged); err != nil {
		t.Fatalf("merged doc unreadable: %v", err)
	}
	if merged["proxy_url"] != "http://panel-managed" {
		t.Fatal("merge must preserve panel-managed top-level fields")
	}
	authObj, _ := merged["auth"].(map[string]any)
	if authObj == nil || authObj["identity_family"] != "ide" {
		t.Fatalf("sticky identity_family must survive the refresh merge, got %v", merged["auth"])
	}
	if authObj["accessToken"] != "fresh" {
		t.Fatal("the refreshed token must also land")
	}
	// A fresh login (no identity_family written) resets to the login family.
	fresh := &storedAuth{Auth: storedTokens{AccessToken: "fresh", Domain: "www.codebuddy.cn"}}
	if identityFamilyFor(fresh) != "cli" {
		t.Fatalf("fresh CLI login must speak cli, got %q", identityFamilyFor(fresh))
	}
}

// TestIdentitySwitch6004NotATrigger — a model-scoped 6004 (429 + code 6004)
// must NOT flip the lane: it is keyed (credential, model) with its own
// precise registry; flipping an account-scoped lane on a per-model limit is
// exactly the over-reach the design rejects.
func TestIdentitySwitch6004NotATrigger(t *testing.T) {
	restoreSeams := sealSwitchSeams("2026-10-26")
	defer restoreSeams()

	doc := `{"type":"workbuddy","auth":{"accessToken":"tok","domain":"www.codebuddy.cn"},"account":{"uid":"uid-sw"}}`
	restorePersist := stubPersistSeams(t, map[string][]byte{"0": []byte(doc)})
	defer restorePersist()

	sa := identitySwitchTestAuth("0")
	recordUpstreamFailure("sw-6004", sa, "deepseek-v4", http.StatusTooManyRequests, `{"code":6004,"msg":"rate limited","data":{"rate_limit_reset_at":"2026-10-26 12:00:00"}}`)
	if sa.Auth.IdentityFamily != "" {
		t.Fatalf("6004 model-scoped limit must not flip the lane, got %q", sa.Auth.IdentityFamily)
	}
}

// TestConfigureIdentitySwitchKnob — the config line form applies the knob
// (and reconfigure can turn it back off).
func TestConfigureIdentitySwitchKnob(t *testing.T) {
	restoreKnob := setIdentitySwitchOn(false)
	defer restoreKnob()

	wbConfigureWire(t, "identity_switch_on_429: true\n")
	if !identitySwitchEnabled() {
		t.Fatal("identity_switch_on_429: true must enable the knob")
	}
	wbConfigureWire(t, "identity_switch_on_429: false\n")
	if identitySwitchEnabled() {
		t.Fatal("identity_switch_on_429: false must disable the knob")
	}
	wbConfigureWire(t, "stream_head_timeout: 3\n")
	if identitySwitchEnabled() {
		t.Fatal("reconfigure without the knob must reset to default off")
	}
}
