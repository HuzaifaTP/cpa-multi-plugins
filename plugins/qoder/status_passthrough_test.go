package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestErrorEnvelopeForCarriesStatus(t *testing.T) {
	raw := errorEnvelopeFor(&statusError{status: http.StatusTooManyRequests, err: errors.New("upstream 429: quota")})
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.OK || env.Error == nil {
		t.Fatalf("expected error envelope, got ok=%v", env.OK)
	}
	if env.Error.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("http_status = %d, want 429", env.Error.HTTPStatus)
	}
}

func TestErrorEnvelopeForPlainErrorOmitsStatus(t *testing.T) {
	raw := errorEnvelopeFor(errors.New("plain failure"))
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error == nil || env.Error.HTTPStatus != 0 {
		t.Fatalf("expected http_status omitted, got %+v", env.Error)
	}
}

// TestUpstreamStatusErrorPolicy locks the 0.8.13 matrix: only 401/402/429
// pass their status to the host cooldown layer; everything else (413/input
// too large, 403, 5xx) stays status-less — request-level or unevidenced
// shapes must not cool the credential beyond the historical default.
func TestUpstreamStatusErrorPolicy(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   int
	}{
		{"402 payment", 402, 402},
		{"401 dead token", 401, 401},
		{"429 free quota drained", 429, 429},
		{"413 input too large", 413, 0},
		{"403 unknown shape", 403, 0},
		{"400 business", 400, 0},
		{"500 server", 500, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := errors.New("translated")
			err := upstreamStatusError(tc.status, base)
			var se *statusError
			if tc.want == 0 {
				if errors.As(err, &se) {
					t.Fatalf("status %d: expected plain error, got statusError{%d}", tc.status, se.status)
				}
				if !errors.Is(err, base) {
					t.Fatalf("plain error must wrap base")
				}
				return
			}
			if !errors.As(err, &se) {
				t.Fatalf("status %d: expected statusError", tc.status)
			}
			if se.status != tc.want {
				t.Fatalf("status = %d, want %d", se.status, tc.want)
			}
		})
	}
}

// TestNextCheckinTimeSkipsBeforeOpeningHour guards the 10:00 opening-hour
// fix: from 09:59 the next auto tick must be 10:00, never the stale 09:00.
// v0.8.66: the window anchor (10:05 UTC+8) also lands today from 09:59 local
// in a UTC+8-local host, so the expectation is unchanged there; in other
// zones the anchor covers the round-open regardless.
func TestNextCheckinTimeSkipsBeforeOpeningHour(t *testing.T) {
	loc := time.Local
	now := time.Date(2026, 9, 20, 9, 59, 0, 0, loc)
	next := nextCheckinTime(now)
	if next.Hour() != 10 || next.Day() != now.Day() {
		t.Fatalf("next = %s, want today 10:00", next)
	}
}

// TestNextCheckinTimeWindowAnchor pins the v0.8.66 window-anchored tick:
// whatever timezone the container runs, nextCheckinTime must consider the
// next 10:05 UTC+8 instant (the round-open timezone itself). This is the fix
// for the Docker default-UTC deployment where "local 10:00" fired at 18:00
// Beijing — 8 hours into the first-come-first-served stock window.
func TestNextCheckinTimeWindowAnchor(t *testing.T) {
	bj := time.FixedZone("UTC+8", 8*3600)
	// Beijing 2026-10-22 09:00 → anchor today 10:05 BJ must be reachable.
	bjNow := time.Date(2026, 10, 22, 9, 0, 0, 0, bj)
	anchor := nextWindowAnchorTime(bjNow)
	if want := time.Date(2026, 10, 22, 10, 5, 0, 0, bj); !anchor.Equal(want) {
		t.Fatalf("anchor from bj 09:00 = %s, want %s", anchor, want)
	}
	// Same instant expressed in UTC (01:00) and New York (prev-day 21:00):
	// the anchor must be the same absolute moment.
	for name, loc := range map[string]*time.Location{
		"utc":      time.UTC,
		"new-york": time.FixedZone("UTC-4", -4*3600),
	} {
		got := nextWindowAnchorTime(bjNow.In(loc))
		if !got.Equal(anchor) {
			t.Errorf("%s: anchor = %s, want the same instant as %s", name, got, anchor)
		}
	}
	// nextCheckinTime unions the anchor with local slots: from Beijing 09:00
	// the earliest is the local 10:00 tick (before the 10:05 anchor).
	next := nextCheckinTime(bjNow)
	if next.Hour() != 10 || next.Minute() != 0 {
		t.Fatalf("next = %s, want local 10:00 (earlier than the 10:05 anchor)", next)
	}
}

// TestNextWindowAnchorTimeCrossesMidnight: from Beijing 10:06 (anchor passed)
// the next anchor is tomorrow 10:05 — expressed as UTC 02:05 next day.
func TestNextWindowAnchorTimeCrossesMidnight(t *testing.T) {
	now := time.Date(2026, 10, 22, 2, 6, 0, 0, time.UTC) // = Beijing 10:06
	next := nextWindowAnchorTime(now)
	want := time.Date(2026, 10, 23, 2, 5, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("nextWindowAnchorTime(%s) = %s, want %s", now, next, want)
	}
}

// TestNextWindowAnchorTimeBeforeOpen: from Beijing 09:59 the anchor is today.
func TestNextWindowAnchorTimeBeforeOpen(t *testing.T) {
	now := time.Date(2026, 10, 22, 1, 59, 0, 0, time.UTC) // = Beijing 09:59
	next := nextWindowAnchorTime(now)
	want := time.Date(2026, 10, 22, 2, 5, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("nextWindowAnchorTime(%s) = %s, want %s", now, next, want)
	}
}

// TestLabelForAuthRegionTag: intl accounts must render [Intl] (v0.8.66 —
// the tag was a hardcoded [CN] tautology from the pre-merge plugin era, so
// every intl account was mislabeled in the host's auth list).
func TestLabelForAuthRegionTag(t *testing.T) {
	intl := &storedAuth{
		Auth:    storedTokens{Region: "intl", Domain: "qoder.com"},
		Account: storedAccount{UID: "u1", Nickname: "tester"},
	}
	if got := labelForAuth(intl); got != "tester [Intl]" {
		t.Fatalf("intl label = %q, want %q", got, "tester [Intl]")
	}
	cn := &storedAuth{
		Auth:    storedTokens{Region: "cn", Domain: "qoder.com.cn"},
		Account: storedAccount{UID: "u2", Nickname: "tester"},
	}
	if got := labelForAuth(cn); got != "tester [CN]" {
		t.Fatalf("cn label = %q, want %q", got, "tester [CN]")
	}
	// Legacy file without an explicit region: domain sniffing must still tag intl.
	legacyIntl := &storedAuth{
		Auth:    storedTokens{Domain: "qoder.sh"},
		Account: storedAccount{UID: "u3", Nickname: "legacy"},
	}
	if got := labelForAuth(legacyIntl); got != "legacy [Intl]" {
		t.Fatalf("legacy intl label = %q, want %q", got, "legacy [Intl]")
	}
}

// TestScheduleSummary: the panel schedule field now reflects the real cadence
// (window anchor + local hours) instead of the stale hardcoded 09:00/21:00.
func TestScheduleSummary(t *testing.T) {
	got := scheduleSummary()
	if len(got) != 1+len(checkinHours) {
		t.Fatalf("scheduleSummary len = %d, want 1 anchor + %d local slots: %v", len(got), len(checkinHours), got)
	}
	if !strings.Contains(got[0], "UTC+8") || !strings.Contains(got[0], "10:05") {
		t.Fatalf("anchor slot = %q, want 10:05 UTC+8 wording", got[0])
	}
	for i, h := range checkinHours {
		want := fmt.Sprintf("%02d:00", h)
		if !strings.Contains(got[i+1], want) {
			t.Fatalf("local slot %d = %q, want to contain %q", i+1, got[i+1], want)
		}
	}
}

// TestUmidRegistryURLFromEnv: QD_UMID_REGISTRY mirror override (v0.8.66 —
// escape hatch for Docker deployments whose network cannot reach npmjs).
// v0.8.67: the value is a registry BASE; the region's package path is
// appended by umidPackageDocURL (intl @qoder-ai/qodercli, cn
// @qodercn-ai/qoderclicn).
func TestUmidRegistryURLFromEnv(t *testing.T) {
	cases := []struct {
		name, env, want string
	}{
		{"empty-keeps-default", "", umidRegistryBaseDefault},
		{"mirror", "https://registry.npmmirror.com", "https://registry.npmmirror.com"},
		{"trailing-slash-trimmed", "https://registry.npmmirror.com/", "https://registry.npmmirror.com"},
		{"scheme-inferred", "registry.npmmirror.com", "https://registry.npmmirror.com"},
		{"spaces-trimmed", "  https://registry.npmmirror.com  ", "https://registry.npmmirror.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("QD_UMID_REGISTRY", c.env)
			if got := umidRegistryURLFromEnv(); got != c.want {
				t.Fatalf("umidRegistryURLFromEnv() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestUmidPackageDocURLRegionSplit (v0.8.67, magpie 0.2.30): each region
// provisions its OWN npm package — CN from @qodercn-ai/qoderclicn (Qoder
// CN's CLI), intl from @qoder-ai/qodercli — both reachable through the same
// QD_UMID_REGISTRY mirror base.
func TestUmidPackageDocURLRegionSplit(t *testing.T) {
	base := "https://registry.example.com"
	prev := umidRegistryURL
	umidRegistryURL = base
	defer func() { umidRegistryURL = prev }()
	if got := umidPackageDocURL(regionCN); got != base+umidPkgCN {
		t.Fatalf("umidPackageDocURL(cn) = %q, want %q", got, base+umidPkgCN)
	}
	if got := umidPackageDocURL(regionIntl); got != base+umidPkgIntl {
		t.Fatalf("umidPackageDocURL(intl) = %q, want %q", got, base+umidPkgIntl)
	}
	if got := umidPackageDocURL("global"); got != base+umidPkgIntl {
		t.Fatalf("umidPackageDocURL(global) = %q, want the intl package (normalizeRegion alias)", got)
	}
}
