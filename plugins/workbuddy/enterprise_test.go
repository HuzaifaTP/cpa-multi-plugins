// enterprise_test.go pins the v0.9.67 enterprise-account plane (issue #55):
//
//   - an enterprise account whose personal meter answers 200 + empty data
//     falls back to /billing/meter/get-enterprise-user-usage and surfaces a
//     synthetic refill-cycle summary (remain > 0 → panel stops reading
//     "余0 已用0", and shouldReenableCN can re-enable a disabled account);
//   - a personal account's empty personal result never touches the
//     enterprise plane;
//   - both planes empty/down reads as unknown (an error), never a zero
//     summary masquerading as exhaustion;
//   - the manual check-in press is short-circuited with the reason instead
//     of the doomed 400/10001 round trip;
//   - the plan reads "enterprise", not the personal ladder's "free".
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// enterpriseTestAuth returns an enterprise-space CN storedAuth.
func enterpriseTestAuth() *storedAuth {
	return &storedAuth{
		Auth:    storedTokens{AccessToken: "test-token"},
		Account: storedAccount{UID: "uid-ent", EnterpriseID: "fysxmvfpz6dc"},
	}
}

// personalEmptyJSON is the reporter's live capture of the personal meter
// plane on an enterprise account: HTTP 200, code 0, and no data at all.
const personalEmptyJSON = `{"code":0,"msg":"OK","data":{"Response":{"Data":{"TotalCount":0,"TotalDosage":0,"Accounts":null}}}}`

// enterpriseUsageJSON mirrors the reporter's live capture of the enterprise
// meter plane (education-public-welfare space, 2000-credit cycle).
const enterpriseUsageJSON = `{"credit":4.11,"limitNum":2000,"cycleStartTime":"2026-10-01 00:00:00","cycleEndTime":"2026-10-31 23:59:59","cycleResetTime":"2026-11-01 00:00:00"}`

// TestFetchUserResourceEnterpriseFallback is the issue's headline scenario.
func TestFetchUserResourceEnterpriseFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/billing/meter/get-user-resource":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(personalEmptyJSON))
		case "/billing/meter/get-enterprise-user-usage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":` + enterpriseUsageJSON + `}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	restore := setBillingBase(srv.URL)
	defer restore()

	cr, err := fetchUserResource(enterpriseTestAuth())
	if err != nil {
		t.Fatalf("fetchUserResource: %v", err)
	}
	if cr == nil {
		t.Fatal("nil summary")
	}
	// credit 4.11 → used 4 (int64 fold), remain 2000-4 = 1996, size 2000.
	if cr.TotalUsed != 4 || cr.TotalSize != 2000 {
		t.Fatalf("totals: used=%d size=%d", cr.TotalUsed, cr.TotalSize)
	}
	if cr.TotalRemain != 1996 {
		t.Fatalf("remain: %d", cr.TotalRemain)
	}
	if cr.PackCount != 1 || len(cr.Packages) != 1 {
		t.Fatalf("packages: %+v", cr.Packages)
	}
	if !strings.Contains(cr.Packages[0].Name, "企业额度") {
		t.Fatalf("package name: %q", cr.Packages[0].Name)
	}
	if cr.Packages[0].CycleEnd != "2026-10-31 23:59:59" {
		t.Fatalf("cycle end: %q", cr.Packages[0].CycleEnd)
	}
	// The lifecycle consequence: a disabled enterprise account with this
	// summary re-enables (this is the trap the issue pinned — it never did).
	if !shouldReenableCN(true, cr) {
		t.Fatal("enterprise summary must re-enable a disabled account")
	}
	if isCreditsExhausted(cr) {
		t.Fatal("enterprise summary must not read as exhausted")
	}
}

// TestFetchUserResourcePersonalEmptyNoFallback pins the guard: only
// enterprise accounts enter the fallback; a personal account's empty result
// keeps its legacy shape (zero summary, no error, no enterprise call).
func TestFetchUserResourcePersonalEmptyNoFallback(t *testing.T) {
	var enterpriseCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/billing/meter/get-user-resource":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(personalEmptyJSON))
		case "/billing/meter/get-enterprise-user-usage":
			atomic.AddInt32(&enterpriseCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"msg":"OK","data":` + enterpriseUsageJSON + `}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	restore := setBillingBase(srv.URL)
	defer restore()

	cr, err := fetchUserResource(billingTestAuth())
	if err != nil {
		t.Fatalf("fetchUserResource: %v", err)
	}
	if cr == nil || cr.TotalRemain != 0 || cr.PackCount != 0 {
		t.Fatalf("personal empty summary: %+v", cr)
	}
	if n := atomic.LoadInt32(&enterpriseCalls); n != 0 {
		t.Fatalf("personal account touched the enterprise plane %d times", n)
	}
}

// TestFetchUserResourceEnterprisePlaneDown: the personal plane is empty AND
// the enterprise plane fails — the account reads unknown (error), never a
// zero summary that would render "余0 已用0".
func TestFetchUserResourceEnterprisePlaneDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/billing/meter/get-user-resource":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(personalEmptyJSON))
		case "/billing/meter/get-enterprise-user-usage":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	restore := setBillingBase(srv.URL)
	defer restore()

	if _, err := fetchUserResource(enterpriseTestAuth()); err == nil {
		t.Fatal("both planes empty must surface an error, not a zero summary")
	}
}

// TestPerformCheckinCallEnterpriseShortCircuit: the manual press never
// reaches the daily-checkin plane (which answers 400 biz 10001 for
// enterprise accounts); the refusal says why.
func TestPerformCheckinCallEnterpriseShortCircuit(t *testing.T) {
	var checkinCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/billing/meter/daily-checkin" {
			atomic.AddInt32(&checkinCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"OK"}`))
	}))
	defer srv.Close()
	restore := setBillingBase(srv.URL)
	defer restore()

	out, err := performCheckinCall(enterpriseTestAuth())
	if err != nil {
		t.Fatalf("performCheckinCall: %v", err)
	}
	if v, _ := out["success"].(bool); v {
		t.Fatalf("enterprise check-in must not report success: %v", out)
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "企业") {
		t.Fatalf("refusal message: %q", msg)
	}
	if n := atomic.LoadInt32(&checkinCalls); n != 0 {
		t.Fatalf("daily-checkin plane was called %d times", n)
	}
}

// TestFetchPaymentTypeEnterprise: the plan names the plane instead of the
// personal ladder's "free" — and without an upstream round trip.
func TestFetchPaymentTypeEnterprise(t *testing.T) {
	var anyCall int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&anyCall, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"OK","paymentType":"free"}`))
	}))
	defer srv.Close()
	restore := setBillingBase(srv.URL)
	defer restore()

	if got := fetchPaymentType(enterpriseTestAuth()); got != "enterprise" {
		t.Fatalf("plan = %q, want enterprise", got)
	}
	if n := atomic.LoadInt32(&anyCall); n != 0 {
		t.Fatalf("get-payment-type was called %d times", n)
	}
}

// TestEnterpriseUsageFold pins the numeric fold in isolation, including the
// over-consumption clamp (credit beyond limitNum reads remain 0, not negative).
func TestEnterpriseUsageFold(t *testing.T) {
	u := &enterpriseUsage{Credit: 2500, LimitNum: 2000}
	cr := u.creditsSummary()
	if cr.TotalRemain != 0 || cr.TotalUsed != 2500 || cr.TotalSize != 2000 {
		t.Fatalf("clamp fold: %+v", cr)
	}
	if !isCreditsExhausted(cr) {
		t.Fatal("a truly over-drawn enterprise cycle must read as exhausted")
	}
}
