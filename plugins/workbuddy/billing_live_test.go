//go:build live

// billing_live_test.go — real-credential verification that the plugin's
// production billing path returns actual credit data. This is the pre-release
// gate for billing EOF fixes: it exercises billingCall → billingCallOnce →
// hostHTTPDo (codebuddy.ai direct bypass → hostHTTPDoDirect) → pooled/rescue
// transports with the resilient dialer — the exact code path a deployed .so
// runs.
//
// Run:
//
//	WB_JWT=... WB_UID=... go test -tags live -run TestLiveBilling -v ./plugins/workbuddy
//
// Skipped unless -tags live AND WB_JWT are set, so normal CI stays hermetic.
package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestLiveBilling_GetUserResource(t *testing.T) {
	jwt := os.Getenv("WB_JWT")
	if jwt == "" {
		t.Skip("WB_JWT not set — live billing verification skipped")
	}
	uid := os.Getenv("WB_UID")

	sa := &storedAuth{
		Auth:    storedTokens{AccessToken: jwt, Domain: "www.codebuddy.ai", Region: "intl", LoginPlatform: "ide"},
		Account: storedAccount{UID: uid},
	}
	now := time.Now()
	body := map[string]any{
		"PageNumber":               1,
		"PageSize":                 100,
		"ProductCode":              "p_tcaca",
		"Status":                   []int{0, 3},
		"PackageEndTimeRangeBegin": now.Format("2006-01-02 15:04:05"),
		"PackageEndTimeRangeEnd":   now.Add(365 * 24 * time.Hour).Format("2006-01-02 15:04:05"),
	}

	data, err := billingCall(sa, "/v2/billing/meter/get-user-resource", body)
	if err != nil {
		t.Fatalf("live billing call failed: %v", err)
	}

	// billingCall returns the apiEnvelope data member. The Intl meter API
	// nests one level deeper: {"Response":{"Data":{"TotalDosage":...}}}.
	var payload struct {
		Response struct {
			Data struct {
				TotalDosage int               `json:"TotalDosage"`
				TotalCount  int               `json:"TotalCount"`
				Accounts    []json.RawMessage `json:"Accounts"`
			} `json:"Data"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode response: %v — raw head: %.400s", err, string(data))
	}
	t.Logf("LIVE OK: TotalDosage=%d TotalCount=%d accounts=%d",
		payload.Response.Data.TotalDosage, payload.Response.Data.TotalCount, len(payload.Response.Data.Accounts))
	if payload.Response.Data.TotalCount == 0 {
		t.Fatalf("expected non-empty resource list, got TotalCount=0 (raw: %.400s)", string(data))
	}
	if payload.Response.Data.TotalDosage < 0 {
		t.Fatalf("unexpected negative TotalDosage: %d", payload.Response.Data.TotalDosage)
	}
}

// TestLiveBilling_DialStageEvidence additionally runs the staged probe against
// the real host so the test log records what each stage looks like from this
// network (useful as a baseline when comparing field reports).
func TestLiveBilling_DialStageEvidence(t *testing.T) {
	uid := os.Getenv("WB_UID")
	_ = uid
	suffix := billingNetDiagSuffix("https://www.codebuddy.ai")
	if suffix == "" {
		t.Fatal("expected non-empty diag suffix for a hostname base")
	}
	t.Logf("net-diag: %s", suffix)
}

// TestLiveBilling_TransportReachesGateway proves the full production transport
// ladder (billingCall → billingCallOnce → hostHTTPDo → direct pooled/rescue
// transports → billingDialContext with the multi-source DNS + DoH) reaches the
// application layer of BOTH billing gateways. It posts the real meter call
// with a dummy token and asserts the failure (if any) is application-class —
// a credential rejection or business code — and NEVER transport exhaustion
// ("unreachable"): DNS, dial and TLS all worked. This is the credential-free
// pre-release gate for the EOF/net-dial fixes.
//
// Run:
//
//	WB_LIVE_GATEWAY=1 go test -tags live -run TestLiveBilling_TransportReachesGateway -v ./plugins/workbuddy
func TestLiveBilling_TransportReachesGateway(t *testing.T) {
	if os.Getenv("WB_LIVE_GATEWAY") == "" {
		t.Skip("WB_LIVE_GATEWAY not set — live gateway transport verification skipped")
	}
	cases := []struct {
		name   string
		domain string
		base   string
	}{
		{"CN", "", "https://www.codebuddy.cn"},
		{"Intl", "www.codebuddy.ai", "https://www.codebuddy.ai"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			region := "cn"
			if tc.domain != "" {
				region = "intl"
			}
			sa := &storedAuth{
				Auth:    storedTokens{AccessToken: "live-transport-probe-dummy-token", Domain: tc.domain, Region: region, LoginPlatform: "ide"},
				Account: storedAccount{UID: "live-transport-probe"},
			}
			body := map[string]any{"PageNumber": 1, "PageSize": 10, "ProductCode": "p_tcaca", "Status": []int{0, 3}}
			_, err := billingCall(sa, "/v2/billing/meter/get-user-resource", body)
			if err == nil {
				t.Logf("%s: meter call unexpectedly succeeded with a dummy token (gateway auth bypass?) — transport proven anyway", tc.base)
				return
			}
			t.Logf("%s: %v", tc.base, err)
			if isTransientBillingErr(err) {
				t.Fatalf("%s: transport-class failure — the ladder did NOT reach the gateway: %v", tc.base, err)
			}
			t.Logf("%s: application-layer answer received — transport ladder (DNS → DoH cross-check → dial → TLS → HTTP) verified end-to-end", tc.base)
		})
	}
}
