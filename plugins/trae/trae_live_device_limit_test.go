//go:build live

// trae_live_device_limit_test.go — v0.12.76 device-gate probe (issue #38
// 余波: ExchangeToken 403 code=20401 "Device limit reached").
//
// TestLiveDeviceGateProbe (gated by TRAE_DEVICE_PROBE=1, TRAE_CRED for the
// credential, -tags live): posts a login-shaped auth-code ExchangeToken to
// https://api.trae.cn with the credential's REGISTERED deviceId/machineId
// and a necessarily-invalid AuthCode. Purpose: prove the 20401 device gate
// keys on DeviceInfo — a KNOWN device must pass the gate and fail later, in
// the invalid-code family (not 20401). That is exactly the core assumption
// of the v0.12.76 stable-identity fix. A failed exchange with a forged code
// registers no device server-side, so the probe itself is side-effect-free.
//
// Optional leg (TRAE_DEVICE_PROBE_FRESH=1): the same request with a
// brand-new device identity — EXPECTED to reproduce the user's 403+20401
// (gate order confirmation); a mismatch is logged, never fatal.
//
// Run:
//
//	TRAE_CRED=/path/cred.json TRAE_DEVICE_PROBE=1 \
//	  go test -tags live -run TestLiveDeviceGateProbe -v ./plugins/trae
//	TRAE_CRED=/path/cred.json TRAE_DEVICE_PROBE=1 TRAE_DEVICE_PROBE_FRESH=1 \
//	  go test -tags live -run TestLiveDeviceGateProbe -v ./plugins/trae
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/upstream"
)

// probeDeviceGateExchange POSTs one login-shaped auth-code ExchangeToken
// request (field-for-field identical to the main.go auth-code branch) and
// returns status + body. Headers mirror exchangeTokenCandidates.
func probeDeviceGateExchange(t *testing.T, deviceID, machineID, variant string) (int, []byte) {
	t.Helper()
	di := buildOfficialDeviceInfo(
		deviceID, machineID, oauthPlatformCodeFor(variant), oauthDeviceName,
		oauthDeviceBrand, upstream.IdeVersion, oauthDeviceType, oauthOSVersion, "",
	)
	body, _ := json.Marshal(map[string]any{
		"ClientID":     upstream.ClientIDFor(variant),
		"AuthCode":     "probe-invalid-code-000000",
		"CodeVerifier": "probe-verifier",
		"DeviceInfo":   di,
		"IDEVersion":   upstream.IdeVersion,
	})
	req, err := http.NewRequest(http.MethodPost,
		"https://api.trae.cn/trae/api/v3/oauth/ExchangeToken", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build probe request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-cloudide-token", "")
	req.Header.Set("User-Agent", "Trae/"+oauthPluginVersion+" antigravity-cockpit-tools")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("probe request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw
}

func TestLiveDeviceGateProbe(t *testing.T) {
	if strings.TrimSpace(os.Getenv("TRAE_DEVICE_PROBE")) != "1" {
		t.Skip("TRAE_DEVICE_PROBE not set — device-gate probe skipped")
	}
	a := liveTraeAuth(t)
	if strings.TrimSpace(a.DeviceID) == "" || strings.TrimSpace(a.MachineID) == "" {
		t.Fatalf("credential carries no registered deviceId/machineId — the probe needs an already-registered device identity (TRAE_CRED=%s)", os.Getenv("TRAE_CRED"))
	}

	// Leg 1: known device — must pass the 20401 device gate and die in the
	// invalid-code family instead. If it 20401s, the stable-identity fix's
	// core assumption is refuted.
	status, raw := probeDeviceGateExchange(t, a.DeviceID, a.MachineID, a.Variant)
	body := string(raw)
	if status == http.StatusForbidden && strings.Contains(body, "20401") {
		t.Fatalf("device gate rejected a KNOWN device: HTTP 403 code=20401 (body=%s) — the v0.12.76 assumption (gate keys on DeviceInfo) is refuted", liveTruncate(body, 400))
	}
	t.Logf("known-device probe: HTTP %d body=%s (expected the invalid-code family, NOT 20401)", status, liveTruncate(body, 400))

	// Optional leg 2: fresh identity — expected to reproduce the user's 403
	// +20401. Informational only: the user's account may simply not be at
	// its device limit right now.
	if strings.TrimSpace(os.Getenv("TRAE_DEVICE_PROBE_FRESH")) == "1" {
		fs, fraw := probeDeviceGateExchange(t, newDeviceID(), newMachineID(), a.Variant)
		fbody := string(fraw)
		if fs == http.StatusForbidden && strings.Contains(fbody, "20401") {
			t.Logf("fresh-device probe: HTTP %d code=20401 — the user-reported gate order reproduced (fresh device blocked before code validation)", fs)
		} else {
			t.Logf("fresh-device probe: HTTP %d body=%s (expected 403+20401; mismatch is informational only — the account may have free device slots)", fs, liveTruncate(fbody, 400))
		}
	}
}
