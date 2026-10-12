//go:build live

// trae_live_payfamily_test.go — issue follow-up (2026-10-12, "trae/cn 仍然
// 有问题：ent_usage session_dead http 401 code 1001"): the pay/ug family
// (ide_user_ent_usage / ide_user_pay_status / checkin_credits) is the face
// where a wrong-lineage or otherwise-poisoned JWT surfaces. The earlier live
// verification (trae_live_refresh_test.go) only proved refresh + CHAT — and
// llm_utils_chat is exactly the call that TOLERATES cross-lineage tokens
// (v0.12.60 measured: chat fine, ug/pay 401 code 1001). These legs close
// that gap on a real credential:
//
//	leg 0  TestLivePayFamilyCurrentToken  — pay/ug/checkin family straight
//	       with the stored token (no refresh): is the CURRENT lineage healthy?
//	leg 1  TestLiveRefreshThenPayFamily   — full Client.RefreshToken chain
//	       (bound ladder → legacy fallback), then the pay family again with
//	       the freshly minted token; persists the rotated pair to TRAE_CRED.
//	leg 2  TestLiveWrongLineageExchange   — gated by TRAE_LINEAGE_EXPERIMENT=1:
//	       hand-rolled /cloudide ExchangeToken with the SOLO client id
//	       (en1oxy7wnw8j9n) against a cn-lineage refresh token. Decides the
//	       bound-ladder-order question: if the server mints the cross-class
//	       token and the pay family rejects it with 401/1001, the v0.12.74
//	       SOLO_PC-first ladder is the regression for cn accounts; if the
//	       server refuses the mismatched client, the ladder order was merely
//	       wasteful. Ends with a correct-lineage recovery exchange and
//	       persists the final pair.
//
// Run:
//
//	TRAE_CRED=/path/cred.json go test -tags live -run TestLivePayFamilyCurrentToken -v ./plugins/trae
//	TRAE_CRED=/path/cred.json go test -tags live -run TestLiveRefreshThenPayFamily -v ./plugins/trae
//	TRAE_CRED=/path/cred.json TRAE_LINEAGE_EXPERIMENT=1 \
//	  go test -tags live -run TestLiveWrongLineageExchange -v ./plugins/trae
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/auth"
	"github.com/mmqz/cpa-multi-plugins/plugins/trae/upstream"
)

// livePayFamily probes ent_usage + pay_status + CheckLogin + checkin status
// and reports each leg's outcome; failures are logged, not fatal, so one
// dead face does not hide the others (the error TEXT is the evidence).
func livePayFamily(t *testing.T, c *upstream.Client, a *auth.Auth, tag string) {
	t.Helper()

	if usage, err := c.UserEntUsage(a); err != nil {
		t.Logf("[%s] ent_usage FAIL: %v", tag, err)
	} else {
		packs := len(usage.UserEntitlementPackList)
		avail, limit, used, hasEv := upstream.FastRequestUsage(usage.UserEntitlementPackList, false)
		t.Logf("[%s] ent_usage OK: is_credits_billing=%v packs=%d fastReq avail=%d limit=%d used=%d hasEvidence=%v",
			tag, usage.IsCreditsBilling, packs, avail, limit, used, hasEv)
	}

	if ps, err := c.PayStatus(a); err != nil {
		t.Logf("[%s] pay_status FAIL: %v", tag, err)
	} else {
		t.Logf("[%s] pay_status OK: code=%d identity=%q fastReqPer=%v soloParallel=%v soloPkg=%v",
			tag, ps.Code, ps.UserPayIdentityStr, ps.FastRequestPer(), ps.SoloParallelLimit(), ps.HasSoloPackage())
	}

	if cl, err := c.CheckLogin(a); err != nil {
		t.Logf("[%s] check_login FAIL: %v", tag, err)
	} else {
		match := cl.BoundDeviceID != "" && cl.BoundDeviceID == a.DeviceID
		t.Logf("[%s] check_login OK: isLogin=%v bindStatus=%q boundDevice=%q localDevice=%q match=%v",
			tag, cl.IsLogin, cl.DeviceBindStatus, cl.BoundDeviceID, a.DeviceID, match)
	}

	if cs, err := c.CheckinStatus(a); err != nil {
		t.Logf("[%s] checkin_status FAIL: %v", tag, err)
	} else {
		t.Logf("[%s] checkin_status OK: checked_in=%v did_checked_in=%v credits=%d extra=%d",
			tag, cs.CheckedIn, cs.DidCheckedIn, cs.Credits, cs.ExtraCredits)
	}
}

// TestLivePayFamilyCurrentToken — leg 0: the pay family with the token as
// stored (no refresh). Establishes whether the current lineage is healthy
// before any renewal runs.
func TestLivePayFamilyCurrentToken(t *testing.T) {
	a := liveTraeAuth(t)
	c := upstream.New()
	livePayFamily(t, c, a, "stored-token")
}

// TestLiveRefreshThenPayFamily — leg 1: the full production renewal chain,
// then the pay family with whatever it minted.
func TestLiveRefreshThenPayFamily(t *testing.T) {
	a := liveTraeAuth(t)
	c := upstream.New()

	oldToken := a.AccessToken
	if err := c.RefreshToken(a); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	t.Logf("refresh OK: token changed=%v expiresAt=%s", a.AccessToken != oldToken,
		time.Unix(a.ExpiresAt, 0).Format(time.RFC3339))
	livePersistCred(t, a)
	livePayFamily(t, c, a, "post-refresh")
}

// livePersistCred writes the current auth pair back to TRAE_CRED so the
// credential handed back to the user is always the newest rotation.
func livePersistCred(t *testing.T, a *auth.Auth) {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("TRAE_CRED"))
	if path == "" {
		return
	}
	doc := map[string]any{
		"provider": "trae", "type": "trae",
		"account": map[string]any{"uid": a.UID, "nickname": a.Nickname, "enterpriseId": a.EnterpriseID},
		"auth": map[string]any{
			"accessToken": a.AccessToken, "refreshToken": a.RefreshToken,
			"expiresAt": a.ExpiresAt, "domain": a.Domain, "apiHost": a.APIHost,
			"machineId": a.MachineID, "deviceId": a.DeviceID,
			"variant":          a.Variant,
			"devicePublicKey":  a.DevicePublicKey,
			"devicePrivateKey": a.DevicePrivateKey,
		},
	}
	if raw, err := json.MarshalIndent(doc, "", " "); err == nil {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Logf("persist cred: %v", err)
		} else {
			t.Logf("persisted rotated pair to %s", path)
		}
	}
}

// liveLegacyExchange hand-rolls the /cloudide ExchangeToken with an
// arbitrary ClientID — the same wire shape refreshLocked's legacy path
// sends (OAuthHeaders, ClientSecret "-", UserID ""). Returns the minted
// token / rotated refresh token ("" when the server refuses).
func liveLegacyExchange(clientID, refreshToken string) (token, rotated string, err error) {
	body, _ := json.Marshal(map[string]any{
		"ClientID":     clientID,
		"RefreshToken": refreshToken,
		"ClientSecret": "-",
		"UserID":       "",
	})
	req, err := http.NewRequest(http.MethodPost, "https://api.trae.cn"+upstream.EpExchange, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	upstream.OAuthHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("http %d: %s", resp.StatusCode, liveTruncate(string(raw), 300))
	}
	var env struct {
		Result struct {
			Token        string `json:"Token"`
			RefreshToken string `json:"RefreshToken"`
		} `json:"Result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", "", fmt.Errorf("parse: %w (body=%s)", err, liveTruncate(string(raw), 200))
	}
	return env.Result.Token, env.Result.RefreshToken, nil
}

// TestLiveDeadRefreshTokenProbe — leg 3 (TRAE_OLD_RT=..., harmless): exchange
// a SUPERSEDED refresh token (rotated away by an earlier live run) with the
// correct-lineage client and record the server's error taxonomy for a dead
// rt. Decides what the plugin should tell the user when their host holds a
// rotated-away rt: is 10101 "refresh token is not matched to the client"
// also the dead-rt answer, or is that error lineage-specific? The current
// live chain (TRAE_CRED) is untouched when the probe fails; if the old rt
// unexpectedly still lives, the freshly rotated pair is persisted instead.
func TestLiveDeadRefreshTokenProbe(t *testing.T) {
	oldRT := strings.TrimSpace(os.Getenv("TRAE_OLD_RT"))
	if oldRT == "" {
		t.Skip("TRAE_OLD_RT not set — dead-rt taxonomy probe skipped")
	}
	a := liveTraeAuth(t)
	c := upstream.New()

	token, rotated, err := liveLegacyExchange(upstream.ClientIDFor(a.Variant), oldRT)
	if err != nil {
		t.Logf("superseded rt REFUSED (expected): %v", err)
		t.Logf("=> dead-rt taxonomy recorded; live chain in TRAE_CRED untouched")
		return
	}
	t.Logf("superseded rt STILL LIVE (rotation grace window): token minted, rt rotated=%v", rotated != "")
	if token == "" {
		t.Fatalf("200 but no token")
	}
	// The exchange rotated the chain away from TRAE_CRED's pair — adopt it.
	a.AccessToken = token
	if rotated != "" {
		a.RefreshToken = rotated
	}
	livePersistCred(t, a)
	livePayFamily(t, c, a, "old-rt-adopted")
}

// TestLiveWrongLineageExchange — leg 2 (TRAE_LINEAGE_EXPERIMENT=1): renew a
// cn-lineage refresh token AS THE SOLO CLIENT, then drive the pay family
// with the cross-class token. Decisive for the bound-ladder-order question.
// Always ends with a correct-lineage recovery exchange + persist.
func TestLiveWrongLineageExchange(t *testing.T) {
	if strings.TrimSpace(os.Getenv("TRAE_LINEAGE_EXPERIMENT")) != "1" {
		t.Skip("TRAE_LINEAGE_EXPERIMENT != 1 — wrong-lineage experiment skipped")
	}
	a := liveTraeAuth(t)
	c := upstream.New()
	rt := a.RefreshToken

	// Step 1: wrong-lineage (SOLO client) legacy exchange.
	soloToken, soloRT, err := liveLegacyExchange("en1oxy7wnw8j9n", rt)
	if err != nil {
		t.Logf("wrong-lineage exchange REFUSED by server: %v", err)
		t.Logf("=> the server gates client↔rt lineage at exchange time; the SOLO_PC-first bound ladder cannot poison cn accounts.")
		livePayFamily(t, c, a, "after-refusal")
		return
	}
	if soloToken == "" {
		t.Fatalf("wrong-lineage exchange returned 200 but no token")
	}
	t.Logf("wrong-lineage exchange MINTED a token (solo client, cn account), rt rotated=%v", soloRT != "")

	// Step 2: pay family under the cross-class token.
	probe := &auth.Auth{
		AccessToken:  soloToken,
		RefreshToken: soloRT,
		UID:          a.UID,
		Variant:      a.Variant,
		DeviceID:     a.DeviceID,
		MachineID:    a.MachineID,
		APIHost:      a.APIHost,
		Domain:       a.Domain,
	}
	livePayFamily(t, c, probe, "wrong-lineage-token")

	// Step 3: recovery — correct-lineage exchange with whichever rt is live.
	recRT := rt
	if soloRT != "" {
		recRT = soloRT
	}
	recToken, recRT2, err := liveLegacyExchange(upstream.ClientIDFor(a.Variant), recRT)
	if err != nil {
		t.Fatalf("recovery exchange failed (rt may be re-lineaged): %v — re-login needed", err)
	}
	t.Logf("recovery exchange OK: token minted under %s, rt rotated=%v", upstream.ClientIDFor(a.Variant), recRT2 != "")
	a.AccessToken = recToken
	if recRT2 != "" {
		a.RefreshToken = recRT2
	} else if soloRT != "" {
		a.RefreshToken = soloRT
	}
	livePersistCred(t, a)
	livePayFamily(t, c, a, "recovered")
}
