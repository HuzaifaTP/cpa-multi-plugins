// bound_exchange_test.go pins the v0.12.74 device-bound token renewal,
// byte-aligned with the production-verified magpie-community reference
// (magpie-community/packages/trae index.mjs boundExchange/proofOf/deviceInfo,
// 行号区间 446-504): the SOLO_PC-first identity ladder with per-identity
// versions, the Cloud-IDE-JWT Authorization header, the magpie DeviceInfo
// value domain, the single api.trae.cn host (no fan-out), bound-first
// ordering in refreshLocked, and the legacy-path fallback when the bound
// renewal is refused on both identities.
package upstream

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/auth"
)

func TestDeviceProofPayloadShape(t *testing.T) {
	// method, path, client, refresh token, unix seconds, nonce — one per line
	// (magpie proofOf / trae-checkin _exchange_once cross-verified).
	got := deviceProofPayload("/trae/api/v3/oauth/ExchangeToken", "cid", "rt", 1750000000, "abc123")
	want := "POST\n/trae/api/v3/oauth/ExchangeToken\ncid\nrt\n1750000000\nabc123"
	if got != want {
		t.Errorf("deviceProofPayload = %q, want %q", got, want)
	}
}

func TestSignDeviceProofVerifiesWithPublicKey(t *testing.T) {
	pubPEM, privPEM, err := auth.GenerateDeviceKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := "POST\n/trae/api/v3/oauth/ExchangeToken\ncid\nrt\n1750000000\nnonce"
	sig, err := auth.SignDeviceProof(privPEM, payload)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("public key PEM undecodable")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T", pubAny)
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(payload))
	if !ecdsa.VerifyASN1(pub, sum[:], raw) {
		t.Error("signature does not verify against the generated public key")
	}
	// a tampered payload must not verify
	sum2 := sha256.Sum256([]byte(payload + "x"))
	if ecdsa.VerifyASN1(pub, sum2[:], raw) {
		t.Error("signature verified over a different payload")
	}
}

// TestBoundExchangeIdentitiesMagpieOrder: v0.12.74 magpie 对齐——固定身份
// 梯子替代 v0.12.73 的 own-lineage 优先（旧行为的断言已随语义迁移到这里）：
// SOLO_PC(en1oxy7wnw8j9n, 0.1.64) 永远第一（qilimixingkong/trae-checkin
// 发现服务器接受的那个），IDE_PC(ono9krqynydwx5, 3.3.99) 第二。
func TestBoundExchangeIdentitiesMagpieOrder(t *testing.T) {
	ids := boundExchangeIdentities()
	if len(ids) != 2 {
		t.Fatalf("identity ladder = %+v, want exactly 2 rungs", ids)
	}
	if ids[0].ClientID != soloExchangeClient || ids[0].PlatformCode != "SOLO_PC" || ids[0].Version != "0.1.64" {
		t.Errorf("first identity = %+v, want SOLO_PC en1oxy7wnw8j9n 0.1.64", ids[0])
	}
	if ids[1].ClientID != ideExchangeClient || ids[1].PlatformCode != "IDE_PC" || ids[1].Version != "3.3.99" {
		t.Errorf("second identity = %+v, want IDE_PC ono9krqynydwx5 3.3.99", ids[1])
	}
}

// TestBoundExchangeHostDefaultIsMagpieAuthHost pins the production host:
// magpie site.hosts.auth — the bound renewal must never fan out to
// apiHost/OAuthHost backups (v0.12.73 behavior, issue #38).
func TestBoundExchangeHostDefaultIsMagpieAuthHost(t *testing.T) {
	if boundExchangeHost != "https://api.trae.cn" {
		t.Fatalf("boundExchangeHost = %q, want the magpie auth host https://api.trae.cn", boundExchangeHost)
	}
}

// TestRefreshLockedBoundExchangeMagpieLadder drives a REAL httptest server
// (boundExchangeHost injected) through c.RefreshToken: the first request must
// carry the SOLO identity, the second (after a 400 refusal) the IDE identity,
// and the IDE run's tokens win. Also pins: the Cloud-IDE-JWT Authorization
// header, the magpie DeviceInfo value domain, the single-host strategy (the
// account's apiHost / the client's OAuthHost are never contacted), and the
// refresh-token rotation respect.
func TestRefreshLockedBoundExchangeMagpieLadder(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	var auths []string
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("bad body: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, body)
		auths = append(auths, r.Header.Get("Authorization"))
		paths = append(paths, r.URL.Path)
		n := len(bodies)
		mu.Unlock()
		if n == 1 {
			// SOLO run refused — e.g. a token the server does not match to
			// that client (issue #38's 400 family).
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"code":10101,"message":"refresh token is not matched to the client"}`)
			return
		}
		fmt.Fprint(w, `{"Result":{"Token":"bound-token","RefreshToken":"rotated-rt","TokenExpireAt":1790000000000}}`)
	}))
	defer ts.Close()

	prevHost := boundExchangeHost
	boundExchangeHost = ts.URL
	t.Cleanup(func() { boundExchangeHost = prevHost })

	// Deliberately DIFFERENT api/OAuth hosts: the v0.12.73 fan-out would have
	// contacted them after a refusal — a single-host strategy must not.
	c := &Client{HTTP: ts.Client(), OAuthHost: "https://oauth-fanout-canary.example"}
	a := &auth.Auth{AccessToken: "live-jwt", RefreshToken: "oldrt", ExpiresAt: 1,
		APIHost: "https://apihost-fanout-canary.example", Variant: "cn",
		DeviceID: "1111222233334444", MachineID: "machine-1"}
	if err := c.RefreshToken(a); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("requests = %d, want exactly 2 (SOLO refusal then IDE success — no host fan-out)", len(bodies))
	}
	// ① 身份梯子顺序与各自身份的版本号（ClientVersion 与 IDEVersion 同值）。
	first, second := bodies[0], bodies[1]
	if first["ClientID"] != soloExchangeClient || first["IDEVersion"] != "0.1.64" {
		t.Errorf("first request ClientID/IDEVersion = %v/%v, want en1oxy7wnw8j9n/0.1.64", first["ClientID"], first["IDEVersion"])
	}
	di1, ok := first["DeviceInfo"].(map[string]any)
	if !ok {
		t.Fatal("first DeviceInfo missing")
	}
	if di1["PlatformCode"] != "SOLO_PC" || di1["ClientVersion"] != "0.1.64" {
		t.Errorf("first DeviceInfo = %v, want SOLO_PC + ClientVersion 0.1.64", di1)
	}
	if second["ClientID"] != ideExchangeClient || second["IDEVersion"] != "3.3.99" {
		t.Errorf("second request ClientID/IDEVersion = %v/%v, want ono9krqynydwx5/3.3.99", second["ClientID"], second["IDEVersion"])
	}
	di2, ok := second["DeviceInfo"].(map[string]any)
	if !ok {
		t.Fatal("second DeviceInfo missing")
	}
	if di2["PlatformCode"] != "IDE_PC" || di2["ClientVersion"] != "3.3.99" {
		t.Errorf("second DeviceInfo = %v, want IDE_PC + ClientVersion 3.3.99", di2)
	}
	// ② magpie boundExchange 带 Authorization: Cloud-IDE-JWT <token>。
	if auths[0] != "Cloud-IDE-JWT live-jwt" || auths[1] != "Cloud-IDE-JWT live-jwt" {
		t.Errorf("Authorization headers = %v, want Cloud-IDE-JWT live-jwt on every request", auths)
	}
	// ③ magpie DeviceInfo 值域（v0.12.73 偏差逐项纠正）。
	for _, di := range []map[string]any{di1, di2} {
		if di["DeviceModel"] != "" {
			t.Errorf("DeviceModel = %v, want empty (v0.12.73 误填品牌串)", di["DeviceModel"])
		}
		if di["OSInfo"] != "Windows" {
			t.Errorf("OSInfo = %v, want Windows (v0.12.73 是小写)", di["OSInfo"])
		}
		if di["OSVersion"] != "10.0.22631" {
			t.Errorf("OSVersion = %v, want 10.0.22631 (v0.12.73 是产品名)", di["OSVersion"])
		}
		if di["DeviceCPU"] != "AMD" {
			t.Errorf("DeviceCPU = %v, want AMD", di["DeviceCPU"])
		}
		if di["DeviceBrand"] != "ASUS TUF Gaming A15 FA507RM_FA507RM" {
			t.Errorf("DeviceBrand = %v, want the magpie site.brand", di["DeviceBrand"])
		}
		if di["DeviceID"] != "1111222233334444" || di["DevicePublicKey"] == "" {
			t.Errorf("DeviceInfo device identity wrong: %v", di)
		}
	}
	// ④ 单 host：所有请求都打注入的 boundExchangeHost 的 ExchangeToken 路径。
	for i, p := range paths {
		if p != epExchangeBound {
			t.Errorf("request %d path = %q, want %q", i, p, epExchangeBound)
		}
	}
	// ⑥ 成功响应解析 + refresh token 轮换尊重（返回了就采用）。
	if a.AccessToken != "bound-token" {
		t.Errorf("AccessToken = %q, want bound-token", a.AccessToken)
	}
	if a.RefreshToken != "rotated-rt" {
		t.Errorf("RefreshToken = %q, want the rotated rt (a returned one is honored)", a.RefreshToken)
	}
	if exp := a.ExpiresAt; exp != 1790000000 {
		t.Errorf("ExpiresAt = %d, want ms-normalized 1790000000", exp)
	}
	// the account had no device keys → generated, attached, ready to persist
	if a.DevicePublicKey == "" || a.DevicePrivateKey == "" {
		t.Error("device key pair not generated/attached")
	}
	// proof shape on both requests
	for i, body := range bodies {
		proof, ok := body["DeviceProof"].(map[string]any)
		if !ok {
			t.Fatalf("request %d DeviceProof missing", i)
		}
		sig, _ := proof["Signature"].(string)
		ts, _ := proof["Timestamp"].(float64)
		nonce, _ := proof["Nonce"].(string)
		if sig == "" || ts == 0 || nonce == "" {
			t.Errorf("request %d DeviceProof incomplete: %v", i, proof)
		}
		if body["ClientSecret"] != "" {
			t.Errorf("request %d ClientSecret = %v, want empty", i, body["ClientSecret"])
		}
	}
}

// TestBoundExchangeNoAuthorizationWithoutToken: magpie sends the JWT header
// only when the account has a token (`a.token ? {...} : {}`).
func TestBoundExchangeNoAuthorizationWithoutToken(t *testing.T) {
	var mu sync.Mutex
	var authHeader string
	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		authHeader = r.Header.Get("Authorization")
		mu.Unlock()
		fmt.Fprint(w, `{"Result":{"Token":"bound-token"}}`)
	}))
	defer ts.Close()

	prevHost := boundExchangeHost
	boundExchangeHost = ts.URL
	t.Cleanup(func() { boundExchangeHost = prevHost })

	c := &Client{HTTP: ts.Client()}
	a := &auth.Auth{RefreshToken: "oldrt", ExpiresAt: 1, Variant: "cn",
		DeviceID: "1111222233334444", MachineID: "machine-1"}
	if err := c.RefreshToken(a); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if authHeader != "" {
		t.Errorf("Authorization = %q, want absent for a token-less account", authHeader)
	}
	if body["ClientID"] != soloExchangeClient {
		t.Errorf("ClientID = %v, want the SOLO rung even without an access token", body["ClientID"])
	}
}

// TestRefreshLockedBoundFallsBackToLegacy: both identities refused (400,
// e.g. cross-lineage mismatch on the whole ladder) → the bound path yields an
// error and the legacy /cloudide path still renews; never worse than before.
// v0.12.74: the ladder is exactly 2 attempts (SOLO then IDE) — no host
// fan-out on top.
func TestRefreshLockedBoundFallsBackToLegacy(t *testing.T) {
	boundHits := 0
	c := testClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == epExchangeBound {
			boundHits++
			return jsonResp(400, `{"code":10101,"message":"refresh token is not matched to the client"}`), nil
		}
		if strings.HasSuffix(r.URL.Path, EpExchange) {
			return jsonResp(200, `{"Result":{"Token":"legacy-token","RefreshToken":"legacy-rt"}}`), nil
		}
		return nil, errors.New("unexpected path " + r.URL.Path)
	})
	a := &auth.Auth{AccessToken: "at", RefreshToken: "oldrt", ExpiresAt: 1, APIHost: "https://oauth.example", Variant: "cn", DeviceID: "1111222233334444"}
	if err := c.RefreshToken(a); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if boundHits != 2 {
		t.Fatalf("bound attempts = %d, want exactly 2 (the magpie ladder, no host fan-out)", boundHits)
	}
	if a.AccessToken != "legacy-token" || a.RefreshToken != "legacy-rt" {
		t.Errorf("fallback tokens wrong: %q / %q", a.AccessToken, a.RefreshToken)
	}
	// the generated key pair stays attached for the next attempt (same key the
	// server will eventually bind), ready for SaveAtomic persistence
	if a.DevicePublicKey == "" || a.DevicePrivateKey == "" {
		t.Error("generated device keys were not kept after fallback")
	}
}
