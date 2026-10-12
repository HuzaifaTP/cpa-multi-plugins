// bound_exchange_test.go pins the device-bound token renewal (v0.12.74
// magpie 对齐, v0.12.75 谱系感知): the lineage-aware identity ladder
// (own-lineage rung first — the server gates rt↔client lineage at the
// ExchangeToken layer, 2026-10-12 live-verified code 10101), per-identity
// versions, the Cloud-IDE-JWT Authorization header, the magpie DeviceInfo
// value domain, the single api.trae.cn host (no fan-out), the 20403
// device-bind short-circuit, bound-first ordering in refreshLocked, and the
// legacy-path fallback when the bound renewal is refused on both identities.
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

// TestBoundExchangeIdentitiesLineageAware: v0.12.75 谱系感知梯子。服务器在
// ExchangeToken 交换层门禁 rt↔client 谱系（2026-10-12 live 实证：cn rt 用
// SOLO client en1oxy7wnw8j9n 交换 → http 400 code 10101 "refresh token is
// not matched to the client"），own-lineage rung 是唯一可能成功的 rung，
// 必须第一。cn/空/intl/未知 → IDE_PC 第一；solo/solo-intl/"  SOLO  "
// （IsSoloVariant 大小写空白容忍）→ SOLO_PC 第一。另一 rung 保留为
// variant 错标时的自愈兜底。
func TestBoundExchangeIdentitiesLineageAware(t *testing.T) {
	solo := exchangeIdentity{ClientID: soloExchangeClient, PlatformCode: "SOLO_PC", Version: soloExchangeVersion}
	ide := exchangeIdentity{ClientID: ideExchangeClient, PlatformCode: "IDE_PC", Version: ideExchangeVersion}
	cases := []struct {
		variant string
		first   exchangeIdentity
		second  exchangeIdentity
	}{
		// cn/空/未知 → 解析为 cn 谱系（与 ClientIDFor 一致）→ IDE_PC 第一。
		{"cn", ide, solo},
		{"", ide, solo},
		{"intl", ide, solo}, // intl 同为 non-solo client id
		{"mystery-lineage", ide, solo},
		// solo 谱系 → SOLO_PC 第一。
		{"solo", solo, ide},
		{"solo-intl", solo, ide},
		{"  SOLO  ", solo, ide}, // IsSoloVariant 内置归一化
	}
	for _, tc := range cases {
		ids := boundExchangeIdentities(tc.variant)
		if len(ids) != 2 {
			t.Fatalf("variant %q: identity ladder = %+v, want exactly 2 rungs", tc.variant, ids)
		}
		if ids[0] != tc.first {
			t.Errorf("variant %q: first identity = %+v, want %+v (own lineage first — the other order burns a guaranteed-dead 10101 attempt)", tc.variant, ids[0], tc.first)
		}
		if ids[1] != tc.second {
			t.Errorf("variant %q: second identity = %+v, want %+v (kept as the mislabeled-variant self-heal rung)", tc.variant, ids[1], tc.second)
		}
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

// TestRefreshLockedBoundExchangeLineageLadder drives a REAL httptest server
// (boundExchangeHost injected) through c.RefreshToken for a cn account: the
// first request must carry the IDE identity (v0.12.75 own-lineage first —
// the server's rt↔client lineage gate, live-verified 2026-10-12, answers the
// SOLO client with 400 code 10101), the second (after that refusal) the SOLO
// identity, and after both refusals the legacy /cloudide path renews. Also
// pins: the Cloud-IDE-JWT Authorization header, the magpie DeviceInfo value
// domain, the single-host strategy (the client's OAuthHost canary is never
// contacted), the proof shape, and the refresh-token rotation respect.
func TestRefreshLockedBoundExchangeLineageLadder(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	var auths []string
	var paths []string
	legacyHits := 0
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
		mu.Unlock()
		if r.URL.Path == epExchangeBound {
			// Both bound rungs refused — the live-verified 10101 lineage-gate
			// shape (http 400, flat lowercase code).
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"code":10101,"message":"refresh token is not matched to the client"}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, EpExchange) {
			t.Errorf("unexpected path %s", r.URL.Path)
			return
		}
		// Legacy /cloudide renewal (the account's apiHost, same server).
		mu.Lock()
		legacyHits++
		mu.Unlock()
		fmt.Fprint(w, `{"Result":{"Token":"legacy-token","RefreshToken":"legacy-rt","TokenExpireAt":1790000000000}}`)
	}))
	defer ts.Close()

	prevHost := boundExchangeHost
	boundExchangeHost = ts.URL
	t.Cleanup(func() { boundExchangeHost = prevHost })

	// a.APIHost is the legacy path's primary source (this server); the
	// client's OAuthHost stays a canary — the v0.12.73 fan-out would have
	// contacted it after a refusal; neither the bound path nor the legacy
	// first source may.
	c := &Client{HTTP: ts.Client(), OAuthHost: "https://oauth-fanout-canary.example"}
	a := &auth.Auth{AccessToken: "live-jwt", RefreshToken: "oldrt", ExpiresAt: 1,
		APIHost: ts.URL, Variant: "cn",
		DeviceID: "1111222233334444", MachineID: "machine-1"}
	if err := c.RefreshToken(a); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 || legacyHits != 1 {
		t.Fatalf("requests = %d (legacy hits %d), want exactly 2 bound rungs + 1 legacy renewal — no host fan-out", len(bodies), legacyHits)
	}
	bound := bodies[:2]
	// ① 谱系梯子顺序与各身份的版本号（ClientVersion 与 IDEVersion 同值）：
	// cn 账号 own-lineage IDE_PC 第一，SOLO_PC 只作 variant 错标自愈兜底。
	first, second := bound[0], bound[1]
	if first["ClientID"] != ideExchangeClient || first["IDEVersion"] != "3.3.99" {
		t.Errorf("first request ClientID/IDEVersion = %v/%v, want ono9krqynydwx5/3.3.99", first["ClientID"], first["IDEVersion"])
	}
	di1, ok := first["DeviceInfo"].(map[string]any)
	if !ok {
		t.Fatal("first DeviceInfo missing")
	}
	if di1["PlatformCode"] != "IDE_PC" || di1["ClientVersion"] != "3.3.99" {
		t.Errorf("first DeviceInfo = %v, want IDE_PC + ClientVersion 3.3.99", di1)
	}
	if second["ClientID"] != soloExchangeClient || second["IDEVersion"] != "0.1.64" {
		t.Errorf("second request ClientID/IDEVersion = %v/%v, want en1oxy7wnw8j9n/0.1.64", second["ClientID"], second["IDEVersion"])
	}
	di2, ok := second["DeviceInfo"].(map[string]any)
	if !ok {
		t.Fatal("second DeviceInfo missing")
	}
	if di2["PlatformCode"] != "SOLO_PC" || di2["ClientVersion"] != "0.1.64" {
		t.Errorf("second DeviceInfo = %v, want SOLO_PC + ClientVersion 0.1.64", di2)
	}
	// ② magpie boundExchange 带 Authorization: Cloud-IDE-JWT <token>。
	if auths[0] != "Cloud-IDE-JWT live-jwt" || auths[1] != "Cloud-IDE-JWT live-jwt" {
		t.Errorf("Authorization headers = %v, want Cloud-IDE-JWT live-jwt on every bound request", auths)
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
	// ④ 单 host：绑定路径只打注入的 boundExchangeHost；legacy 恰好一次走账号
	// apiHost 的 /cloudide EpExchange（同一 server，路径可区分），OAuthHost
	// canary 从未被联系。
	for i, p := range paths[:2] {
		if p != epExchangeBound {
			t.Errorf("bound request %d path = %q, want %q", i, p, epExchangeBound)
		}
	}
	if paths[2] != EpExchange {
		t.Errorf("legacy request path = %q, want %q", paths[2], EpExchange)
	}
	// ⑥ legacy 兜底成功 + refresh token 轮换尊重（返回了就采用）。
	if a.AccessToken != "legacy-token" {
		t.Errorf("AccessToken = %q, want legacy-token", a.AccessToken)
	}
	if a.RefreshToken != "legacy-rt" {
		t.Errorf("RefreshToken = %q, want the rotated legacy rt (a returned one is honored)", a.RefreshToken)
	}
	if exp := a.ExpiresAt; exp != 1790000000 {
		t.Errorf("ExpiresAt = %d, want ms-normalized 1790000000", exp)
	}
	// the account had no device keys → generated, attached, ready to persist
	if a.DevicePublicKey == "" || a.DevicePrivateKey == "" {
		t.Error("device key pair not generated/attached")
	}
	// proof shape on both bound requests
	for i, body := range bound {
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
	if body["ClientID"] != ideExchangeClient {
		t.Errorf("ClientID = %v, want the IDE rung (cn lineage first) even without an access token", body["ClientID"])
	}
}

// TestRefreshLockedBoundFallsBackToLegacy: both identities refused (400,
// e.g. cross-lineage mismatch on the whole ladder) → the bound path yields an
// error and the legacy /cloudide path still renews; never worse than before.
// v0.12.75: the ladder is exactly 2 attempts (IDE_PC then SOLO_PC for a cn
// account — own lineage first) — no host fan-out on top.
func TestRefreshLockedBoundFallsBackToLegacy(t *testing.T) {
	var boundClients []string
	c := testClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == epExchangeBound {
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			boundClients = append(boundClients, fmt.Sprintf("%v", body["ClientID"]))
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
	if len(boundClients) != 2 {
		t.Fatalf("bound attempts = %d, want exactly 2 (the lineage ladder, no host fan-out)", len(boundClients))
	}
	if boundClients[0] != ideExchangeClient || boundClients[1] != soloExchangeClient {
		t.Errorf("bound ladder = %v, want [%s %s] (own lineage first)", boundClients, ideExchangeClient, soloExchangeClient)
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

// TestBoundExchangeDeviceMismatchShortCircuit: v0.12.75 —— 首 rung 被
// 401 code 20403 "Token device not match" 拒（2026-10-12 live 实证：服务器
// 绑定设备与 DeviceInfo 不匹配即 20403，与 client 谱系无关）时梯子必须
// 短路：两个 rung 呈同一 DeviceInfo、同一密钥签名，次 rung 必败，继续
// 尝试只会多烧一次失败 proof（issue #38 服务端安全层教训）。cn 账号首
// rung IDE_PC、solo 账号首 rung SOLO_PC，两条谱系同样短路，legacy 兜底
// 照常成功。
func TestBoundExchangeDeviceMismatchShortCircuit(t *testing.T) {
	const mismatch = `{"ResponseMetadata":{"Error":{"Code":"20403","Message":"Token device not match."}},"Result":null}`
	cases := []struct {
		name        string
		variant     string
		firstRungID string
	}{
		{"cn first rung IDE_PC", "cn", ideExchangeClient},
		{"solo first rung SOLO_PC", "solo", soloExchangeClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var boundClients []string
			c := testClient(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == epExchangeBound {
					raw, _ := io.ReadAll(r.Body)
					var body map[string]any
					_ = json.Unmarshal(raw, &body)
					boundClients = append(boundClients, fmt.Sprintf("%v", body["ClientID"]))
					return jsonResp(http.StatusUnauthorized, mismatch), nil
				}
				if strings.HasSuffix(r.URL.Path, EpExchange) {
					return jsonResp(200, `{"Result":{"Token":"legacy-token","RefreshToken":"legacy-rt"}}`), nil
				}
				return nil, errors.New("unexpected path " + r.URL.Path)
			})
			a := &auth.Auth{AccessToken: "at", RefreshToken: "oldrt", ExpiresAt: 1, APIHost: "https://oauth.example", Variant: tc.variant, DeviceID: "1111222233334444"}
			if err := c.RefreshToken(a); err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if len(boundClients) != 1 {
				t.Fatalf("bound attempts = %d, want exactly 1 (20403 short-circuits the ladder — the next rung re-sends the same DeviceInfo signed by the same key and cannot succeed)", len(boundClients))
			}
			if boundClients[0] != tc.firstRungID {
				t.Errorf("refused rung ClientID = %v, want %s (own lineage first)", boundClients[0], tc.firstRungID)
			}
			if a.AccessToken != "legacy-token" || a.RefreshToken != "legacy-rt" {
				t.Errorf("legacy fallback tokens wrong: %q / %q", a.AccessToken, a.RefreshToken)
			}
		})
	}
}
