// bound_exchange.go — device-bound token renewal (v0.12.73 引入，v0.12.74 与
// magpie-community 权威实现逐字节对齐).
//
// The legacy refresh path (EpExchange = /cloudide/api/v3/trae/oauth/
// ExchangeToken, ClientID+RefreshToken only) yields a JWT with NO device
// binding. Trae CN's growth gate answers that JWT's check-in claim with
// 9074 「当前参与用户太多，请稍后再试」 EVERY time while the read-only
// status stays code:0 — the official client's own (device-bound) token
// claims code:0 at the same moment on the same account (magpie#808:
// mintonight's same-account side-by-side 2026-10-05; MiFaZhan's
// out-of-plugin isolation 2026-10-05/06; qilimixingkong/trae-checkin
// TECH_DESIGN §2.8). This file renews the way the official clients do:
//
//	POST /trae/api/v3/oauth/ExchangeToken
//	{
//	  "ClientID":     <renewal identity client>,
//	  "ClientSecret": "",
//	  "RefreshToken": <rt>,
//	  "DeviceInfo":   { DeviceID, MachineID, PlatformCode, DeviceType "PC",
//	                    ClientVersion, DevicePublicKey <SPKI PEM>, ... },
//	  "DeviceProof":  { Signature <ECDSA-SHA256 DER b64 over
//	                     "POST\n{path}\n{ClientID}\n{RefreshToken}\n{ts}\n{nonce}">,
//	                    Timestamp, Nonce },
//	  "IDEVersion":   <per-identity version>
//	}
//
// v0.12.74 alignment (issue #38 "refresh token is not matched to the client"
// 疑似相关): the renewal identity ladder, DeviceInfo value domain, request
// headers, host strategy and per-request timeout are now byte-aligned with
// the production-verified magpie-community reference
// (magpie-community/packages/trae index.mjs SITES["trae-cn"].deviceExchange
// 与 boundExchange/proofOf/deviceInfo, 行号区间 446-504):
//   - identities (v0.12.75 谱系感知): own-lineage rung first — solo 谱系
//     SOLO_PC (en1oxy7wnw8j9n, 0.1.64), cn/intl/空/未知谱系 IDE_PC
//     (ono9krqynydwx5, 3.3.99); each identity carries ITS OWN version in
//     ClientVersion/IDEVersion (v0.12.73 paired the SOLO version with the
//     IDE_PC platform for cn-lineage tokens — self-contradictory). v0.12.74
//     的 SOLO_PC 永远第一已被 2026-10-12 live 实证推翻：服务器在交换层
//     10101 门禁 rt↔client 谱系，cn 账号每刷新都白烧一次必败尝试；
//   - single host api.trae.cn (site.hosts.auth): the v0.12.73 multi-source
//     fan-out (apiHost → OAuthHost → backup) produced up to 4-6 failed proof
//     attempts per refresh on the bound path, and the repeated device/client
//     mismatches may trip the server's security layer;
//   - Authorization: Cloud-IDE-JWT <token> rides every request (magpie
//     boundExchange carries it; v0.12.73 omitted it);
//   - DeviceInfo: DeviceModel "" (not the brand string), OSInfo "Windows"
//     (capitalized), OSVersion "10.0.22631" (build number), DeviceCPU "AMD";
//   - 20s per-request timeout (magpie AbortSignal.timeout(20_000)).
//
// The refreshToken does not rotate on this path; a returned one is honored.
// Failure falls back to the legacy path — never worse than before.
package upstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/auth"
)

// epExchangeBound is the clients' own renewal path, which binds the JWT to
// the device named in DeviceInfo.
const epExchangeBound = "/trae/api/v3/oauth/ExchangeToken"

// magpie-community/packages/trae index.mjs SITES["trae-cn"].deviceExchange.as
// —— 身份与版本号逐项照抄（生产验证可用）；v0.12.75 起梯子顺序谱系感知
// （own-lineage 优先，见 boundExchangeIdentities），不再固定 SOLO 优先。
const (
	soloExchangeClient  = "en1oxy7wnw8j9n" // TRAE SOLO CN
	soloExchangeVersion = "0.1.64"
	ideExchangeClient   = "ono9krqynydwx5" // Trae CN IDE
	ideExchangeVersion  = "3.3.99"
	// magpie deviceInfo 的固定画像值。
	boundDeviceBrand = "ASUS TUF Gaming A15 FA507RM_FA507RM"
	boundDeviceCPU   = "AMD"
	boundOSInfo      = "Windows"
	boundOSVersion   = "10.0.22631"
	boundTimeout     = 20 * time.Second // magpie AbortSignal.timeout(20_000)
)

// boundExchangeHost：magpie site.hosts.auth——绑定续期只打这一个源。
// v0.12.73 的多源扇出（apiHost→OAuthHost→备用）在绑定路径上最多产生
// 4~6 次失败 proof 尝试，反复的设备/client 不匹配可能触发服务端安全层
// （issue #38 "refresh token is not matched to the client" 疑似相关）。
// var（非 const）供测试注入 httptest 源。
var boundExchangeHost = "https://api.trae.cn"

// exchangeIdentity is one renewal identity candidate: the client the refresh
// token is exchanged as, and the version that identity names.
type exchangeIdentity struct {
	ClientID     string
	PlatformCode string // SOLO_PC | IDE_PC
	Version      string
}

// boundExchangeIdentities returns the lineage-aware renewal identity
// ladder: the account's own-lineage rung first, the other lineage second.
//
// v0.12.75 (2026-10-12 live 实证, trae_live_payfamily_test.go leg2): the
// server gates rt↔client lineage AT the ExchangeToken layer — a cn-lineage
// rt exchanged as the SOLO client (en1oxy7wnw8j9n) is refused with
// http 400 code 10101 "refresh token is not matched to the client". The
// v0.12.74 magpie-aligned fixed ladder (SOLO_PC first for every account)
// therefore burned one guaranteed-dead attempt on every cn refresh. The
// own-lineage rung is the only rung that can succeed; the other lineage is
// kept as a self-heal fallback for a mislabeled variant — if the auth
// file's variant is wrong, the own-lineage rung 10101s and the other
// rung may still go through.
//
// Lineage resolution mirrors ClientIDFor exactly (empty/unknown → cn):
// IsSoloVariant ("solo"/"solo-intl", case/whitespace tolerant) → SOLO_PC
// first; everything else (cn/intl/empty/unknown) → IDE_PC first.
func boundExchangeIdentities(variant string) []exchangeIdentity {
	solo := exchangeIdentity{ClientID: soloExchangeClient, PlatformCode: "SOLO_PC", Version: soloExchangeVersion}
	ide := exchangeIdentity{ClientID: ideExchangeClient, PlatformCode: "IDE_PC", Version: ideExchangeVersion}
	if IsSoloVariant(variant) {
		return []exchangeIdentity{solo, ide}
	}
	return []exchangeIdentity{ide, solo}
}

// deviceProofPayload is the exact string the device key signs:
// method, path, client, refresh token, unix seconds, nonce — one per line.
func deviceProofPayload(path, clientID, refreshToken string, ts int64, nonce string) string {
	return strings.Join([]string{"POST", path, clientID, refreshToken, fmt.Sprintf("%d", ts), nonce}, "\n")
}

// newProofNonce mints a 128-bit hex nonce per attempt (the clients mint one
// per renewal; trae-checkin "%032x" / magpie randomBytes(16).toString("hex")).
func newProofNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// boundDeviceInfo mirrors magpie deviceInfo (index.mjs:429-444): the device
// a renewal names, its public key with it. v0.12.74 value-domain alignment:
// DeviceModel is EMPTY (v0.12.73 误填品牌串), OSInfo "Windows"（v0.12.73 是
// 小写 "windows"）, OSVersion "10.0.22631"（构建号；v0.12.73 是
// "Windows 11 Pro"）, DeviceCPU "AMD".
func boundDeviceInfo(a *auth.Auth, id exchangeIdentity) map[string]any {
	return map[string]any{
		"DeviceID":        a.DeviceID,
		"MachineID":       a.MachineID,
		"PlatformCode":    id.PlatformCode,
		"DeviceType":      "PC",
		"DeviceName":      "",
		"DeviceModel":     "",         // magpie：空（v0.12.73 误填品牌串）
		"ClientVersion":   id.Version, // 每身份自己的版本号
		"DevicePublicKey": a.DevicePublicKey,
		"DeviceBrand":     boundDeviceBrand,
		"DeviceCPU":       boundDeviceCPU,
		"OSInfo":          boundOSInfo,    // "Windows"（v0.12.73 是小写 "windows"）
		"OSVersion":       boundOSVersion, // 构建号（v0.12.73 是 "Windows 11 Pro"）
	}
}

// ensureDeviceKeyLocked returns the account's device key pair, generating and
// attaching one when the account predates the bound renewal (older logins).
// The generated pair persists with the next SaveAtomic, so every later
// renewal signs with the SAME key the server bound — magpie keeps this
// contract too ("a device key made for the account goes with either").
// Caller must hold a's write lock.
func ensureDeviceKeyLocked(a *auth.Auth) {
	if strings.TrimSpace(a.DevicePublicKey) != "" && strings.TrimSpace(a.DevicePrivateKey) != "" {
		return
	}
	pubPEM, privPEM, err := auth.GenerateDeviceKeyPair()
	if err != nil {
		return // bound exchange will fail without keys; legacy path still renews
	}
	a.DevicePublicKey = pubPEM
	a.DevicePrivateKey = privPEM
}

// isTokenDeviceNotMatch reports whether err is the server's device-bind
// refusal: http 401 code 20403 "Token device not match" (2026-10-12 live
// 实证：服务器绑定设备与 DeviceInfo 不匹配即 20403，与 client 谱系无关).
// Msg is the body fragment doJSON embeds; the ResponseMetadata nested
// envelope spells the uppercase "Code" shape, the flat lowercase "code"
// shape is tolerated too.
func isTokenDeviceNotMatch(err error) bool {
	ue, ok := err.(*Error)
	if !ok || ue == nil {
		return false
	}
	return strings.Contains(ue.Msg, `"Code":"20403"`) || strings.Contains(ue.Msg, `"code":20403`)
}

// boundExchangeLocked renews the JWT the official-client way so it is bound
// to the account's device. v0.12.74 magpie 对齐：单 host（boundExchangeHost）、
// 每请求 20s ctx 超时、带 Authorization: Cloud-IDE-JWT 头；v0.12.75：身份梯子
// 谱系感知（own-lineage rung 优先）+ 20403 短路。Every failure path leaves
// a untouched (the refreshLocked atomicity contract). Caller must hold a's
// write lock.
func (c *Client) boundExchangeLocked(a *auth.Auth) error {
	if strings.TrimSpace(a.RefreshToken) == "" {
		return fmt.Errorf("no refreshToken")
	}
	ensureDeviceKeyLocked(a)
	if a.DevicePublicKey == "" || a.DevicePrivateKey == "" {
		return fmt.Errorf("no device key pair")
	}
	rt := a.RefreshToken // held write lock
	// ⚠️ 持 a 写锁期间禁止调 a.JWT()（RLock 重入死锁），直接读 a.AccessToken。
	at := strings.TrimSpace(a.AccessToken)
	var lastErr error
	for _, id := range boundExchangeIdentities(a.Variant) {
		ts := time.Now().Unix()
		nonce := newProofNonce()
		proof, err := auth.SignDeviceProof(a.DevicePrivateKey, deviceProofPayload(epExchangeBound, id.ClientID, rt, ts, nonce))
		if err != nil {
			return err // key material problem: no point trying the other identity
		}
		body := map[string]any{
			"ClientID":     id.ClientID,
			"ClientSecret": "",
			"RefreshToken": rt,
			"DeviceInfo":   boundDeviceInfo(a, id),
			"DeviceProof": map[string]any{
				"Signature": proof,
				"Timestamp": ts,
				"Nonce":     nonce,
			},
			"IDEVersion": id.Version,
		}
		raw, _ := json.Marshal(body)
		// magpie AbortSignal.timeout(20_000)：每请求独立 20s 预算。
		ctx, cancel := context.WithTimeout(context.Background(), boundTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, boundExchangeHost+epExchangeBound, bytes.NewReader(raw))
		if err != nil {
			cancel()
			return err
		}
		OAuthHeaders(req)
		if at != "" {
			req.Header.Set("Authorization", "Cloud-IDE-JWT "+at)
		}
		data, err := c.doJSON(req)
		cancel()
		if err != nil {
			lastErr = err
			// v0.12.75: 20403 短路。两个 rung 呈同一 DeviceInfo、同一密钥
			// 签名——第一个 rung 20403 后第二个 rung 必然也败（2026-10-12
			// live 证据：服务器绑定设备与 DeviceInfo 不匹配即 20403，与
			// client 谱系无关），继续尝试只会多烧一次失败 proof
			// （issue #38 服务端安全层教训）。
			if isTokenDeviceNotMatch(err) {
				break
			}
			continue
		}
		token, refreshToken, expiresAt, ok := parseBoundExchange(data)
		if !ok {
			lastErr = fmt.Errorf("bound exchange: no token in response")
			continue
		}
		a.AccessToken = token
		if refreshToken != "" {
			a.RefreshToken = refreshToken
		}
		if expiresAt > 0 {
			a.ExpiresAt = expiresAt
		}
		log.Printf("exchange refresh (bound): uid=%s variant=%q client=%s platform=%s", a.UID, a.Variant, id.ClientID, id.PlatformCode)
		return nil
	}
	return lastErr
}

// parseBoundExchange reads the ExchangeToken envelope (Result.Token /
// TokenExpireAt, refreshToken optional) shared by both renewal paths.
func parseBoundExchange(data []byte) (token, refreshToken string, expiresAt int64, ok bool) {
	var resp struct {
		Result struct {
			Token               string `json:"Token"`
			TokenExpireAt       int64  `json:"TokenExpireAt"`
			TokenExpireDuration int64  `json:"TokenExpireDuration"`
			RefreshToken        string `json:"RefreshToken"`
		} `json:"Result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", "", 0, false
	}
	if resp.Result.Token == "" {
		return "", "", 0, false
	}
	exp := int64(0)
	if resp.Result.TokenExpireAt > 0 {
		exp = normalizeExpiresAt(resp.Result.TokenExpireAt)
	} else if resp.Result.TokenExpireDuration > 0 {
		exp = time.Now().Add(time.Duration(resp.Result.TokenExpireDuration) * time.Second).Unix()
	}
	return resp.Result.Token, resp.Result.RefreshToken, exp, true
}
