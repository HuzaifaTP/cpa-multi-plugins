// image_upload.go — issue #37: 把消息里的 data: URI 图片上传到 Qoder 的
// 文件 API 换 OSS URL（官方 qodercli 的图片通道）。
//
// 协议依据（两个独立生产实现的同源模块，主代理已全文核对）：
// PawanOsman/OpenCursor 与 decolua/9router 的 attachments.{ts,js}：
//  1. 官方 qodercli 不把图片字节内联进 agent_chat_generation：先
//     PUT {推理网关}/algo/api/v2/image/upload?request_id=<uuid>（COSY 签名
//     multipart，字段名 "file"，filename image.<ext>），拿返回的 OSS URL，
//     再把 URL 放进消息 content 的 OpenAI 形 image_url 块。
//  2. 顶层 image_urls 与 chat_context.imageUrls 保持 null——官方客户端
//     自己就留空（legacy 字段，不是图片通道），本插件沿 baseprompt.json
//     模板原样保留。
//  3. 大小护栏对齐 OpenCursor 常量：整包 6MB 上限（QODER_MAX_PAYLOAD_BYTES，
//     此处实现为内联保底的累计预算）；上传失败时 ≤512KB
//     （QODER_INLINE_FALLBACK_MAX_BYTES）的 data URI 内联保底、>512KB 替换
//     为文本桩。
//
// 2026-10-12 实弹矩阵探测（intl，20 变体，见 qoder_live_upload_matrix_
// test.go）：intl 网关的该端点已迁移——官方 CLI 1.1.68 bundle 实锤上传走
// CENTER 端点（center.qoder.sh/algo/api/v2/image/upload，SO() 函数给所有
// base 自动补 /algo 前缀），且鉴权是 wasm 内部的 "auth" 签名方案
// （qodercontext_prepareRequest，QoderContext 持 uid/encrypt_user_info/key），
// 二进制 body 不进 wasm → 无法在插件侧复刻。api3+/algo+COSY 方言（生态
// 三方实现的写法）在 intl 实测 403 "Signature invalid"（code 101）——三方
// 实现的优雅回退掩盖了这一点。本实现保留该方言为尽力路径（CN 网关
// gateway.qoder.com.cn 未测、可能仍接受；intl 若重开亦直接受益），失败时
// 走降级契约。图片可见性的主修复是 body.go 的官方 contents 方言对齐。
//
// 定位（v0.8.67 起）：本文件是**探测/ Round-2 基础设施**，未接入执行器——
// qoder 0.8.63 的诚实拒绝守卫（body_vision_test.go）在图片请求到达构建层
// 之前就已显式失败，本上传流因此不再有生产调用方。保留它是因为：
//  1. -tags live 的上传/方言矩阵探测（qoder_live_upload*_test.go、
//     qoder_live_image_test.go）以它为驱动——那是未来在 discharged 路径上
//     验证 center/wasm 端点、并把 #37 从"拒绝"升级为"转发"的工具链；
//  2. CN 网关（gateway.qoder.com.cn）对该方言的接受性未测——若接受，
//     重接执行器只需两行（rewriteMessageImages 调用已在 v0.8.66 前身
//     637135e 中验证过形状）。
//
// 降级契约（供未来重接时遵守）：任何上传失败都不让聊天请求失败——
// ≤512KB 且整包预算未耗尽的图片原样内联，其余桩化为文本说明。
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// imageUploadSigPath 是签名路径：buildBearer 会剥掉 /algo 前缀后参与
	// md5 签名，与 chat / model/list 端点的口径一致。
	imageUploadSigPath = "/api/v2/image/upload"
	// imageInlineFallbackMaxBytes 对齐 OpenCursor 的
	// QODER_INLINE_FALLBACK_MAX_BYTES：上传失败时仅 ≤512KB 的 data URI
	// 内联保底（解码后字节数）。
	imageInlineFallbackMaxBytes = 512 * 1024
	// imageMaxPayloadBytes 对齐 OpenCursor 的 QODER_MAX_PAYLOAD_BYTES：
	// 整包 6MB 上限，此处实现为内联保底的累计预算——多张 fallback 图片
	// 的内联总量不得超过该值，超出后一律桩化，避免把请求撑爆。
	imageMaxPayloadBytes = 6 * 1024 * 1024
	// imageUploadCacheMaxEntries 限定进程级上传缓存的容量，超限时淘汰任意
	// 条目（缓存只用于免重传，不是正确性依赖）。
	imageUploadCacheMaxEntries = 64
	// imageUploadResponseCap 限制上传响应体的读取上限，防止异常网关挂死
	// 内存（正常响应是一小段 JSON）。
	imageUploadResponseCap = 64 * 1024
)

// imageUploadBaseOverride is nil in production; tests point it at an
// httptest server. Same seam pattern as billingBaseOverride — the upstream
// base consts are compile-time, so this indirection is the only way an
// HTTP-level test can redirect the upload endpoint.
var imageUploadBaseOverride func(sa *storedAuth) string

// imageUploadBaseFor resolves the upload gateway base for one account,
// honoring the test override. Also namespaces the upload cache: in tests
// every httptest server gets its own cache namespace (in production the
// base is a per-region constant, so the namespace is stable).
func imageUploadBaseFor(sa *storedAuth) string {
	if imageUploadBaseOverride != nil {
		return imageUploadBaseOverride(sa)
	}
	return gatewayBaseFor(sa)
}

// imageUploadEndpointFor builds the OSS upload URL for one account:
// {推理网关}/algo/api/v2/image/upload?request_id=<uuid>。request_id 用
// uuid（OpenCursor 同做法），查询串不参与 COSY 签名（签名只覆盖 path）。
func imageUploadEndpointFor(sa *storedAuth) string {
	return imageUploadBaseFor(sa) + "/algo" + imageUploadSigPath + "?request_id=" + uuid.NewString()
}

// imageUploadHTTPClient 是上传专用的独立 client：15s 硬超时（图片上传
// 绝不能拖住聊天请求的主流程）。Transport 沿用 directProxyFunc（host
// config 的 proxy-url / 环境变量）并禁用 HTTP/2——与 sharedHTTPClient 同
// 理由：APISIX 网关会在 HTTP/2 连接中途 EOF（v0.8.50），上传走 h1.1 直连。
func imageUploadHTTPClient() *http.Client {
	imageUploadClientOnce.Do(func() {
		imageUploadClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:           directProxyFunc,
				TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
				IdleConnTimeout: 90 * time.Second,
			},
		}
	})
	return imageUploadClient
}

var (
	imageUploadClientOnce sync.Once
	imageUploadClient     *http.Client
)

// parseDataURI 解析 `data:<mime>;base64,<b64>`。容错 base64 中的空白
// （\r\n 是常见的行折叠）；非 base64（如 URL-encoded payload）或非
// image/* mime 返回 !ok——调用方将其桩化为文本，而不是让请求失败。
func parseDataURI(s string) (mime string, data []byte, ok bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "data:") {
		return "", nil, false
	}
	rest := s[len("data:"):]
	comma := strings.Index(rest, ",")
	if comma < 0 {
		return "", nil, false
	}
	meta, payload := rest[:comma], rest[comma+1:]
	mime = meta
	isBase64 := false
	if idx := strings.Index(meta, ";"); idx >= 0 {
		mime = meta[:idx]
		for _, param := range strings.Split(meta[idx+1:], ";") {
			if strings.EqualFold(strings.TrimSpace(param), "base64") {
				isBase64 = true
			}
		}
	}
	if !isBase64 {
		return "", nil, false
	}
	mime = strings.ToLower(strings.TrimSpace(mime))
	if !strings.HasPrefix(mime, "image/") || mime == "image/" {
		return "", nil, false
	}
	// 容错 base64 空白：剔除后再解码。
	var cleaned strings.Builder
	cleaned.Grow(len(payload))
	for _, r := range payload {
		switch r {
		case ' ', '\t', '\r', '\n':
			continue
		}
		cleaned.WriteRune(r)
	}
	decoded, err := base64.StdEncoding.DecodeString(cleaned.String())
	if err != nil {
		// 无 padding 的变体（RawStdEncoding）也接受。
		decoded, err = base64.RawStdEncoding.DecodeString(cleaned.String())
		if err != nil {
			return "", nil, false
		}
	}
	if len(decoded) == 0 {
		return "", nil, false
	}
	return mime, decoded, true
}

// imageExtForMime 把 mime 映射为上传文件扩展名：png/jpg/jpeg/gif/webp/bmp
// 原样，其余（avif/heic/未知）统一 bin——网关只按文件名后缀转发，未知
// 扩展名保底比猜一个强。
func imageExtForMime(mime string) string {
	switch strings.ToLower(strings.TrimSpace(mime)) {
	case "image/png":
		return "png"
	case "image/jpg", "image/jpeg":
		return "jpg"
	case "image/gif":
		return "gif"
	case "image/webp":
		return "webp"
	case "image/bmp":
		return "bmp"
	}
	return "bin"
}

// uploadURLListKeys / uploadURLStringKeys 固定键扫描顺序，对齐 OpenCursor
// extractUrlFromUploadResponse：数组形优先（imageUrls/image_urls），再扫
// 单值 string 字段。
var (
	uploadURLListKeys   = []string{"imageUrls", "image_urls"}
	uploadURLStringKeys = []string{"imageUrl", "image_url", "url", "ossUrl", "oss_url", "originalUrl", "originUrl", "link", "image"}
)

// extractUploadURL 在上传响应 JSON 里找 OSS URL。扫描顺序（对齐
// OpenCursor）：result.imageUrls[0] → result.image_urls[0] → 顶层
// imageUrls[0]/image_urls[0]（元素须为非空 string）→ result 与顶层的
// imageUrl/image_url/url/ossUrl/oss_url/originalUrl/originUrl/link/image
// string 字段 → body 字段是 string 时尝试 JSON.parse 后递归同样扫描。
func extractUploadURL(body []byte) string {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	return extractUploadURLFromObj(doc)
}

func extractUploadURLFromObj(doc map[string]json.RawMessage) string {
	if doc == nil {
		return ""
	}
	scopes := make([]map[string]json.RawMessage, 0, 2)
	if raw, ok := doc["result"]; ok {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(raw, &result); err == nil {
			scopes = append(scopes, result)
		}
	}
	scopes = append(scopes, doc)
	// 1. 数组形：imageUrls / image_urls 的首个非空 string 元素。
	for _, scope := range scopes {
		for _, key := range uploadURLListKeys {
			raw, ok := scope[key]
			if !ok {
				continue
			}
			var list []json.RawMessage
			if err := json.Unmarshal(raw, &list); err != nil {
				continue
			}
			for _, el := range list {
				var s string
				if err := json.Unmarshal(el, &s); err == nil && strings.TrimSpace(s) != "" {
					return s
				}
			}
		}
	}
	// 2. 单值 string 字段。
	for _, scope := range scopes {
		for _, key := range uploadURLStringKeys {
			raw, ok := scope[key]
			if !ok {
				continue
			}
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	// 3. body 字段是 string（网关二次包装的 JSON 文本）→ parse 后递归。
	for _, scope := range scopes {
		raw, ok := scope["body"]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || !strings.HasPrefix(strings.TrimSpace(s), "{") {
			continue
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &nested); err == nil {
			if u := extractUploadURLFromObj(nested); u != "" {
				return u
			}
		}
	}
	return ""
}

// qoderUploadImage 把图片字节 PUT 到 Qoder 的文件 API，返回 OSS URL。
//
// 签名口径：multipart 原样字节参与 COSY md5 签名（headers() 的 body
// 参数就是发送字节串），签名后再把 content-type 覆盖为
// multipart/form-data; boundary=<boundary>——签名不覆盖 content-type，
// OpenCursor 同做法。额外带 AI-CLIENT-TIMESTAMP（unix 秒）对齐官方客户端。
func qoderUploadImage(sa *storedAuth, data []byte, mime string) (string, error) {
	if sa == nil || sa.Auth.AccessToken == "" {
		return "", errors.New("image upload: no credential")
	}
	ext := imageExtForMime(mime)

	// multipart：字段 "file"，filename image.<ext>，part Content-Type = mime。
	// boundary 由 multipart.Writer 自造；整个 body 先落 buffer，保证签名的
	// 字节串与发送的字节串完全一致（models.go 的 body==signed-body 教训）。
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="image.%s"`, ext))
	h.Set("Content-Type", mime)
	part, err := w.CreatePart(h)
	if err != nil {
		return "", fmt.Errorf("image upload: multipart: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return "", fmt.Errorf("image upload: multipart body: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("image upload: multipart close: %w", err)
	}
	body := buf.Bytes()

	rawURL := imageUploadEndpointFor(sa)
	sess, err := cosySessionFor(sa)
	if err != nil {
		return "", fmt.Errorf("image upload: cosy: %w", err)
	}
	// 签名时 accept 用 application/json（headers() 会写入 accept 头），
	// content-type 先按默认参与头集生成、签名后覆盖为 multipart。
	hdr, err := sess.headers(sa.Account.UID, string(body), rawURL, "application/json", false)
	if err != nil {
		return "", fmt.Errorf("image upload: cosy sign: %w", err)
	}
	hdr["content-type"] = w.FormDataContentType()
	hdr["AI-CLIENT-TIMESTAMP"] = strconv.FormatInt(time.Now().Unix(), 10)
	// 上传端点比 chat/models 端点更严格：还会校验请求体完整性三头与
	// sigpath 回显（实测 403 "Signature invalid" code 101；对齐 OpenCursor
	// buildCosyHeaders 的完整头集——Cosy-Bodyhash/Bodylength/Sigpath +
	// X-Request-Id + Machineos + Organization 空占位）。签名本身不覆盖这些
	// 头，补在签名之后不影响 bearer。
	sum := md5.Sum(body)
	u, _ := url.Parse(rawURL)
	sigPath := u.Path
	if strings.HasPrefix(sigPath, "/algo") {
		sigPath = sigPath[len("/algo"):]
	}
	hdr["cosy-bodyhash"] = hex.EncodeToString(sum[:])
	hdr["cosy-bodylength"] = strconv.Itoa(len(body))
	hdr["cosy-sigpath"] = sigPath
	hdr["x-request-id"] = uuid.NewString()
	hdr["cosy-machineos"] = "x86_64_windows"
	hdr["cosy-organization-id"] = ""
	hdr["cosy-organization-tags"] = ""

	req, err := http.NewRequest(http.MethodPut, rawURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := imageUploadHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("image upload: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, imageUploadResponseCap+1))
	if err != nil {
		return "", fmt.Errorf("image upload: read response: %w", err)
	}
	if len(respBody) > imageUploadResponseCap {
		return "", errors.New("image upload: response exceeds size cap")
	}
	if resp.StatusCode != http.StatusOK {
		snippet := respBody
		if len(snippet) > 180 {
			snippet = snippet[:180]
		}
		return "", fmt.Errorf("image upload: status %d: %s", resp.StatusCode, snippet)
	}
	ossURL := extractUploadURL(respBody)
	if ossURL == "" {
		return "", errors.New("upload response missing url")
	}
	return ossURL, nil
}

// imageUploadCacheKey 以 网关base + 内容 sha256 为键：CN/Intl 网关返回的
// OSS URL 不保证跨网关可用，区域隔离是最小正确性边界。
type imageUploadCacheKey struct {
	base string
	sum  [sha256.Size]byte
}

// imageUploadCache 是进程级 sha256→URL 缓存：同一张图在同一次会话里重复
// 出现（多轮重发、网关重试）时免重传。容量上限 imageUploadCacheMaxEntries，
// 超限淘汰任意条目——缓存只是性能优化，不是正确性依赖。
var imageUploadCache = struct {
	sync.Mutex
	m map[imageUploadCacheKey]string
}{m: make(map[imageUploadCacheKey]string)}

// cachedImageUpload 是缓存包装的上传：命中直接返回，未命中上传并写入。
func cachedImageUpload(sa *storedAuth, data []byte, mime string) (string, error) {
	key := imageUploadCacheKey{base: imageUploadBaseFor(sa), sum: sha256.Sum256(data)}
	imageUploadCache.Lock()
	if u, ok := imageUploadCache.m[key]; ok {
		imageUploadCache.Unlock()
		return u, nil
	}
	imageUploadCache.Unlock()

	u, err := qoderUploadImage(sa, data, mime)
	if err != nil {
		return "", err
	}
	imageUploadCache.Lock()
	if len(imageUploadCache.m) >= imageUploadCacheMaxEntries {
		// 淘汰任意一条即可（map 迭代顺序随机）：缓存语义只求"最近用过
		// 的大概率还在"，不做 LRU。
		for k := range imageUploadCache.m {
			delete(imageUploadCache.m, k)
			break
		}
	}
	imageUploadCache.m[key] = u
	imageUploadCache.Unlock()
	return u, nil
}

// requestHasInlineDataImages 是热路径预扫描：所有 rawContent 都不含
// "data:" 子串就必然没有内联图片，直接返回——无图请求零解析零分配。
func requestHasInlineDataImages(req *openAIRequest) bool {
	for i := range req.Messages {
		if strings.Contains(req.Messages[i].rawContent, "data:") {
			return true
		}
		if strings.Contains(req.Messages[i].Content, "data:") {
			// 纯文本 content 里出现的 data:（如用户粘贴的 URI 字符串）
			// 不是图片块，但让它走完整扫描无害：块级判断会过滤掉。
			return true
		}
	}
	return false
}

// imageLogSubject 选上传日志的主语：优先账号 UID，缺失时退回请求模型名
// （执行器调用点的统一日志口径）。
func imageLogSubject(authUID, model string) string {
	if authUID != "" {
		return authUID
	}
	return model
}

// rewriteMessageImages 遍历请求消息，把 data: URI 图片块上传换 OSS URL。
//
// 规则（issue #37 修改清单）：
//   - url 为 http(s):// → 不动（已是远端 URL）
//   - parseDataURI 失败（非图片/坏 base64）→ 文本桩
//     "[file omitted: unreadable or non-image data URI]"
//   - 上传成功 → 替换为 {"type":"image_url","image_url":{"url":<ossURL>}}
//   - 上传失败且解码后 ≤512KB 且整包内联预算未耗尽 → 保留原样（内联保底）
//   - 上传失败且 >512KB（或预算耗尽）→ 文本桩
//     "[image omitted: upload failed, <N> bytes]"
//
// 仅当消息数组有实际改动时才重新 Marshal 回 rawContent——无改动的消息
// 保持字节级原样。返回 (uploaded, stubbed) 统计，调用方在 >0 时打日志。
// 任何上传失败都不向上传播（降级契约）。
func rewriteMessageImages(sa *storedAuth, req *openAIRequest) (uploaded, stubbed int) {
	if req == nil || !requestHasInlineDataImages(req) {
		return 0, 0
	}
	inlineBudget := imageMaxPayloadBytes
	for i := range req.Messages {
		m := &req.Messages[i]
		raw := m.rawContent
		if !strings.HasPrefix(raw, "[") {
			continue
		}
		if !strings.Contains(raw, "data:") {
			continue
		}
		var parts []map[string]any
		if err := json.Unmarshal([]byte(raw), &parts); err != nil {
			// 解析失败：不动该消息（fail-open，原样透传）。
			continue
		}
		changed := false
		for j, part := range parts {
			if t, _ := part["type"].(string); t != "image_url" {
				continue
			}
			iu, _ := part["image_url"].(map[string]any)
			if iu == nil {
				continue
			}
			urlStr, _ := iu["url"].(string)
			if !strings.HasPrefix(urlStr, "data:") {
				continue
			}
			mime, data, ok := parseDataURI(urlStr)
			if !ok {
				parts[j] = map[string]any{"type": "text", "text": "[file omitted: unreadable or non-image data URI]"}
				changed = true
				stubbed++
				continue
			}
			ossURL, err := cachedImageUpload(sa, data, mime)
			if err == nil {
				parts[j] = map[string]any{"type": "image_url", "image_url": map[string]any{"url": ossURL}}
				changed = true
				uploaded++
				continue
			}
			if len(data) <= imageInlineFallbackMaxBytes && len(data) <= inlineBudget {
				// 内联保底：保留原样（不置 changed，保持字节级原样）。
				inlineBudget -= len(data)
				continue
			}
			parts[j] = map[string]any{"type": "text", "text": fmt.Sprintf("[image omitted: upload failed, %d bytes]", len(data))}
			changed = true
			stubbed++
		}
		if !changed {
			continue
		}
		enc, err := json.Marshal(parts)
		if err != nil {
			// 编码失败：不动原消息（fail-open）。
			continue
		}
		m.rawContent = string(enc)
	}
	return uploaded, stubbed
}
