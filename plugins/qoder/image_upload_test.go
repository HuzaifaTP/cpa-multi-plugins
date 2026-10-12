// image_upload_test.go — issue #37 hermetic coverage for the OSS image
// channel: data URI parsing, the upload wire format (path / query /
// multipart / cosy headers), response URL extraction shapes, and the
// rewrite ladder (upload → inline fallback → text stub).
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// tinyPNGURI builds a data:image/png URI around arbitrary bytes (the bytes
// need not be a real PNG — only the mime/base64 layer is under test).
func tinyPNGURI(data []byte) string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
}

func imageTestAuth() *storedAuth {
	return &storedAuth{
		Auth:    storedTokens{AccessToken: "dt-image-test", Region: regionCN},
		Account: storedAccount{UID: "u-image-test", Nickname: "img"},
	}
}

func stubImageUploadBase(t *testing.T, base string) {
	t.Helper()
	prev := imageUploadBaseOverride
	imageUploadBaseOverride = func(*storedAuth) string { return base }
	t.Cleanup(func() { imageUploadBaseOverride = prev })
}

func resetImageUploadCache() {
	imageUploadCache.Lock()
	imageUploadCache.m = make(map[imageUploadCacheKey]string)
	imageUploadCache.Unlock()
}

// capturedUpload records what one upload PUT actually carried on the wire.
type capturedUpload struct {
	Method      string
	Path        string
	RequestID   string
	ContentType string
	FormName    string
	Filename    string
	PartCT      string
	FileBytes   []byte
	CosyKey     string
	Authz       string
	CosyUser    string
	Timestamp   string
}

// newImageUploadServer spins up the fake /algo/api/v2/image/upload endpoint.
// Every hit records into captured (last one wins) and bumps hits. Uploads in
// one rewriteMessageImages call are sequential, so no lock is needed.
func newImageUploadServer(t *testing.T, status int, body string, captured *capturedUpload, hits *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits++
		}
		c := capturedUpload{
			Method:      r.Method,
			Path:        r.URL.Path,
			RequestID:   r.URL.Query().Get("request_id"),
			ContentType: r.Header.Get("Content-Type"),
			CosyKey:     r.Header.Get("cosy-key"),
			Authz:       r.Header.Get("Authorization"),
			CosyUser:    r.Header.Get("cosy-user"),
			Timestamp:   r.Header.Get("AI-CLIENT-TIMESTAMP"),
		}
		if mr, err := r.MultipartReader(); err == nil {
			if part, err := mr.NextPart(); err == nil {
				c.FormName = part.FormName()
				c.Filename = part.FileName()
				c.PartCT = part.Header.Get("Content-Type")
				c.FileBytes, _ = io.ReadAll(part)
			}
		}
		if captured != nil {
			*captured = c
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// imageRequest builds an OpenAI request whose last user message carries the
// given raw structured content.
func imageRequest(rawContent string) *openAIRequest {
	return &openAIRequest{
		Model: "qfmodel",
		Messages: []openAIMessage{
			{Role: "system", Content: "you are a harness"},
			{Role: "user", rawContent: rawContent, contentSet: true},
		},
	}
}

// -----------------------------------------------------------------------------

func TestParseDataURI(t *testing.T) {
	png := tinyPNGURI([]byte{0x89, 'P', 'N', 'G', 1, 2, 3})
	cases := []struct {
		name     string
		in       string
		wantMime string
		wantOK   bool
	}{
		{"png", png, "image/png", true},
		{"jpeg", "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString([]byte("jpegdata")), "image/jpeg", true},
		{"uppercase-mime", "data:image/PNG;base64," + base64.StdEncoding.EncodeToString([]byte("x")), "image/png", true},
		{
			// 行折叠空白容错：base64 中的 \r\n 必须被剔除后再解码。
			"folded-base64",
			"data:image/png;base64,iVBORw0KGgoAAA\r\nANSUhEUgAAAAEAAAAB",
			"image/png", true,
		},
		{
			// 无 padding 变体（RawStdEncoding）。
			"raw-std-no-padding",
			"data:image/png;base64," + base64.RawStdEncoding.EncodeToString([]byte("nopadding")),
			"image/png", true,
		},
		{"not-base64", "data:image/png,%89PNG%0D%0A", "", false},
		{"not-image-mime", "data:text/plain;base64," + base64.StdEncoding.EncodeToString([]byte("hello")), "", false},
		{"empty-mime", "data:;base64," + base64.StdEncoding.EncodeToString([]byte("x")), "", false},
		{"no-comma", "data:image/png;base64", "", false},
		{"no-prefix", "image/png;base64,AAAA", "", false},
		{"empty-payload", "data:image/png;base64,", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mime, data, ok := parseDataURI(c.in)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if mime != c.wantMime {
				t.Errorf("mime = %q, want %q", mime, c.wantMime)
			}
			if len(data) == 0 {
				t.Error("decoded data empty")
			}
		})
	}
}

func TestImageExtForMime(t *testing.T) {
	cases := []struct{ mime, want string }{
		{"image/png", "png"},
		{"image/PNG", "png"},
		{"image/jpg", "jpg"},
		{"image/jpeg", "jpg"},
		{"image/gif", "gif"},
		{"image/webp", "webp"},
		{"image/bmp", "bmp"},
		{"image/avif", "bin"},
		{"", "bin"},
		{"application/pdf", "bin"},
	}
	for _, c := range cases {
		if got := imageExtForMime(c.mime); got != c.want {
			t.Errorf("imageExtForMime(%q) = %q, want %q", c.mime, got, c.want)
		}
	}
}

// TestQoderUploadImageWire pins the wire contract: PUT to the signed path
// with a request_id query, multipart field "file" named image.<ext> with the
// part Content-Type set, cosy headers present, and the result.imageUrls[0]
// shape extracted.
func TestQoderUploadImageWire(t *testing.T) {
	resetImageUploadCache()
	img := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 9, 9, 9}
	var cap capturedUpload
	hits := 0
	srv := newImageUploadServer(t, http.StatusOK,
		`{"code":200,"result":{"imageUrls":["https://oss.example/u/x.png"]}}`, &cap, &hits)
	stubImageUploadBase(t, srv.URL)

	url, err := qoderUploadImage(imageTestAuth(), img, "image/png")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if url != "https://oss.example/u/x.png" {
		t.Errorf("url = %q", url)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if cap.Method != http.MethodPut {
		t.Errorf("method = %s, want PUT", cap.Method)
	}
	if cap.Path != "/algo/api/v2/image/upload" {
		t.Errorf("path = %q, want /algo/api/v2/image/upload", cap.Path)
	}
	if cap.RequestID == "" {
		t.Error("request_id query missing")
	}
	if !strings.HasPrefix(cap.ContentType, "multipart/form-data; boundary=") {
		t.Errorf("content-type = %q, want multipart with boundary", cap.ContentType)
	}
	if cap.FormName != "file" {
		t.Errorf("form field = %q, want file", cap.FormName)
	}
	if cap.Filename != "image.png" {
		t.Errorf("filename = %q, want image.png", cap.Filename)
	}
	if cap.PartCT != "image/png" {
		t.Errorf("part content-type = %q, want image/png", cap.PartCT)
	}
	if string(cap.FileBytes) != string(img) {
		t.Errorf("file bytes drifted: %d bytes received, want %d", len(cap.FileBytes), len(img))
	}
	if cap.CosyKey == "" {
		t.Error("cosy-key header missing")
	}
	if !strings.HasPrefix(cap.Authz, "Bearer COSY.") {
		t.Errorf("authorization = %q, want Bearer COSY. prefix", cap.Authz)
	}
	if cap.CosyUser != "u-image-test" {
		t.Errorf("cosy-user = %q, want u-image-test", cap.CosyUser)
	}
	if ts, err := strconv.ParseInt(cap.Timestamp, 10, 64); err != nil || ts <= 0 {
		t.Errorf("AI-CLIENT-TIMESTAMP = %q, want unix seconds", cap.Timestamp)
	}
}

func TestQoderUploadImageResponseShapes(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantURL string
		wantErr string
	}{
		{"result-imageUrls", `{"result":{"imageUrls":["https://a/1.png"]}}`, "https://a/1.png", ""},
		{"result-image-urls", `{"result":{"image_urls":["https://a/2.png"]}}`, "https://a/2.png", ""},
		{"top-imageUrls", `{"imageUrls":["https://a/3.png"]}`, "https://a/3.png", ""},
		{"top-image-urls", `{"image_urls":["https://a/4.png"]}`, "https://a/4.png", ""},
		{"result-url", `{"result":{"url":"https://a/5.png"}}`, "https://a/5.png", ""},
		{"top-ossUrl", `{"ossUrl":"https://a/6.png"}`, "https://a/6.png", ""},
		{"body-string-nested", `{"body":"{\"result\":{\"imageUrls\":[\"https://a/7.png\"]}}"}`, "https://a/7.png", ""},
		{"empty-first-element", `{"result":{"imageUrls":["", "https://a/8.png"]}}`, "https://a/8.png", ""},
		{"no-url", `{"result":{"foo":1}}`, "", "upload response missing url"},
		{"non-json", `not json`, "", "upload response missing url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetImageUploadCache()
			hits := 0
			srv := newImageUploadServer(t, http.StatusOK, c.body, nil, &hits)
			stubImageUploadBase(t, srv.URL)
			url, err := qoderUploadImage(imageTestAuth(), []byte("img"), "image/png")
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("upload: %v", err)
			}
			if url != c.wantURL {
				t.Errorf("url = %q, want %q", url, c.wantURL)
			}
		})
	}
}

func TestQoderUploadImageHTTPError(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusInternalServerError, `{"msg":"boom-bucket-unavailable"}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)
	_, err := qoderUploadImage(imageTestAuth(), []byte("img"), "image/png")
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "500") {
		t.Errorf("error missing status: %s", msg)
	}
	if !strings.Contains(msg, "boom-bucket-unavailable") {
		t.Errorf("error missing body snippet: %s", msg)
	}
}

func TestQoderUploadImageNoCredential(t *testing.T) {
	resetImageUploadCache()
	if _, err := qoderUploadImage(&storedAuth{}, []byte("x"), "image/png"); err == nil {
		t.Fatal("want error for empty credential")
	}
}

// -----------------------------------------------------------------------------

func TestRewriteMessageImagesUploadSuccess(t *testing.T) {
	resetImageUploadCache()
	var cap capturedUpload
	hits := 0
	srv := newImageUploadServer(t, http.StatusOK, `{"result":{"imageUrls":["https://oss.example/ok.png"]}}`, &cap, &hits)
	stubImageUploadBase(t, srv.URL)

	img := []byte("fakepngdata-1")
	raw := `[{"type":"text","text":"看看这张图"},{"type":"image_url","image_url":{"url":"` + tinyPNGURI(img) + `"}}]`
	req := imageRequest(raw)

	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 1 || stub != 0 {
		t.Fatalf("uploaded=%d stubbed=%d, want 1/0", up, stub)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if cap.Filename != "image.png" || cap.FormName != "file" {
		t.Errorf("multipart shape: field=%q filename=%q", cap.FormName, cap.Filename)
	}
	if string(cap.FileBytes) != string(img) {
		t.Error("uploaded bytes drifted")
	}
	if !strings.Contains(req.Messages[1].rawContent, "https://oss.example/ok.png") {
		t.Errorf("rawContent missing OSS URL: %s", req.Messages[1].rawContent)
	}
	if strings.Contains(req.Messages[1].rawContent, "data:image") {
		t.Errorf("data URI survived rewrite: %s", req.Messages[1].rawContent)
	}
	if !strings.Contains(req.Messages[1].rawContent, "看看这张图") {
		t.Errorf("text part lost in rewrite: %s", req.Messages[1].rawContent)
	}
	// The rewritten block must be the OpenAI image_url shape.
	var parts []map[string]any
	if err := json.Unmarshal([]byte(req.Messages[1].rawContent), &parts); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("parts len = %d, want 2", len(parts))
	}
	if parts[1]["type"] != "image_url" {
		t.Fatalf("block type = %v, want image_url", parts[1]["type"])
	}
	iu, _ := parts[1]["image_url"].(map[string]any)
	if iu == nil || iu["url"] != "https://oss.example/ok.png" {
		t.Errorf("image_url block = %v", parts[1])
	}
}

func TestRewriteMessageImagesUploadFailSmallInline(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusInternalServerError, `{"msg":"down"}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	raw := `[{"type":"image_url","image_url":{"url":"` + tinyPNGURI([]byte("small-img")) + `"}}]`
	req := imageRequest(raw)
	before := req.Messages[1].rawContent

	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 0 || stub != 0 {
		t.Fatalf("uploaded=%d stubbed=%d, want 0/0 (inline fallback)", up, stub)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 upload attempt", hits)
	}
	// ≤512KB：原样保留，字节级不变。
	if req.Messages[1].rawContent != before {
		t.Errorf("rawContent changed:\n before=%s\n after =%s", before, req.Messages[1].rawContent)
	}
}

func TestRewriteMessageImagesUploadFailLargeStub(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusInternalServerError, `{"msg":"down"}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	big := bytes.Repeat([]byte{'A'}, 600*1024) // 解码后 >512KB
	raw := `[{"type":"text","text":"图呢"},{"type":"image_url","image_url":{"url":"` + tinyPNGURI(big) + `"}}]`
	req := imageRequest(raw)

	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 0 || stub != 1 {
		t.Fatalf("uploaded=%d stubbed=%d, want 0/1", up, stub)
	}
	after := req.Messages[1].rawContent
	wantStub := fmt.Sprintf("[image omitted: upload failed, %d bytes]", len(big))
	if !strings.Contains(after, wantStub) {
		t.Errorf("stub text missing %q: %s", wantStub, after)
	}
	if strings.Contains(after, "data:image") {
		t.Errorf("oversized data URI survived: %.80s...", after)
	}
	if !strings.Contains(after, "图呢") {
		t.Errorf("text part lost: %s", after)
	}
}

// TestRewriteMessageImagesBudgetExhausted: 12 张 512KB 图片各上传失败时全部
// 内联保底（整包预算恰好 6MB），第 13 张必须桩化——整包护栏生效。
func TestRewriteMessageImagesBudgetExhausted(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusInternalServerError, `{}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	blocks := make([]string, 0, 13)
	for i := 0; i < 13; i++ {
		blocks = append(blocks, `{"type":"image_url","image_url":{"url":"`+tinyPNGURI(bytes.Repeat([]byte{byte('0' + i%10)}, imageInlineFallbackMaxBytes))+`"}}`)
	}
	raw := "[" + strings.Join(blocks, ",") + "]"
	req := imageRequest(raw)

	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 0 {
		t.Fatalf("uploaded=%d, want 0", up)
	}
	if stub != 1 {
		t.Fatalf("stubbed=%d, want 1 (budget exhausted on the 13th image)", stub)
	}
	if hits != 13 {
		t.Fatalf("hits = %d, want 13 upload attempts", hits)
	}
	var parts []map[string]any
	if err := json.Unmarshal([]byte(req.Messages[1].rawContent), &parts); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if kind, _ := parts[12]["type"].(string); kind != "text" {
		t.Errorf("13th block type = %v, want text stub", parts[12]["type"])
	}
	if kind, _ := parts[0]["type"].(string); kind != "image_url" {
		t.Errorf("first inline-fallback block drifted to %v", parts[0]["type"])
	}
}

func TestRewriteMessageImagesRemoteURLUntouched(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	// 远端 URL：绝不触网——指向一个会 fail 的服务器也能证明零调用。
	srv := newImageUploadServer(t, http.StatusInternalServerError, `{}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	raw := `[{"type":"image_url","image_url":{"url":"https://oss.example/already-there.png"}}]`
	req := imageRequest(raw)
	before := req.Messages[1].rawContent

	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 0 || stub != 0 {
		t.Fatalf("uploaded=%d stubbed=%d, want 0/0", up, stub)
	}
	if hits != 0 {
		t.Fatalf("hits = %d, want 0 (http(s) URLs are already remote)", hits)
	}
	if req.Messages[1].rawContent != before {
		t.Errorf("rawContent changed: %s", req.Messages[1].rawContent)
	}
}

func TestRewriteMessageImagesNoImagesFastPath(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusOK, `{}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	req := imageRequest(`[{"type":"text","text":"纯文本"},{"type":"text","text":"没有图"}]`)
	before := req.Messages[1].rawContent
	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 0 || stub != 0 {
		t.Fatalf("uploaded=%d stubbed=%d, want 0/0", up, stub)
	}
	if hits != 0 {
		t.Fatalf("hits = %d, want 0 on the no-image fast path", hits)
	}
	if req.Messages[1].rawContent != before {
		t.Error("rawContent changed on fast path")
	}

	// 纯字符串 content（无 rawContent）同样零改动。
	req2 := &openAIRequest{Model: "qfmodel", Messages: []openAIMessage{{Role: "user", Content: "hi"}}}
	if up, stub := rewriteMessageImages(imageTestAuth(), req2); up != 0 || stub != 0 {
		t.Fatalf("plain-string content: uploaded=%d stubbed=%d", up, stub)
	}
	if hits != 0 {
		t.Fatalf("hits = %d after plain-string request", hits)
	}
}

func TestRewriteMessageImagesNonImageDataURI(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusOK, `{}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	raw := `[{"type":"image_url","image_url":{"url":"data:application/pdf;base64,JVBERi0xLjQK"}}]`
	req := imageRequest(raw)

	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 0 || stub != 1 {
		t.Fatalf("uploaded=%d stubbed=%d, want 0/1", up, stub)
	}
	if hits != 0 {
		t.Fatalf("hits = %d, want 0 (non-image data URIs are never uploaded)", hits)
	}
	if !strings.Contains(req.Messages[1].rawContent, "[file omitted: unreadable or non-image data URI]") {
		t.Errorf("stub text missing: %s", req.Messages[1].rawContent)
	}
}

func TestRewriteMessageImagesUnparsableArrayUntouched(t *testing.T) {
	resetImageUploadCache()
	// rawContent 以 [ 开头但不是合法 JSON 数组：fail-open，原样透传。
	req := imageRequest(`[not-json-at-all data:`)
	before := req.Messages[1].rawContent
	if up, stub := rewriteMessageImages(imageTestAuth(), req); up != 0 || stub != 0 {
		t.Fatalf("uploaded=%d stubbed=%d, want 0/0", up, stub)
	}
	if req.Messages[1].rawContent != before {
		t.Error("unparsable rawContent changed")
	}
}

func TestRewriteMessageImagesCacheHit(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusOK, `{"result":{"imageUrls":["https://oss.example/cached.png"]}}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	uri := tinyPNGURI([]byte("same-image-bytes"))
	req := &openAIRequest{Model: "qfmodel", Messages: []openAIMessage{
		{Role: "user", rawContent: `[{"type":"image_url","image_url":{"url":"` + uri + `"}}]`, contentSet: true},
		{Role: "assistant", Content: "ok"},
		{Role: "user", rawContent: `[{"type":"image_url","image_url":{"url":"` + uri + `"}}]`, contentSet: true},
	}}

	up, stub := rewriteMessageImages(imageTestAuth(), req)
	if up != 2 || stub != 0 {
		t.Fatalf("uploaded=%d stubbed=%d, want 2/0", up, stub)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (second image served from cache)", hits)
	}
	if !strings.Contains(req.Messages[0].rawContent, "https://oss.example/cached.png") ||
		!strings.Contains(req.Messages[2].rawContent, "https://oss.example/cached.png") {
		t.Errorf("cache hit did not rewrite both messages:\n %s\n %s", req.Messages[0].rawContent, req.Messages[2].rawContent)
	}
}

// TestImageUploadCacheCap: 容量上限 imageUploadCacheMaxEntries 生效（超限
// 淘汰任意条目，map 大小有界）。
func TestImageUploadCacheCap(t *testing.T) {
	resetImageUploadCache()
	hits := 0
	srv := newImageUploadServer(t, http.StatusOK, `{"result":{"imageUrls":["https://oss.example/c.png"]}}`, nil, &hits)
	stubImageUploadBase(t, srv.URL)

	sa := imageTestAuth()
	for i := 0; i < imageUploadCacheMaxEntries+5; i++ {
		if _, err := cachedImageUpload(sa, []byte{byte(i), 1, 2, 3}, "image/png"); err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
	}
	imageUploadCache.Lock()
	size := len(imageUploadCache.m)
	imageUploadCache.Unlock()
	if size > imageUploadCacheMaxEntries {
		t.Fatalf("cache size = %d, want <= %d", size, imageUploadCacheMaxEntries)
	}
}
