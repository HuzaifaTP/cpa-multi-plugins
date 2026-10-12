//go:build live

// qoder_live_upload_test.go — issue #37 live leg: drive the REAL
// /algo/api/v2/image/upload endpoint (the file API does not ride the chat
// 10605 queue) to verify (a) the COSY-signed multipart is accepted and
// (b) the response key that actually carries the OSS URL.
//
//	QD_TOKEN=dt-... QD_REGION=intl QD_UID=... go test -tags live -run TestLiveImageUpload -v ./plugins/qoder
package main

import (
	"strings"
	"testing"
)

func TestLiveImageUpload(t *testing.T) {
	sa := liveImageAuth(t)
	uri := redPNG64
	mime, data, ok := parseDataURI(uri)
	if !ok {
		t.Fatalf("parseDataURI failed for probe image")
	}
	t.Logf("probe image: mime=%s bytes=%d", mime, len(data))

	url, err := qoderUploadImage(sa, data, mime)
	if err != nil {
		t.Fatalf("live upload failed: %v", err)
	}
	t.Logf("live upload OK: oss url=%s", url)
	if !strings.HasPrefix(url, "http") {
		t.Errorf("unexpected url shape: %q", url)
	}

	// Second call must hit the sha256 cache (no second network upload —
	// verified by the hermetic tests; here we just confirm idempotence).
	url2, err := qoderUploadImage(sa, data, mime)
	if err != nil {
		t.Fatalf("cached upload failed: %v", err)
	}
	if url2 != url {
		t.Errorf("cache miss? %q != %q", url2, url)
	}
	t.Logf("cached upload OK: %s", url2)
}
