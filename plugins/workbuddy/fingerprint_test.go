package main

import (
	"net/http"
	"testing"
)

// TestFingerprintVersionsPinned — the 2026-10-18 captures from issue #56.
// If a future bump changes these, this test is the tripwire that says the
// change was intentional (and the CHANGELOG said so).
func TestFingerprintVersionsPinned(t *testing.T) {
	if clientUA != "CLI/2.168.2 CodeBuddy/2.168.2" {
		t.Fatalf("clientUA = %q, want CLI/2.168.2 CodeBuddy/2.168.2 (issue #56 captures)", clientUA)
	}
	if desktopClientVersion != "5.8.3" {
		t.Fatalf("desktopClientVersion = %q, want 5.8.3", desktopClientVersion)
	}
	if desktopBundledCLIVersion != "2.161.0" {
		t.Fatalf("desktopBundledCLIVersion = %q, want 2.161.0", desktopBundledCLIVersion)
	}
	wantUA := "WorkBuddy/5.8.3 WorkBuddy/5.8.3 CLI/2.161.0"
	if growthDesktopUA != wantUA {
		t.Fatalf("growthDesktopUA = %q, want %q", growthDesktopUA, wantUA)
	}
}

// TestStainlessOSArchMapping — the SDK's process.platform / process.arch
// vocabulary, mapped from the real runtime.
func TestStainlessOSArchMapping(t *testing.T) {
	// The mapping itself is exercised on the live GOOS/GOARCH; the table is
	// checked through the switch's contract on whatever this test binary
	// runs on, plus the direct helpers.
	os, arch := stainlessOS(), stainlessArch()
	switch os {
	case "macOS", "Linux", "Windows":
	default:
		t.Fatalf("stainlessOS() = %q — unexpected vocabulary", os)
	}
	switch arch {
	case "x64", "arm64":
	default:
		t.Fatalf("stainlessArch() = %q — unexpected vocabulary", arch)
	}
}

// TestBackendHeadersStainlessCLIIdentity — a CLI-identity credential's chat
// request carries the full OpenAI Node SDK fingerprint family (issue #56);
// an IDE-identity credential keeps its own family and carries none of it.
func TestBackendHeadersStainlessCLIIdentity(t *testing.T) {
	cliSA := &storedAuth{Auth: storedTokens{AccessToken: "at", Domain: "copilot.tencent.com"}}
	req := &http.Request{Header: http.Header{}}
	backendHeaders(req, cliSA)

	want := map[string]string{
		"X-Stainless-Lang":            "js",
		"X-Stainless-Package-Version": "6.25.0",
		"X-Stainless-Runtime":         "node",
		"X-Stainless-Runtime-Version": "v22.14.0",
	}
	for h, v := range want {
		if got := req.Header.Get(h); got != v {
			t.Fatalf("CLI identity: %s = %q, want %q", h, got, v)
		}
	}
	if got := req.Header.Get("X-Stainless-OS"); got == "" {
		t.Fatalf("CLI identity: X-Stainless-OS must reflect the real platform")
	}
	if got := req.Header.Get("X-Stainless-Arch"); got == "" {
		t.Fatalf("CLI identity: X-Stainless-Arch must reflect the real arch")
	}

	// The desktop identity fallback also rides the current version.
	if got := req.Header.Get("X-IDE-Version"); got != "5.8.3" {
		t.Fatalf("X-IDE-Version = %q, want 5.8.3", got)
	}

	// IDE-identity logins: their own header family stays (the Intl realm
	// override shapes it as CodeBuddy/IDE 1.100.0), and the Stainless family
	// stays OUT — mixing identities is a new mismatch.
	ideSA := &storedAuth{
		Auth: storedTokens{AccessToken: "at", Domain: "www.codebuddy.ai", LoginPlatform: "ide", Region: "intl"},
	}
	ideReq := &http.Request{Header: http.Header{}}
	backendHeaders(ideReq, ideSA)
	for _, h := range []string{"X-Stainless-Lang", "X-Stainless-Package-Version", "X-Stainless-OS", "X-Stainless-Arch", "X-Stainless-Runtime", "X-Stainless-Runtime-Version"} {
		if got := ideReq.Header.Get(h); got != "" {
			t.Fatalf("IDE identity must not carry %s, got %q", h, got)
		}
	}
	if got := ideReq.Header.Get("X-IDE-Type"); got == "WorkBuddy" || got == "" {
		t.Fatalf("IDE identity keeps its own family, X-IDE-Type = %q", got)
	}
}
