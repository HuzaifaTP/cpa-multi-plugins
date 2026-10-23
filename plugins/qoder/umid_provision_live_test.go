//go:build live

// umid_provision_live_test.go — v0.8.67: the CN identity leg, verified
// against the REAL npm registry end-to-end, exactly the way a fresh Docker
// deployment will run it on first check-in.
//
// What this test answers (magpie 0.2.30, yetone/magpie#2911 + plugins#304:
// Qoder CN moved the daily 100 Credits into the desktop's 权益中心 and its
// campaigns pages stopped offering the row to requests without Qoder CN's
// own device identity):
//
//  1. provisionedRuntimeInfo("cn") downloads @qodercn-ai/qoderclicn (NOT
//     @qoder-ai/qodercli) from the real registry, extracts the bridge from
//     package/bundle/qoder-worker-runtime.mjs and installs it under the cn
//     region dir;
//  2. the installed bridge is the byte-identical official binary (linux-x64
//     sha256 e30b307eaae12680d2f4e220d4d34b0ea4f70355a624d6d55ee916e03f7d7478
//     — same value v0.8.44 read off the CN CLI 1.1.65 bundle and the IDE
//     deb; re-verified 2026-10-23 against both 1.1.77 tarballs);
//  3. machineIdentityFor(cn, uid) runs it with the CN dialect — environment
//     argument 0, no --account-stdin on linux — and returns a native
//     runtime-info identity (P1gA token, 18-hex type with the 91 marker);
//  4. the intl leg stays on @qoder-ai/qodercli with environment 3.
//
// Requires network. Run: go test -tags live -run TestLiveUmidProvisionCN -v .
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestLiveUmidProvisionCN downloads Qoder CN's own CLI package from the
// real npm registry and runs the extracted bridge the way the CN campaigns
// leg now does. It pins BOTH the install split and the spawn dialect.
func TestLiveUmidProvisionCN(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("bridge sha256 pin is linux-x64 only; skipping on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	t.Setenv("QD_UMID_AUTO", "1")
	t.Setenv("QD_UMID_REGISTRY", "") // the real registry, no mirror
	t.Setenv("QD_UMID_BIN", "")
	t.Setenv("QODERCN_RUNTIME_INFO", "")
	t.Setenv("QODER_RUNTIME_INFO", "")
	t.Setenv("QD_NATIVE_IDENTITY", "")

	dir := t.TempDir()
	prevOverride := umidStateDirOverride
	umidStateDirOverride = func() string { return dir }
	t.Cleanup(func() { umidStateDirOverride = prevOverride })

	start := time.Now()
	exe := provisionedRuntimeInfo(regionCN)
	if exe == "" {
		t.Fatalf("CN provisioning failed against the real registry: %s", umidProvisionLastError(regionCN))
	}
	if !strings.HasSuffix(exe, filepath.Join("cn", "runtime-info")) {
		t.Fatalf("CN bridge installed outside the cn region dir: %q", exe)
	}
	t.Logf("provisioned in %s from @qodercn-ai/qoderclicn: %s", time.Since(start).Round(time.Millisecond), exe)

	// The byte-identity pin: same official binary v0.8.44 extracted from
	// the CN CLI 1.1.65 bundle (and the IDE deb). If this ever drifts, the
	// e30b307e pin documents WHERE the new binary came from — re-derive,
	// don't blindly update.
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatalf("read provisioned bridge: %v", err)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	const want = "e30b307eaae12680d2f4e220d4d34b0ea4f70355a624d6d55ee916e03f7d7478"
	if got != want {
		t.Fatalf("CN bridge sha256 = %s, want the pinned official binary %s (upstream reshuffled the bundle — re-verify the extraction)", got, want)
	}

	// The identity itself: native source, official shape, CN dialect (env 0).
	// A FAKE wrapper records the argv the plugin actually spawned it with.
	wrapDir := t.TempDir()
	argsFile := filepath.Join(wrapDir, "args.txt")
	real := filepath.Join(wrapDir, "real")
	if err := os.Rename(exe, real); err != nil {
		t.Fatalf("stage real bridge: %v", err)
	}
	wrapper := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + argsFile + "\n" +
		"exec " + real + " \"$@\"\n"
	if err := os.WriteFile(exe, []byte(wrapper), 0o755); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	machineIdentityCache.Delete(regionCN)
	id := machineIdentityFor(regionCN, "01a0239b-64cb-73ae-bf50-2bc6673e7fcc", true)
	if id.Source != identitySourceNative {
		t.Fatalf("identity source = %q, want %q (provisioned CN bridge must produce a native identity)", id.Source, identitySourceNative)
	}
	if !strings.HasPrefix(id.MachineToken, "P1gA") || len(id.MachineToken) != 88 {
		t.Fatalf("machineToken = %q, want the official 88-char P1gA shape", id.MachineToken)
	}
	if len(id.MachineType) != 18 || !strings.Contains(id.MachineType, "91") {
		t.Fatalf("machineType = %q, want 18 hex with the 91 marker", id.MachineType)
	}
	argsRaw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("wrapper args missing: %v", err)
	}
	if got := strings.TrimSpace(string(argsRaw)); got != "0" {
		t.Fatalf("CN bridge spawn args = %q, want the CN UMID environment %q", got, "0")
	}
	t.Logf("CN native identity OK: token=%s… type=%s code=%s vm=%v(%s %d)",
		id.MachineToken[:12], id.MachineType, id.MachineCode, id.VMIsVM, id.VMBrand, id.VMScore)

	// The intl leg stays on its own package with its own dialect.
	intlExe := provisionedRuntimeInfo(regionIntl)
	if intlExe == "" {
		t.Fatalf("intl provisioning failed: %s", umidProvisionLastError(regionIntl))
	}
	if !strings.HasSuffix(intlExe, filepath.Join("intl", "runtime-info")) {
		t.Fatalf("intl bridge installed outside the intl region dir: %q", intlExe)
	}
	intlWrap := filepath.Dir(intlExe)
	intlReal := filepath.Join(intlWrap, "real")
	intlArgs := filepath.Join(intlWrap, "args.txt")
	if err := os.Rename(intlExe, intlReal); err != nil {
		t.Fatalf("stage real intl bridge: %v", err)
	}
	wrapper2 := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + intlArgs + "\n" +
		"exec " + intlReal + " \"$@\"\n"
	if err := os.WriteFile(intlExe, []byte(wrapper2), 0o755); err != nil {
		t.Fatalf("write intl wrapper: %v", err)
	}
	machineIdentityCache.Delete(regionIntl)
	idIntl := machineIdentityFor(regionIntl, "01a0239b-64cb-73ae-bf50-2bc6673e7fcc", true)
	if idIntl.Source != identitySourceNative {
		t.Fatalf("intl identity source = %q, want native", idIntl.Source)
	}
	argsRaw2, err := os.ReadFile(intlArgs)
	if err != nil {
		t.Fatalf("intl wrapper args missing: %v", err)
	}
	if got := strings.TrimSpace(string(argsRaw2)); got != "3" {
		t.Fatalf("intl bridge spawn args = %q, want the intl UMID environment %q", got, "3")
	}
	t.Logf("intl native identity OK: token=%s… type=%s (env 3)",
		idIntl.MachineToken[:12], idIntl.MachineType)
}
