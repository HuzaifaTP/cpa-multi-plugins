package main

// Issue #36（Part 2）— 登录平台血统持久化测试。
//
// startLoginWithRegion 按 login_platform / login_region 决定 OAuth 入口与
// 登录头族，但 handlePollLogin 成功后构造的 storedAuth 从不写
// sa.Auth.LoginPlatform → IDE 流程铸造的 token 在聊天时以 CLI 头族出现
//（token 血统 vs 请求方言错配）。这里用 httptest 服务器驱动完整登录流
//（state → poll → account），钉死三种平台的持久化结果。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// setLoginPlatformForTest pins the configured platform for NEW logins and
// restores it on cleanup.
func setLoginPlatformForTest(t *testing.T, platform string) {
	t.Helper()
	loginPlatformMu.Lock()
	old := loginPlatform
	loginPlatform = platform
	loginPlatformMu.Unlock()
	t.Cleanup(func() {
		loginPlatformMu.Lock()
		loginPlatform = old
		loginPlatformMu.Unlock()
	})
}

// withLoginEndpointsServer redirects the three login endpoints to an
// httptest server and records the platform the state request carried.
func withLoginEndpointsServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	platforms := &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/plugin/auth/state", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*platforms = append(*platforms, r.URL.Query().Get("platform"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":{"state":"st-36","authUrl":"https://auth.example/cb"}}`))
	})
	mux.HandleFunc("/v2/plugin/auth/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":{"accessToken":"at-36","refreshToken":"rt-36","expiresIn":3600,"domain":"copilot.tencent.com"}}`))
	})
	mux.HandleFunc("/v2/plugin/login/account", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":{"uid":"u-36","nickname":"issue36"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	old := loginEndpointsOverride
	loginEndpointsOverride = srv.URL
	t.Cleanup(func() { loginEndpointsOverride = old })
	return srv, platforms
}

// runIssue36LoginFlow drives startLoginWithRegion → handlePollLogin against
// the redirected endpoints and returns the credential the host would store
// (from the poll response's StorageJSON).
func runIssue36LoginFlow(t *testing.T, region string) *storedAuth {
	t.Helper()
	saves := withRecordedAuthPersist(t)
	if _, err := startLoginWithRegion([]byte(`{}`), region); err != nil {
		t.Fatalf("startLoginWithRegion(%s): %v", region, err)
	}
	pollRaw, err := json.Marshal(pluginapi.AuthLoginPollRequest{State: "st-36"})
	if err != nil {
		t.Fatalf("marshal poll request: %v", err)
	}
	out, err := handlePollLogin(pollRaw)
	if err != nil {
		t.Fatalf("handlePollLogin: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil || !env.OK {
		t.Fatalf("poll envelope: err=%v ok=%v raw=%s", err, env.OK, out)
	}
	var resp pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("decode poll response: %v", err)
	}
	if resp.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("poll status = %q, want success (msg=%q)", resp.Status, resp.Message)
	}
	sa, err := parseStored(resp.Auth.StorageJSON)
	if err != nil {
		t.Fatalf("parse poll StorageJSON: %v", err)
	}
	// The plugin-side persist (v0.9.44) must agree — the platform rides BOTH
	// the host-facing AuthData and the file the panel lists.
	if len(*saves) != 1 {
		t.Fatalf("plugin-side persist saves = %d, want 1", len(*saves))
	}
	saved, err := parseStored((*saves)[0].raw)
	if err != nil {
		t.Fatalf("parse persisted credential: %v", err)
	}
	if saved.Auth.LoginPlatform != sa.Auth.LoginPlatform {
		t.Fatalf("persisted platform %q != poll platform %q", saved.Auth.LoginPlatform, sa.Auth.LoginPlatform)
	}
	return sa
}

func TestIssue36_LoginPlatformPersistedIDE(t *testing.T) {
	_, platforms := withLoginEndpointsServer(t)
	setLoginPlatformForTest(t, "ide")

	sa := runIssue36LoginFlow(t, regionCN)
	if sa.Auth.LoginPlatform != "ide" {
		t.Fatalf("cn login with login_platform=ide must persist LoginPlatform=ide, got %q", sa.Auth.LoginPlatform)
	}
	if len(*platforms) != 1 || (*platforms)[0] != "ide" {
		t.Fatalf("auth/state must be requested for the ide platform, got %v", *platforms)
	}
}

func TestIssue36_LoginPlatformIntlForcesIDE(t *testing.T) {
	_, platforms := withLoginEndpointsServer(t)
	// Even with the CLI platform configured, the Intl entry is IDE-only.
	setLoginPlatformForTest(t, "CLI")

	sa := runIssue36LoginFlow(t, regionIntl)
	if sa.Auth.LoginPlatform != "ide" {
		t.Fatalf("intl login must force LoginPlatform=ide, got %q", sa.Auth.LoginPlatform)
	}
	if len(*platforms) != 1 || (*platforms)[0] != "ide" {
		t.Fatalf("intl auth/state must be requested for the ide platform, got %v", *platforms)
	}
	if sa.Auth.Region != regionIntl {
		t.Fatalf("intl login must pin Region=intl, got %q", sa.Auth.Region)
	}
}

func TestIssue36_LoginPlatformDefaultsCLI(t *testing.T) {
	_, platforms := withLoginEndpointsServer(t)
	// No login_platform configured → the historical CLI default.
	setLoginPlatformForTest(t, "")

	sa := runIssue36LoginFlow(t, regionCN)
	if sa.Auth.LoginPlatform != "CLI" {
		t.Fatalf("default login must persist LoginPlatform=CLI, got %q", sa.Auth.LoginPlatform)
	}
	if len(*platforms) != 1 || (*platforms)[0] != "CLI" {
		t.Fatalf("auth/state must be requested for the CLI platform, got %v", *platforms)
	}
}

// TestIssue36_LoginPlatformSurvivesRoundTrip: the persisted field is what
// platformForAuth reads at chat time — the lineage fix only works if the
// JSON round-trips (storedTokens.loginPlatform).
func TestIssue36_LoginPlatformSurvivesRoundTrip(t *testing.T) {
	raw, err := json.Marshal(&storedAuth{Auth: storedTokens{AccessToken: "t", LoginPlatform: "ide"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sa, err := parseStored(raw)
	if err != nil {
		t.Fatalf("parseStored: %v", err)
	}
	if platformForAuth(sa) != "ide" {
		t.Fatalf("platformForAuth = %q, want ide", platformForAuth(sa))
	}
	// The persisted save body must literally carry the field (the panel and
	// any external tooling read the file, not the struct).
	if !strings.Contains(string(raw), `"loginPlatform":"ide"`) {
		t.Fatalf("serialized credential lost loginPlatform: %s", raw)
	}
}
