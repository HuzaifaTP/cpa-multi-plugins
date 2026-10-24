package main

import (
        "encoding/json"
        "errors"
        "net/http"
        "strings"
        "testing"

        "github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// --- reader ---------------------------------------------------------------

func TestReadExcludedModelsDoc(t *testing.T) {
        cases := []struct {
                name string
                doc  string
                want []string
        }{
                {"absent", `{"auth":{"accessToken":"t"}}`, nil},
                {"null", `{"excluded_models":null}`, nil},
                {"empty array", `{"excluded_models":[]}`, nil},
                {"all blank", `{"excluded_models":["","  "]}`, nil},
                {"underscore []string", `{"excluded_models":["glm-5.3","Kimi-K2.8-Preview"]}`, []string{"glm-5.3", "kimi-k2.8-preview"}},
                {"hyphen spelling", `{"excluded-models":["glm-5.3"]}`, []string{"glm-5.3"}},
                {"underscore wins over hyphen", `{"excluded_models":["a"],"excluded-models":["b"]}`, []string{"a"}},
                {"[]interface{} elements", `{"excluded_models":["glm-5.3", 42, null, "deepseek-v4-pro"]}`, []string{"glm-5.3", "deepseek-v4-pro"}},
                {"trim + dedup", `{"excluded_models":[" GLM-5.3 ","glm-5.3","glm-5.2*"]}`, []string{"glm-5.3", "glm-5.2*"}},
                {"malformed list is no opinion", `{"excluded_models":"glm-5.3"}`, nil},
                {"malformed doc", `not json`, nil},
        }
        for _, tc := range cases {
                got := readExcludedModelsDoc([]byte(tc.doc))
                if len(got) != len(tc.want) {
                        t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
                }
                for i := range got {
                        if got[i] != tc.want[i] {
                                t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
                        }
                }
        }
}

// --- wildcard (host matchWildcard parity) ----------------------------------

func TestMatchModelWildcard(t *testing.T) {
        cases := []struct {
                pattern, value string
                want           bool
        }{
                {"glm-5.3", "glm-5.3", true},
                {"GLM-5.3", "glm-5.3", true},
                {"glm-5.3", "glm-5.3-flash", false},
                {"glm-5.3*", "glm-5.3-flash", true},
                {"glm-5.3*", "glm-5.3", true},
                {"*flash", "glm-5.3-flash", true},
                {"*flash", "glm-5.3-pro", false},
                {"glm*flash", "glm-5.3-flash", true},
                {"glm*flash", "gpt-flash", false},
                {"*", "anything-at-all", true},
                {"kimi*", "kimi-k3.1-pro", true},
                {"", "glm-5.3", false},
        }
        for _, tc := range cases {
                if got := matchModelWildcard(tc.pattern, tc.value); got != tc.want {
                        t.Fatalf("match(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
                }
        }
}

// --- serve-layer filter -----------------------------------------------------

func TestFilterModelsForCredential(t *testing.T) {
        models := realmTestModels("glm-5.3", "glm-5.3-flash", "kimi-k3.1-pro", "deepseek-v4-pro")

        doc := `{"excluded_models":["glm-5.3","deepseek-v4-pro"]}`
        got := filterModelsForCredential(models, []byte(doc))
        if len(got) != 2 || got[0].ID != "glm-5.3-flash" || got[1].ID != "kimi-k3.1-pro" {
                t.Fatalf("exact exclusion: got %+v", got)
        }

        wild := `{"excluded_models":["glm-*"]}`
        got = filterModelsForCredential(models, []byte(wild))
        if len(got) != 2 || got[0].ID != "kimi-k3.1-pro" || got[1].ID != "deepseek-v4-pro" {
                t.Fatalf("wildcard exclusion: got %+v", got)
        }

        // No opinion: absent, null, and empty lists all pass the list through
        // untouched — the channel-level rules keep applying on the host side.
        for _, doc := range []string{`{}`, `{"excluded_models":null}`, `{"excluded_models":[]}`} {
                if got := filterModelsForCredential(models, []byte(doc)); len(got) != len(models) {
                        t.Fatalf("doc %s: expected no filtering, got %+v", doc, got)
                }
        }
        // Same storage, no exclusion field anywhere.
        if got := filterModelsForCredential(models, nil); len(got) != len(models) {
                t.Fatalf("nil storage must not filter, got %+v", got)
        }
        // Excluding everything yields an empty (not nil) list — the host then
        // unregisters the credential's models, which is the honest answer.
        if got := filterModelsForCredential(models, []byte(`{"excluded_models":["*"]}`)); len(got) != 0 {
                t.Fatalf("exclude-all: got %+v", got)
        }
}

// The full serve path filters by the ASKING credential's own document —
// the shared realm cache must never leak a sibling's narrowing (the exact
// trap of issue #56: the education account and two personal accounts share
// the CN realm's one cache entry).
func TestFetchDynamicModelsFiltersCredentialExcluded(t *testing.T) {
        resetDynamicModelsCache()
        defer resetDynamicModelsCache()

        eduDoc := persistTestStorage("tok-edu", "cn", `,"excluded_models":["glm-5.3","glm-5.2","kimi-k2.8-preview"]`)
        personalDoc := persistTestStorage("tok-personal", "cn", "")

        orig := discoverModelsFn
        discoverModelsFn = func(accessToken, realm, uid string) ([]pluginapi.ModelInfo, error) {
                return nil, errors.New("down")
        }
        defer func() { discoverModelsFn = orig }()

        catalog := realmTestModels("glm-5.3", "glm-5.2", "hy3", "kimi-k2.8-preview")
        snap := &persistedModelCache{Realm: "cn", FetchedAt: "2026-10-24T00:00:00Z", Models: catalog}
        withSnap, err := mergeModelCacheIntoDoc(eduDoc, snap)
        if err != nil {
                t.Fatalf("merge: %v", err)
        }
        personalSnap, err := mergeModelCacheIntoDoc(personalDoc, snap)
        if err != nil {
                t.Fatalf("merge: %v", err)
        }

        restore := stubPersistSeams(t, map[string][]byte{"edu": withSnap, "personal": personalSnap})
        defer restore()

        // The education account serves the catalog minus its own exclusions
        // (glm-5.3, glm-5.2 and kimi-k2.8-preview excluded → only hy3 survives).
        got := fetchDynamicModelsFromStorage(withSnap)
        if len(got) != 1 || got[0].ID != "hy3" {
                t.Fatalf("edu account: want [hy3], got %+v", idsOf(got))
        }
        // The personal account, same realm, same snapshot: full catalog.
        got = fetchDynamicModelsFromStorage(personalSnap)
        if len(got) != 4 {
                t.Fatalf("personal account must keep the full catalog, got %+v", idsOf(got))
        }
}

func idsOf(models []pluginapi.ModelInfo) []string {
        out := make([]string, 0, len(models))
        for _, m := range models {
                out = append(out, m.ID)
        }
        return out
}

// --- persistence: the whitelist defends the field across typed rebuilds -----

func TestPreservePluginDocKeysExcludedModels(t *testing.T) {
        files := map[string][]byte{
                "a1": []byte(`{"type":"workbuddy","auth":{"accessToken":"t"},"account":{"uid":"u1"},` +
                        `"excluded_models":["glm-5.3"],"prefix":"wb-edu","model_cache":{"realm":"cn","fetched_at":"2026-10-24T00:00:00Z","models":[{"id":"glm-5.3"}]}}`),
        }
        restore := stubPersistSeams(t, files)
        defer restore()

        // A typed rebuild (lifecycle note churn) that carries none of the
        // whitelisted fields — the pre-0.9.69 behavior wiped excluded_models
        // here within seconds of a hand edit.
        rebuilt := []byte(`{"type":"workbuddy","provider":"workbuddy","auth_kind":"oauth","disabled":false,` +
                `"note":"CN · edu","auth":{"accessToken":"t"},"account":{"uid":"u1"}}`)
        merged := preservePluginDocKeys("workbuddy-a1.json", rebuilt)

        var doc map[string]json.RawMessage
        if err := json.Unmarshal(merged, &doc); err != nil {
                t.Fatalf("merged doc unreadable: %v", err)
        }
        var list []string
        if raw, ok := doc["excluded_models"]; ok {
                _ = json.Unmarshal(raw, &list)
        }
        if len(list) != 1 || list[0] != "glm-5.3" {
                t.Fatalf("excluded_models must survive the typed rebuild, got %v", list)
        }
        var prefix string
        if raw, ok := doc["prefix"]; ok {
                _ = json.Unmarshal(raw, &prefix)
        }
        if prefix != "wb-edu" {
                t.Fatalf("prefix must keep surviving (issue #25), got %q", prefix)
        }
        if _, ok := doc["model_cache"]; !ok {
                t.Fatalf("model_cache must keep surviving (v0.9.38)")
        }

        // The hyphen spelling rides the same defense.
        files["a1"] = []byte(`{"type":"workbuddy","auth":{"accessToken":"t"},"account":{"uid":"u1"},"excluded-models":["glm-5.2"]}`)
        merged = preservePluginDocKeys("workbuddy-a1.json", rebuilt)
        doc = map[string]json.RawMessage{}
        if err := json.Unmarshal(merged, &doc); err != nil {
                t.Fatalf("merged doc unreadable: %v", err)
        }
        if raw, ok := doc["excluded-models"]; !ok || strings.TrimSpace(string(raw)) == "" {
                t.Fatalf("hyphen spelling must survive too, got %v", doc)
        }
}

// --- management endpoints ----------------------------------------------------

func TestExcludedModelsEndpoints(t *testing.T) {
        files := map[string][]byte{
                "a1": []byte(`{"type":"workbuddy","auth":{"accessToken":"t"},"account":{"uid":"u1"},"note":"CN"}`),
        }
        restore := stubPersistSeams(t, files)
        defer restore()

        // GET before any exclusion: empty answer, no error.
        get := handleExcludedModelsGet(pluginapi.ManagementRequest{
                Method: http.MethodGet,
                Query:  map[string][]string{"auth_index": {"a1"}},
        })
        if get["error"] != nil {
                t.Fatalf("GET before set: %+v", get)
        }
        if list, _ := get["models"].([]string); len(list) != 0 {
                t.Fatalf("GET before set: want empty list, got %v", list)
        }

        // POST merges into the physical doc through the funnel.
        set := handleExcludedModelsSet(pluginapi.ManagementRequest{
                Method: http.MethodPost,
                Body:   []byte(`{"auth_index":"a1","models":["GLM-5.3","glm-5.3"," kimi-k2.7 "]}`),
        })
        if set["ok"] != true {
                t.Fatalf("POST set: %+v", set)
        }
        var saved map[string]json.RawMessage
        if err := json.Unmarshal(files["a1"], &saved); err != nil {
                t.Fatalf("saved doc unreadable: %v", err)
        }
        var list []string
        if err := json.Unmarshal(saved["excluded_models"], &list); err != nil {
                t.Fatalf("saved excluded_models: %v", err)
        }
        if len(list) != 2 || list[0] != "glm-5.3" || list[1] != "kimi-k2.7" {
                t.Fatalf("normalized list not persisted, got %v", list)
        }
        // The note the panel owns is still there — the merge only touched the
        // exclusion key.
        var note string
        _ = json.Unmarshal(saved["note"], &note)
        if note != "CN" {
                t.Fatalf("note must survive the merge, got %q", note)
        }

        // GET reads it back.
        get = handleExcludedModelsGet(pluginapi.ManagementRequest{
                Method: http.MethodGet,
                Query:  map[string][]string{"auth_index": {"a1"}},
        })
        got, _ := get["models"].([]string)
        if len(got) != 2 || got[0] != "glm-5.3" {
                t.Fatalf("GET after set: %+v", get)
        }

        // POST with an empty list removes the field (back to channel rules).
        set = handleExcludedModelsSet(pluginapi.ManagementRequest{
                Method: http.MethodPost,
                Body:   []byte(`{"auth_index":"a1","models":[]}`),
        })
        if set["ok"] != true {
                t.Fatalf("POST clear: %+v", set)
        }
        saved = map[string]json.RawMessage{}
        if err := json.Unmarshal(files["a1"], &saved); err != nil {
                t.Fatalf("cleared doc unreadable: %v", err)
        }
        if _, ok := saved["excluded_models"]; ok {
                t.Fatalf("empty list must remove the field, got %v", saved)
        }

        // The funnel's own hygiene ran on every save: type/provider stamped.
        if string(saved["type"]) != `"workbuddy"` {
                t.Fatalf("funnel must normalize type, got %s", saved["type"])
        }

        // Missing auth_index is an error, not a panic.
        if bad := handleExcludedModelsGet(pluginapi.ManagementRequest{Method: http.MethodGet}); bad["error"] == nil {
                t.Fatalf("GET without auth_index must error, got %+v", bad)
        }
        if bad := handleExcludedModelsSet(pluginapi.ManagementRequest{Method: http.MethodPost, Body: []byte(`{}`)}); bad["error"] == nil {
                t.Fatalf("POST without auth_index must error, got %+v", bad)
        }
}
