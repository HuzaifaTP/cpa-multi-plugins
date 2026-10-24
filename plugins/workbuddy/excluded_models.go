// excluded_models.go — v0.9.69 (issue #56): per-CREDENTIAL model exclusions
// for WorkBuddy accounts that share a channel with narrower siblings.
//
// Problem: an education/enterprise account discovered 54 models but is only
// authorized for a subset (unauthorized ones answer 400 code 11136 "model not
// allowed"). The channel-level exclusion (config.yaml oauth-excluded-models,
// keyed by provider like workbuddy-cn) removes those models from EVERY
// account on the channel — personal accounts lose them too. The host DOES
// support a per-credential list (the watcher synthesizer merges the auth
// file's top-level "excluded_models" into auth.Attributes and the model
// registry applies it per auth at registration, service.go:1929-1935), but
// the field never survived on disk: every plugin-side typed rebuild
// (lifecycle notes, check-in status churn) reconstructed the document without
// it, and it was not in the preservePluginDocKeys whitelist — wiped within
// seconds of a hand edit.
//
// This file closes the loop on three layers:
//
//  1. persistence — excluded_models/excluded-models joined the preserve
//     whitelist (models_persist.go), so typed rebuilds re-inject the field
//     from the physical file the same way model_cache survives;
//  2. serving — fetchDynamicModelsFromStorage filters the credential's
//     advertised list through its own exclusion before the host ever sees it,
//     with the host's exact matching semantics (trim + lowercase + '*'
//     wildcard), so the two layers can never disagree;
//  3. management — GET/POST /excluded-models gives the panel (and curl) a
//     per-account editor that merges the list into the physical document via
//     the hostAuthSaveJSON funnel, so users no longer hand-edit auth files.
//
// Matching semantics are byte-for-byte the host's applyExcludedModels /
// matchWildcard pair (sdk/cliproxy/service.go): patterns are trimmed,
// lowercased, and matched against the lowercased model id with '*' matching
// any substring. An empty/absent list means "no opinion" — the global
// channel-level rules keep applying, which is also what the host's
// synthesizer does (it only overrides when the combined list is non-empty).
package main

import (
	"encoding/json"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// excludedModelsDocKeys are the two top-level spellings the host's watcher
// synthesizer accepts in credential files. Both are preserved on every
// plugin-side rewrite; both are honored when filtering.
var excludedModelsDocKeys = []string{"excluded_models", "excluded-models"}

// readExcludedModelsDoc extracts the credential's own exclusion list from a
// storage document. Accepts []string and []interface{} element shapes (the
// host's synthesizer tolerates both — files pass through enough hands that
// either encoding shows up in the wild). Returns the normalized list
// (trimmed, lowercased, de-duplicated, empty entries dropped); an absent,
// null, or empty field returns nil = "no per-credential opinion".
func readExcludedModelsDoc(doc []byte) []string {
	if len(doc) == 0 {
		return nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil
	}
	var rawList json.RawMessage
	found := false
	for _, key := range excludedModelsDocKeys {
		if v, ok := top[key]; ok {
			rawList, found = v, true
			break
		}
	}
	if !found {
		return nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(rawList, &elems); err != nil {
		return nil // a malformed list is an opinion nobody can act on — treat as absent
	}
	seen := make(map[string]struct{}, len(elems))
	out := make([]string, 0, len(elems))
	for _, e := range elems {
		var s string
		if err := json.Unmarshal(e, &s); err != nil {
			continue // tolerate non-string elements, matching the host's leniency
		}
		trimmed := strings.ToLower(strings.TrimSpace(s))
		if trimmed == "" {
			continue
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// matchModelWildcard is the host's matchWildcard (sdk/cliproxy/service.go):
// case-insensitive, '*' matches any substring (including none). Keeping the
// semantics identical means a list that excludes a model in the plugin's
// serve layer would also exclude it in the host's registry layer — the two
// filters can never produce different answers for the same document.
func matchModelWildcard(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	if parts[0] != "" {
		if !strings.HasPrefix(value, parts[0]) {
			return false
		}
		pos = len(parts[0])
	}
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(value[pos:], parts[i])
		if idx < 0 {
			return false
		}
		pos += idx + len(parts[i])
	}
	last := parts[len(parts)-1]
	if last == "" {
		return true
	}
	return strings.HasSuffix(value[pos:], last) && len(value) >= pos+len(last)
}

// filterModelsForCredential removes models the credential itself excluded.
// storageJSON is the raw credential document model.for_auth was asked about;
// models is the list the serve layer is about to return (any branch: pinned,
// fresh discovery, cache, or persisted snapshot — the exclusion is the
// credential's opinion about itself and applies to all of them).
func filterModelsForCredential(models []pluginapi.ModelInfo, storageJSON []byte) []pluginapi.ModelInfo {
	patterns := readExcludedModelsDoc(storageJSON)
	if len(patterns) == 0 || len(models) == 0 {
		return models
	}
	out := make([]pluginapi.ModelInfo, 0, len(models))
	for _, m := range models {
		id := strings.ToLower(strings.TrimSpace(m.ID))
		blocked := false
		for _, p := range patterns {
			if matchModelWildcard(p, id) {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, m)
		}
	}
	return out
}

// handleExcludedModelsGet answers GET ?auth_index=... with the credential's
// current exclusion list plus a normalized echo of what was parsed, so the
// panel can render the per-account switches it already has the catalog for
// (GET /models/groups supplies the realm catalog side by side).
func handleExcludedModelsGet(req pluginapi.ManagementRequest) map[string]any {
	authIndex := ""
	if vals := req.Query["auth_index"]; len(vals) > 0 {
		authIndex = strings.TrimSpace(vals[0])
	}
	if authIndex == "" {
		return map[string]any{"error": "auth_index is required"}
	}
	phys, err := hostAuthGetPhysicalFn(authIndex)
	if err != nil || phys == nil || len(phys.JSON) == 0 {
		return map[string]any{"error": "account not found", "auth_index": authIndex}
	}
	return map[string]any{
		"auth_index": authIndex,
		"name":       phys.Name,
		"models":     readExcludedModelsDoc(phys.JSON),
	}
}

// handleExcludedModelsSet merges a new exclusion list into the credential's
// physical document via the hostAuthSaveJSON funnel — the same path every
// plugin-side rewrite takes, which stamps the field into the on-disk file
// AND teaches the preserve whitelist to defend it on subsequent rebuilds.
// An empty models slice removes the field entirely (back to channel rules).
func handleExcludedModelsSet(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		AuthIndex string   `json:"auth_index"`
		Models    []string `json:"models"`
	}
	_ = json.Unmarshal(req.Body, &body)
	authIndex := strings.TrimSpace(body.AuthIndex)
	if authIndex == "" {
		return map[string]any{"error": "auth_index is required"}
	}
	phys, err := hostAuthGetPhysicalFn(authIndex)
	if err != nil || phys == nil || len(phys.JSON) == 0 {
		return map[string]any{"error": "account not found", "auth_index": authIndex}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(phys.JSON, &doc); err != nil {
		return map[string]any{"error": "credential document unreadable", "auth_index": authIndex}
	}
	// Normalize the incoming list exactly like the reader: trim, lowercase,
	// dedup, drop empties. Preserve the user's original spelling of the key
	// when it already exists; otherwise stamp the underscore form the host's
	// synthesizer documents first.
	stampKey := excludedModelsDocKeys[0]
	for _, key := range excludedModelsDocKeys {
		if _, ok := doc[key]; ok {
			stampKey = key
			break
		}
	}
	seen := make(map[string]struct{}, len(body.Models))
	normalized := make([]string, 0, len(body.Models))
	for _, m := range body.Models {
		t := strings.ToLower(strings.TrimSpace(m))
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		normalized = append(normalized, t)
	}
	if len(normalized) == 0 {
		for _, key := range excludedModelsDocKeys {
			delete(doc, key)
		}
	} else {
		raw, err := json.Marshal(normalized)
		if err != nil {
			return map[string]any{"error": "models not serializable", "auth_index": authIndex}
		}
		doc[stampKey] = raw
	}
	merged, err := json.Marshal(doc)
	if err != nil {
		return map[string]any{"error": "document merge failed", "auth_index": authIndex}
	}
	if err := hostAuthSaveJSONFn(phys.Name, merged); err != nil {
		return map[string]any{"error": "save failed: " + err.Error(), "auth_index": authIndex}
	}
	return map[string]any{
		"ok":         true,
		"auth_index": authIndex,
		"name":       phys.Name,
		"models":     normalized,
		"applies_to": "this credential only (channel-level rules still apply elsewhere)",
	}
}
