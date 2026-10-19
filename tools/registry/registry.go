// Package main implements the registry.json maintenance tool for
// cpa-multi-plugins (issue #39).
//
// The repo-root registry.json is the machine-readable feed that plugin
// stores consume. Two entry points share the loader in this file:
//
//   - `go run . sync`   bumps every registry entry's version from the
//     matching plugins/<id>/VERSION file and rewrites the README version
//     table, so a release is one command away from lockstep.
//   - `go test ./...`   runs the lockstep guards: registry ↔ VERSION ↔
//     README, download URL shape, split-channel coverage, homepage sanity.
//     CI (release.yml `test` job) runs these on every main push and tag.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PluginEntry is one element of registry.json's "plugins" array. Field
// order here is the canonical serialization order — the sync command
// round-trips the file through these structs, so a hand-edited file and a
// synced file must not churn against each other.
type PluginEntry struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Author        string   `json:"author"`
	Version       string   `json:"version"`
	Changelog     string   `json:"changelog"`
	Repository    string   `json:"repository"`
	Homepage      string   `json:"homepage"`
	License       string   `json:"license"`
	Platforms     []string `json:"platforms"`
	SplitChannels []string `json:"split_channels,omitempty"`
	Tags          []string `json:"tags"`
}

// DownloadsBlock carries the stable "always latest release" asset URLs.
// All five plugins ship inside every platform zip, so the URLs live at
// the top level rather than per plugin.
type DownloadsBlock struct {
	Unified map[string]string `json:"unified"`
	Split   map[string]string `json:"split"`
	Note    string            `json:"note"`
}

// Registry is the whole registry.json document (schema v2).
type Registry struct {
	SchemaVersion int            `json:"schema_version"`
	ReleaseNotes  string         `json:"release_notes"`
	Downloads     DownloadsBlock `json:"downloads"`
	Plugins       []PluginEntry  `json:"plugins"`
}

// repoRoot walks up from the working directory until it finds registry.json.
// Tests run inside tools/registry, the sync command may be invoked from the
// repo root or anywhere below it — both resolve the same root.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "registry.json")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("registry.json not found in any parent directory — run from inside the repository")
		}
		dir = parent
	}
}

// loadRegistry reads and parses the repo-root registry.json.
func loadRegistry() (*Registry, string, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(root, "registry.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}
	var reg Registry
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, path, fmt.Errorf("registry.json: %w", err)
	}
	return &reg, path, nil
}

// saveRegistry serializes reg back to path with stable 2-space indentation
// and a trailing newline, matching the committed formatting.
func saveRegistry(reg *Registry, path string) error {
	out, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}

// pluginVersion reads plugins/<id>/VERSION (whitespace-trimmed). Empty
// string means "no VERSION file" — the caller decides whether that is
// fatal (sync/guard: yes; the plugin dir simply is not a shipped plugin).
func pluginVersion(root, id string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "plugins", id, "VERSION"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	ver := string(trimSpaceBytes(raw))
	if ver == "" {
		return "", fmt.Errorf("plugins/%s/VERSION is empty", id)
	}
	return ver, nil
}

func trimSpaceBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
