package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// usage:
//
//	cd tools/registry && go run . sync   # or: go run . from anywhere below repo root
//
// sync bumps registry.json versions from plugins/<id>/VERSION and rewrites
// the README version table. Descriptions, changelog one-liners and tags
// stay maintainer-owned — sync never invents prose, it only enforces that
// the version numbers cannot drift again (issue #39's original complaint:
// registry versions were frozen at 0.1.0 across a dozen releases).
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 || args[0] != "sync" {
		return fmt.Errorf("usage: go run . sync  (bump registry.json + README version table from plugins/*/VERSION)")
	}
	reg, regPath, err := loadRegistry()
	if err != nil {
		return err
	}
	root := filepath.Dir(regPath)

	changed := 0
	for i := range reg.Plugins {
		e := &reg.Plugins[i]
		ver, err := pluginVersion(root, e.ID)
		if err != nil {
			return err
		}
		if ver == "" {
			return fmt.Errorf("registry entry %q has no plugins/%s/VERSION file — remove the entry or restore the plugin dir", e.ID, e.ID)
		}
		if e.Version != ver {
			fmt.Printf("  %s: %s -> %s\n", e.ID, e.Version, ver)
			e.Version = ver
			changed++
		}
	}
	if err := saveRegistry(reg, regPath); err != nil {
		return err
	}

	readmePath := filepath.Join(root, "README.md")
	n, err := syncReadmeTable(readmePath, reg)
	if err != nil {
		return err
	}
	fmt.Printf("registry.json synced (%d version bumps), README table rows updated: %d\n", changed, n)
	return nil
}

var readmeRowRe = regexp.MustCompile(`(?m)^(\|\s*(workbuddy|qoder|trae|zcode|mimo)\s*\|\s*)(\S+)(\s*\|)$`)

// syncReadmeTable rewrites the "| plugin | version |" rows in README.md to
// match the (just-synced) registry versions, keeping the human table and
// the machine feed saying the same thing.
func syncReadmeTable(path string, reg *Registry) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	versions := map[string]string{}
	for _, e := range reg.Plugins {
		versions[e.ID] = e.Version
	}
	rows := 0
	out := readmeRowRe.ReplaceAllFunc(raw, func(m []byte) []byte {
		groups := readmeRowRe.FindSubmatch(m)
		id := string(groups[2])
		ver, ok := versions[id]
		if !ok {
			return m
		}
		rows++
		if string(groups[3]) == ver {
			return m
		}
		return []byte(string(groups[1]) + ver + string(groups[4]))
	})
	if rows == 0 {
		return 0, fmt.Errorf("README.md: version table not found — expected rows like '| workbuddy | 0.9.x |'")
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return 0, err
	}
	return rows, nil
}

// expectedPlatforms mirrors the release.yml build matrix. Pinned here so a
// workflow edit that drops or adds a platform fails loudly in the guard
// tests instead of silently desyncing the download URLs.
var expectedPlatforms = []string{
	"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64",
}

func platformSet() map[string]bool {
	s := map[string]bool{}
	for _, p := range expectedPlatforms {
		s[p] = true
	}
	return s
}

func sortedPlatforms() string {
	ps := append([]string(nil), expectedPlatforms...)
	sort.Strings(ps)
	return strings.Join(ps, ", ")
}
