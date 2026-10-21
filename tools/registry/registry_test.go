package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// loadOrFail is the shared fixture for every guard test.
func loadOrFail(t *testing.T) (*Registry, string) {
	t.Helper()
	reg, path, err := loadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg, path
}

// TestSchemaVersion pins the schema the store integration targets. Bump the
// expected value (and the store's parser) together, deliberately.
func TestSchemaVersion(t *testing.T) {
	reg, _ := loadOrFail(t)
	if reg.SchemaVersion != 2 {
		t.Fatalf("schema_version = %d, want 2", reg.SchemaVersion)
	}
}

// TestRegistryCoversEveryShippedPlugin fails when a plugin dir with a VERSION
// file lacks a registry entry (new plugin forgotten — the mimo situation from
// before v0.8.71) or when an entry points at a nonexistent plugin dir.
func TestRegistryCoversEveryShippedPlugin(t *testing.T) {
	reg, regPath := loadOrFail(t)
	root := filepath.Dir(regPath)

	entries := map[string]bool{}
	for _, e := range reg.Plugins {
		if entries[e.ID] {
			t.Errorf("duplicate registry entry %q", e.ID)
		}
		entries[e.ID] = true
		if ver, _ := pluginVersion(root, e.ID); ver == "" {
			t.Errorf("registry entry %q has no plugins/%s/VERSION", e.ID, e.ID)
		}
	}

	dirs, err := os.ReadDir(filepath.Join(root, "plugins"))
	if err != nil {
		t.Fatalf("readdir plugins/: %v", err)
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if ver, _ := pluginVersion(root, d.Name()); ver != "" && !entries[d.Name()] {
			t.Errorf("plugins/%s has a VERSION file but no registry.json entry — run `go run . sync` won't add it, add the entry by hand", d.Name())
		}
	}
}

// TestRegistryVersionsLockstepWithVERSIONFiles is the heart of issue #39:
// the registry's version field must equal the plugin's VERSION file, so
// `releases/latest/download` URLs and the store's update prompts always
// describe what the zips actually contain.
func TestRegistryVersionsLockstepWithVERSIONFiles(t *testing.T) {
	reg, regPath := loadOrFail(t)
	root := filepath.Dir(regPath)
	for _, e := range reg.Plugins {
		ver, err := pluginVersion(root, e.ID)
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		if e.Version != ver {
			t.Errorf("registry %q version %q != plugins/%s/VERSION %q — cd tools/registry && go run . sync", e.ID, e.Version, e.ID, ver)
		}
	}
}

// TestReadmeVersionTableLockstep keeps the human-readable table honest too;
// it rotted once already (README said 0.9.58/0.12.75 while main shipped
// 0.9.59/0.12.77).
func TestReadmeVersionTableLockstep(t *testing.T) {
	reg, regPath := loadOrFail(t)
	root := filepath.Dir(regPath)

	raw, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	versions := map[string]string{}
	for _, e := range reg.Plugins {
		versions[e.ID] = e.Version
	}
	found := map[string]bool{}
	for _, m := range readmeRowRe.FindAllStringSubmatch(string(raw), -1) {
		id, ver := m[2], m[3]
		want, ok := versions[id]
		if !ok {
			continue
		}
		found[id] = true
		if ver != want {
			t.Errorf("README table: %s %q != registry %q", id, ver, want)
		}
	}
	for id := range versions {
		if !found[id] {
			t.Errorf("README table has no row for %s", id)
		}
	}
}

// TestDownloadURLs validates the store-facing download block: every expected
// platform present, URLs matching the stable latest-release asset naming,
// and no surprises like a stray tag pinned in the URL.
func TestDownloadURLs(t *testing.T) {
	reg, _ := loadOrFail(t)
	want := platformSet()

	base := "https://github.com/mmqz/cpa-multi-plugins/releases/latest/download/"
	check := func(kind, prefix string, m map[string]string) {
		t.Helper()
		if len(m) != len(want) {
			t.Errorf("downloads.%s: %d platforms (%v), want %d (%v)", kind, len(m), keys(m), len(want), sortedPlatforms())
		}
		for plat, url := range m {
			if !want[plat] {
				t.Errorf("downloads.%s: unexpected platform %q", kind, plat)
				continue
			}
			expect := base + prefix + plat + ".zip"
			if url != expect {
				t.Errorf("downloads.%s[%s] = %q, want %q", kind, plat, url, expect)
			}
		}
	}
	check("unified", "cpa-multi-plugins-", reg.Downloads.Unified)
	check("split", "cpa-multi-plugins-split-", reg.Downloads.Split)
}

// TestPluginPlatformsAndHomepages checks the per-plugin convenience fields:
// the platform list must mirror the build matrix, and the homepage must
// point into this repository on the main branch (zcode once carried a
// stale /tree/zcode/... branch URL).
func TestPluginPlatformsAndHomepages(t *testing.T) {
	reg, _ := loadOrFail(t)
	want := platformSet()
	for _, e := range reg.Plugins {
		if len(e.Platforms) != len(want) {
			t.Errorf("%s: platforms %v, want %v", e.ID, e.Platforms, sortedPlatforms())
			continue
		}
		for _, p := range e.Platforms {
			if !want[p] {
				t.Errorf("%s: unexpected platform %q", e.ID, p)
			}
		}
		if !strings.HasPrefix(e.Homepage, "https://github.com/mmqz/cpa-multi-plugins/tree/main/") {
			t.Errorf("%s: homepage %q must point at the main branch of this repository", e.ID, e.Homepage)
		}
	}
}

// TestSplitChannels pins the split-package variant ids per plugin. The list
// mirrors the SPLIT= line in .github/workflows/release.yml — if the workflow
// gains or loses a split flavor, update both places (or the guard goes red
// on purpose: stores key install-switching advice off these ids).
func TestSplitChannels(t *testing.T) {
	reg, _ := loadOrFail(t)
	expect := map[string][]string{
		"workbuddy": {"codebuddy-cn", "codebuddy-intl"},
		"qoder":     {"qoder-cn", "qoder-intl"},
		"trae":      {"trae-cn", "trae-solo-cn", "trae-intl"},
		"zcode":     nil,
		"mimo":      nil,
	}
	for _, e := range reg.Plugins {
		want, ok := expect[e.ID]
		if !ok {
			continue
		}
		got := append([]string(nil), e.SplitChannels...)
		sort.Strings(got)
		wantSorted := append([]string(nil), want...)
		sort.Strings(wantSorted)
		if strings.Join(got, ",") != strings.Join(wantSorted, ",") {
			t.Errorf("%s: split_channels %v, want %v (mirror of release.yml SPLIT=)", e.ID, e.SplitChannels, want)
		}
	}
}

// TestChangelogOneLiners: every entry ships a short changelog for the
// store's update dialog — present, single-line, and bounded.
func TestChangelogOneLiners(t *testing.T) {
	reg, _ := loadOrFail(t)
	for _, e := range reg.Plugins {
		c := strings.TrimSpace(e.Changelog)
		if c == "" {
			t.Errorf("%s: changelog is empty — stores render it as the update prompt", e.ID)
			continue
		}
		if strings.ContainsAny(c, "\n\r") {
			t.Errorf("%s: changelog must be a single line", e.ID)
		}
		if len(c) > 400 {
			t.Errorf("%s: changelog is %d chars, keep it under 400 for the update dialog", e.ID, len(c))
		}
	}
}

// TestSyncIsIdempotent runs the sync code path against the committed state
// and asserts it produces zero version churn — the repo must never carry a
// half-synced registry again.
func TestSyncIsIdempotent(t *testing.T) {
	reg, regPath := loadOrFail(t)
	root := filepath.Dir(regPath)

	before, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	drift := 0
	for i := range reg.Plugins {
		e := &reg.Plugins[i]
		ver, err := pluginVersion(root, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		if e.Version != ver {
			drift++
			e.Version = ver
		}
	}
	if drift > 0 {
		t.Fatalf("%d entr(ies) drifted from plugins/*/VERSION — run `cd tools/registry && go run . sync` and commit", drift)
	}
	after, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if normalizeJSON(strings.TrimRight(string(before), "\n")) != normalizeJSON(string(after)) {
		t.Error("registry.json formatting/structure differs from the canonical sync output — run `go run . sync` once and commit the result")
	}
}

func keys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// normalizeJSON strips the space after colons so a hand-formatted file and
// the MarshalIndent output compare equal on content rather than spacing.
var colonSpaceRe = regexp.MustCompile(`:\s*`)

func normalizeJSON(s string) string { return colonSpaceRe.ReplaceAllString(s, ":") }

// TestReleaseWorkflowCarriesStoreAssets pins the CPA plugin-store asset
// contract (v0.8.74, #39 field report): the CLIProxyAPI store client resolves
// each plugin's repository -> latest release -> asset named
// {plugin_id}_{release_version}_{goos}_{goarch}.zip plus a checksums.txt
// sibling, with exactly one dynamic library at zip root. A release workflow
// edit that silently drops the packaging step, renames the template, or stops
// uploading checksums.txt re-breaks every store install with a 502
// "release asset ... not found" — this guard fails the build instead.
func TestReleaseWorkflowCarriesStoreAssets(t *testing.T) {
	reg, regPath := loadOrFail(t)
	root := filepath.Dir(regPath)
	data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	wf := string(data)
	for _, marker := range []string{
		"Package per-plugin store zips + checksums.txt", // the packaging step
		`"${id}_${TAGVER}_${goos}_${goarch}.zip"`,       // the store asset naming template
		"sha256sum *.zip > checksums.txt",               // checksums.txt generation
		"release/checksums.txt",                         // checksums.txt uploaded as a release asset
		"TAGVER=\"${TAGVER#v}\"",                        // asset version = release tag without the v
		`plat="${plat%.zip}"`,                           // dry-run catch: the glob keeps the .zip suffix — without this the store zips become name.zip.zip
	} {
		if !strings.Contains(wf, marker) {
			t.Errorf("release.yml lost the plugin-store asset contract marker %q", marker)
		}
	}
	// The store routes installs through each plugin's repository field; it
	// must stay exactly https://github.com/{this repo} (CPA rejects anything
	// else for github-release installs).
	for _, e := range reg.Plugins {
		if e.Repository != "https://github.com/mmqz/cpa-multi-plugins" {
			t.Errorf("plugins[%s].repository = %q, want https://github.com/mmqz/cpa-multi-plugins", e.ID, e.Repository)
		}
	}
}
