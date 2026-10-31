package integration_test

// ADR-0051: every image the project pulls from a registry is pinned by its digest — in the
// Dockerfiles, the Compose files and the CI workflow — so that a tag moved upstream changes
// nothing until the repository says so. The images Compose builds from this repository
// (openbastion*) are not pulled, and are the only exception.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var pinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// imageRefs returns, for each file, the image references it pulls.
func imageRefs(t *testing.T, root string) map[string][]string {
	t.Helper()
	refs := map[string][]string{}
	add := func(file, ref string) {
		if ref = strings.Trim(strings.TrimSpace(ref), `"'`); ref != "" {
			refs[file] = append(refs[file], ref)
		}
	}
	var files []string
	for _, pattern := range []string{"deploy/*/Dockerfile*", "deploy/*/docker-compose*.yml", ".github/workflows/*.yml", "test/integration/testdata/*/*/Dockerfile*"} {
		m, _ := filepath.Glob(filepath.Join(root, pattern))
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no Dockerfile, Compose file nor workflow found")
	}
	for _, abs := range files {
		rel, _ := filepath.Rel(root, abs)
		b, err := os.ReadFile(abs)
		if err != nil {
			t.Fatal(err)
		}
		stages := map[string]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if strings.HasPrefix(filepath.Base(rel), "Dockerfile") && len(fields) >= 2 && strings.EqualFold(fields[0], "FROM") {
				ref := fields[1]
				for _, f := range fields[1:] {
					if !strings.HasPrefix(f, "--") {
						ref = f
						break
					}
				}
				if !stages[strings.ToLower(ref)] { // FROM <an earlier stage> pulls nothing
					add(rel, ref)
				}
				if len(fields) >= 4 && strings.EqualFold(fields[len(fields)-2], "AS") {
					stages[strings.ToLower(fields[len(fields)-1])] = true
				}
				continue
			}
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "image:") {
				add(rel, strings.SplitN(strings.TrimPrefix(trimmed, "image:"), "#", 2)[0])
			}
		}
	}
	return refs
}

func TestImages_EveryPulledImageIsPinnedByItsDigest(t *testing.T) {
	root := repoRoot(t)
	total := 0
	for file, refs := range imageRefs(t, root) {
		for _, ref := range refs {
			if strings.HasPrefix(ref, "openbastion") && !strings.Contains(ref, "/") {
				continue // built by Compose from this repository, never pulled
			}
			total++
			if !pinned.MatchString(ref) {
				t.Errorf("%s pulls %q, which is not pinned by a digest (name:tag@sha256:<64 hex>)", file, ref)
			}
		}
	}
	if total == 0 {
		t.Fatal("no pulled image found: the scan is broken")
	}
}
