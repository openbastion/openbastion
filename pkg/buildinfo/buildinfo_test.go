package buildinfo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The VERSION file of the repository is a Semantic Version (ADR-0063): the CI fails otherwise.
func TestTheVERSIONFileIsASemanticVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	v := string(raw)
	if !strings.HasSuffix(v, "\n") || strings.Count(v, "\n") != 1 {
		t.Fatalf("VERSION must hold one line: %q", v)
	}
	if v = strings.TrimSuffix(v, "\n"); !Valid(v) {
		t.Fatalf("VERSION %q is not a Semantic Version (semver.org 2.0.0, without a leading v)", v)
	}
}

func TestValid_TheSemverOrgGrammar(t *testing.T) {
	for _, ok := range []string{"0.0.1", "0.0.1-dev", "0.0.2", "1.2.3-rc.1+build.5", "0.0.1-dev+3f776b5c1a2b", "10.20.30", "1.0.0-alpha.beta.1"} {
		if !Valid(ok) {
			t.Fatalf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "v0.0.1", "0.0", "1.0", "01.0.0", "0.01.0", "0.0.1-", "0.0.1-01", "0.0.1+", "0.0.1 ", " 0.0.1", "0.0.1\n", "1.0.0-dev..1"} {
		if Valid(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
	for v, want := range map[string]bool{"0.0.1": true, "0.0.1+build.2": true, "0.0.1-dev": false, "1.0.0-rc.1": false, "v0.0.1": false} {
		if Release(v) != want {
			t.Fatalf("Release(%q) = %v", v, !want)
		}
	}
}

func TestString_TheStampedVersion_AndTheCommitOnlyWhenTheVersionHasNone(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "0.0.1-dev+abc123"
	if got := String(); got != "0.0.1-dev+abc123" {
		t.Fatalf("a version that carries its build: %q", got)
	}
	Version = "0.0.1"
	if got := String(); !strings.HasPrefix(got, "0.0.1") {
		t.Fatalf("%q", got)
	}
}

func TestShortRevision(t *testing.T) {
	tests := []struct{ input, want string }{
		{"b75be22f1a2b3c4d", "b75be22"},
		{"ABCDEF012345", "abcdef0"},
		{"abcdef", "unknown"},
		{"zzzzzzz12345", "unknown"},
		{"1234567+dirty", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := shortRevision(tt.input); got != tt.want {
				t.Fatalf("shortRevision(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestInfoFormatting(t *testing.T) {
	i := Info{Version: "dev", GoVersion: "go1.27.3", Built: "b75be22", OSArch: "linux/amd64"}
	want := "Version:           dev\nGo version:        go1.27.3\nBuilt:             b75be22\nOS/Arch:           linux/amd64"
	if got := i.String(); got != want {
		t.Fatalf("Info.String() = %q, want %q", got, want)
	}
	if got := i.Short(); got != "dev" {
		t.Fatalf("Info.Short() = %q, want dev", got)
	}
}
