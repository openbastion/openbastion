// Package buildinfo is the version a binary was built as (ADR-0063): the VERSION file of the
// repository, in Semantic Versioning, stamped at build by
//
//	-ldflags "-X github.com/openbastion/openbastion/pkg/buildinfo.Version=<version>"
//
// (make build, the Dockerfile and the CI do it), and the commit Go records when it builds from a
// clone. Standard library only.
package buildinfo

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is what -ldflags stamps; "dev" for a binary built without it (go run, go test).
var Version = "dev"

// semver is the regular expression of semver.org (2.0.0), with its "v" prefix refused: VERSION
// holds the version, a tag adds the "v".
var semver = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
	`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// Valid says whether v is a Semantic Version (without a leading "v").
func Valid(v string) bool { return semver.MatchString(v) }

// Release says whether v is a version without pre-release: what a tag may name.
func Release(v string) bool {
	m := semver.FindStringSubmatch(v)
	return m != nil && m[4] == ""
}

// Commit is the commit Go recorded at build (12 characters, "+dirty" when the tree was modified),
// or "" — a binary built from an archive, or in a container without the .git directory.
func Commit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	dirty := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev != "" && dirty {
		rev += "+dirty"
	}
	return rev
}

// String is the version as a service writes it at its start: "0.0.1-dev+abc123", and the commit
// Go recorded when the version does not carry one.
func String() string {
	m := semver.FindStringSubmatch(Version)
	if c := Commit(); c != "" && (m == nil || m[5] == "") {
		return Version + " (commit " + c + ")"
	}
	return Version
}

// Info describes the build currently executing, without changing String's legacy log format.
type Info struct {
	Version   string
	GoVersion string
	Built     string
	OSArch    string
}

// Current returns the runtime and VCS metadata embedded in the current executable.
func Current() Info {
	return Info{
		Version:   Version,
		GoVersion: runtime.Version(),
		Built:     vcsRevision(),
		OSArch:    runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// Short returns only the stamped version, suitable for scripts.
func (i Info) Short() string { return i.Version }

// String returns the stable four-line diagnostic representation.
func (i Info) String() string {
	return fmt.Sprintf("Version:           %s\nGo version:        %s\nBuilt:             %s\nOS/Arch:           %s",
		i.Version, i.GoVersion, i.Built, i.OSArch)
}

func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return shortRevision(setting.Value)
		}
	}
	return "unknown"
}

func shortRevision(revision string) string {
	revision = strings.ToLower(revision)
	if len(revision) < 7 {
		return "unknown"
	}
	for _, r := range revision {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "unknown"
		}
	}
	return revision[:7]
}
