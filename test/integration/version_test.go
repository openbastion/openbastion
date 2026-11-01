package integration_test

// ADR-0063: a binary built with the stamp of make build says its version — the CLI when asked,
// a service on the first line of its log.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion_AStampedBinarySaysItsVersion_TheCLIWhenAsked_AServiceFirst(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(string(raw)) + "+integration.test"
	build := func(pkg, name string) string {
		out := filepath.Join(t.TempDir(), name)
		cmd := exec.Command("go", "build", "-ldflags", "-X github.com/openbastion/openbastion/pkg/buildinfo.Version="+version, "-o", out, pkg)
		cmd.Dir, cmd.Env = root, buildEnv(root)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", pkg, err, b)
		}
		builtFrom.Store(out, pkg)
		return out
	}
	cli := build("./cli/openbastion-cli", "openbastion-cli-63")
	out, err := exec.Command(cli, "version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != version {
		t.Fatalf("openbastion-cli version: %q %v, want %q", out, err, version)
	}
	authn := startService(t, root, build("./services/access/authentication/cmd/authentication", "authentication-63"), "19641", "SKIP_DEMO_SEED=1")
	first, _, _ := strings.Cut(authn.out.String(), "\n")
	if !strings.HasSuffix(first, "authentication "+version) {
		t.Fatalf("the first line of the log does not say the version: %q", first)
	}
	// Built without the stamp (go run, go test): "dev", and never a version it was not given.
	plain := buildBinary(t, root, "./cli/openbastion-cli", "openbastion-cli-63-dev")
	out, _ = exec.Command(plain, "version").CombinedOutput()
	if !strings.HasPrefix(string(out), "dev") {
		t.Fatalf("an unstamped binary says %q", out)
	}
}
