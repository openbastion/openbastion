package main_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestCLI_AllIssuesAUsableIdentityPerService_AndIsRepeatable(t *testing.T) {
	dir := t.TempDir()
	if out, err := run(t, "all", "--dir", dir, "--trust-domain", "cli.test"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, svc := range pki.StandardServices {
		c, err := mtls.NewCredentials(mtls.Settings{
			Mode: mtls.Required, TrustDomain: "cli.test",
			CertFile: pki.CertFile(dir, svc), KeyFile: pki.KeyFile(dir, svc), CAFile: pki.CAFile(dir),
		})
		if err != nil || c.Identity() != svc {
			t.Errorf("%s: %v", svc, err)
		}
	}
	caBefore, _ := os.ReadFile(pki.CAFile(dir))
	// running it again renews the identities but keeps the authority
	if out, err := run(t, "all", "--dir", dir, "--trust-domain", "cli.test"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if caAfter, _ := os.ReadFile(pki.CAFile(dir)); string(caBefore) != string(caAfter) {
		t.Error("the second run replaced the authority")
	}
}

func TestCLI_RejectsLegacySingleDashLongFlags(t *testing.T) {
	if out, err := run(t, "init", "-dir", t.TempDir()); err == nil {
		t.Fatalf("legacy single-dash flag was accepted: %s", out)
	}
}

func TestCLI_RefusesWhatItCannotDo(t *testing.T) {
	dir := t.TempDir()
	if _, err := run(t, "issue", "--dir", dir, "--service", "ssh-proxy"); err == nil {
		t.Error("issued without an authority")
	}
	if out, err := run(t, "init", "--dir", dir); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := run(t, "init", "--dir", dir); err == nil {
		t.Error("a second init succeeded")
	}
	if _, err := run(t, "issue", "--dir", dir); err == nil {
		t.Error("issue without --service succeeded")
	}
	if _, err := run(t, "issue", "--dir", dir, "--service", "Bad Name"); err == nil {
		t.Error("issued for an invalid name")
	}
	if _, err := run(t, "issue", "--dir", dir, "--service", "ssh-proxy", "--ip", "not-an-ip"); err == nil {
		t.Error("accepted a bad IP")
	}
	if _, err := run(t, "bogus"); err == nil {
		t.Error("an unknown command succeeded")
	}
}
