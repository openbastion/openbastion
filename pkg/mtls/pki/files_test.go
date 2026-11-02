package pki_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestInitDir_NeverReplacesAnExistingAuthority(t *testing.T) {
	dir := t.TempDir()
	if _, err := pki.InitDir(dir, "openbastion.test", time.Hour); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(pki.CAFile(dir))

	if _, err := pki.InitDir(dir, "openbastion.test", time.Hour); !errors.Is(err, pki.ErrCAExists) {
		t.Fatalf("a second init: %v", err)
	}
	if after, _ := os.ReadFile(pki.CAFile(dir)); !bytes.Equal(before, after) {
		t.Fatal("the existing authority was replaced — every certificate issued from it would now be invalid")
	}

	info, err := os.Stat(filepath.Join(dir, "ca-key.pem"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the CA key mode is %v, %v", info.Mode().Perm(), err)
	}
}

func TestIssueToDir_WritesAnIdentityAServiceCanUse(t *testing.T) {
	dir := t.TempDir()
	if _, err := pki.InitDir(dir, "openbastion.test", 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadDir(dir, "openbastion.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.IssueToDir(ca, dir, "password-vault", pki.IssueOptions{TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}

	if info, err := os.Stat(pki.KeyFile(dir, "password-vault")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the service key mode is %v, %v", info.Mode().Perm(), err)
	}
	creds, err := mtls.NewCredentials(mtls.Settings{
		Mode: mtls.Required, TrustDomain: "openbastion.test",
		CertFile: pki.CertFile(dir, "password-vault"), KeyFile: pki.KeyFile(dir, "password-vault"), CAFile: pki.CAFile(dir),
	})
	if err != nil || creds.Identity() != "password-vault" {
		t.Fatalf("the issued files are not a usable identity: %v", err)
	}

	// renewal replaces the files and leaves nothing behind
	if _, err := pki.IssueToDir(ca, dir, "password-vault", pki.IssueOptions{TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "password-vault"))
	if len(entries) != 2 {
		t.Errorf("the service directory holds %d files after a renewal, want 2", len(entries))
	}
}

func TestLoadDir_SaysWhatIsMissing(t *testing.T) {
	if _, err := pki.LoadDir(t.TempDir(), "openbastion.test"); err == nil {
		t.Fatal("loaded an authority from an empty directory")
	}
}

func TestStandardServices_AreTheWholeDeployment(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range pki.StandardServices {
		if !mtls.ValidServiceName(s) || seen[s] {
			t.Errorf("%q is invalid or listed twice", s)
		}
		seen[s] = true
	}
	for _, want := range []string{"api-gateway", "authentication", "authorization", "session-broker", "ssh-proxy", "password-vault", "audit-service", "command-recorder", "video-recorder", "admin-cli"} {
		if !seen[want] {
			t.Errorf("%q has no standard identity", want)
		}
	}
}
