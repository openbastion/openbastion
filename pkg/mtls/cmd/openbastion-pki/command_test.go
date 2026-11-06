package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func execute(args ...string) (*bytes.Buffer, error) {
	var out bytes.Buffer
	cmd := newRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(normalizeLegacyFlags(args))
	return &out, cmd.Execute()
}

func TestPKIVersionIsSideEffectFree(t *testing.T) {
	out, err := execute("version", "--short")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), buildinfo.Version+"\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestPKIInitAndIssueCommandsPreserveFlagsAndSANs(t *testing.T) {
	dir := t.TempDir()
	if _, err := execute("init", "-dir", dir, "-trust-domain", "test.openbastion.local", "-ttl", "8760h"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Fatalf("CA certificate: %v", err)
	}
	if _, err := execute("issue", "--dir", dir, "--trust-domain", "test.openbastion.local", "--service", "authentication", "--ttl", "24h", "--dns", "auth.example.test", "--ip", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(pki.CertFile(dir, "authentication"), pki.KeyFile(dir, "authentication"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "auth.example.test" {
		t.Fatalf("DNS SANs = %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("IP SANs = %v", leaf.IPAddresses)
	}
}

func TestPKIAllCommandRemainsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := execute("all", "-dir", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("all", "-dir", dir); err != nil {
		t.Fatal(err)
	}
	for _, service := range pki.StandardServices {
		if _, err := os.Stat(pki.CertFile(dir, service)); err != nil {
			t.Errorf("certificate for %s: %v", service, err)
		}
	}
}

func TestPKICommandsRejectInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{"issue"}, {"init", "unexpected"}, {"version", "--unknown"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if _, err := execute(args...); err == nil {
				t.Fatalf("execute(%v) unexpectedly succeeded", args)
			}
		})
	}
}
