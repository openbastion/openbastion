package mtls_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestNewCredentials_AcceptsAValidIdentity(t *testing.T) {
	e := newEnv(t)
	c, err := mtls.NewCredentials(e.issue("password-vault", pki.IssueOptions{TTL: time.Hour}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity() != "password-vault" || c.TrustDomain() != testDomain {
		t.Errorf("identity %q, domain %q", c.Identity(), c.TrustDomain())
	}
	if d := time.Until(c.NotAfter()); d < 50*time.Minute || d > 61*time.Minute {
		t.Errorf("NotAfter is %s away", d)
	}
}

func TestNewCredentials_RefusesAnythingPeersWouldRefuse(t *testing.T) {
	e := newEnv(t)
	other := newEnv(t) // a second, unrelated CA

	cases := map[string]struct {
		prepare func() mtls.Settings
		want    string
	}{
		"an expired certificate": {
			func() mtls.Settings {
				return e.issue("ssh-proxy", pki.IssueOptions{NotBefore: time.Now().Add(-3 * time.Hour), TTL: time.Hour})
			}, "expired at", // the explicit, operator-readable refusal — not just a chain-verification failure
		},
		"a certificate that is not valid yet": {
			func() mtls.Settings {
				return e.issue("ssh-proxy", pki.IssueOptions{NotBefore: time.Now().Add(2 * time.Hour), TTL: time.Hour})
			}, "not valid before",
		},
		"a certificate from another authority": {
			func() mtls.Settings {
				s := other.issue("ssh-proxy", pki.IssueOptions{})
				s.CAFile = e.settingsFor("ssh-proxy").CAFile // trusts e, but holds other's certificate
				return s
			}, "does not chain",
		},
		"a key that is not the certificate's": {
			func() mtls.Settings {
				s := e.issue("ssh-proxy", pki.IssueOptions{})
				stranger := e.issue("authorization", pki.IssueOptions{})
				b, _ := os.ReadFile(stranger.KeyFile)
				must(t, os.WriteFile(s.KeyFile, b, 0o600))
				return s
			}, "certificate and key",
		},
		"an empty CA bundle": {
			func() mtls.Settings {
				s := e.issue("ssh-proxy", pki.IssueOptions{})
				must(t, os.WriteFile(s.CAFile, []byte("not pem"), 0o600))
				return s
			}, "no certificate",
		},
		"a missing certificate file": {
			func() mtls.Settings {
				s := e.issue("ssh-proxy", pki.IssueOptions{})
				s.CertFile += ".missing"
				return s
			}, "reading certificate",
		},
		"a certificate of another trust domain": {
			func() mtls.Settings {
				s := e.issue("ssh-proxy", pki.IssueOptions{})
				s.TrustDomain = "elsewhere.test"
				return s
			}, "trust domain",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// every case rewrites the shared CA bundle; restore it for the next
			defer e.writeCA(e.ca)
			_, err := mtls.NewCredentials(c.prepare())
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestNewCredentials_RefusesDisabledMode(t *testing.T) {
	if _, err := mtls.NewCredentials(mtls.Settings{Mode: mtls.Disabled}); err == nil {
		t.Fatal("credentials were built while mutual TLS is disabled")
	}
}
