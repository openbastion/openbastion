package mtls_test

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
)

func certWithURIs(t *testing.T, uris ...string) *x509.Certificate {
	t.Helper()
	c := &x509.Certificate{}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		c.URIs = append(c.URIs, u)
	}
	return c
}

func TestServiceFromCertificate_IsStrictAboutWhatCountsAsAnIdentity(t *testing.T) {
	const td = "openbastion.test"
	good := "spiffe://" + td + "/session-broker"

	if got, err := mtls.ServiceFromCertificate(certWithURIs(t, good), td); err != nil || got != "session-broker" {
		t.Fatalf("a well-formed identity: got %q, %v", got, err)
	}

	for name, uris := range map[string][]string{
		"no URI SAN":                  nil,
		"two identities (ambiguous)":  {good, "spiffe://" + td + "/command-recorder"},
		"an http URI":                 {"https://" + td + "/session-broker"},
		"another trust domain":        {"spiffe://evil.test/session-broker"},
		"a trust domain with a port":  {"spiffe://" + td + ":443/session-broker"},
		"no service":                  {"spiffe://" + td},
		"a root path":                 {"spiffe://" + td + "/"},
		"a nested path":               {"spiffe://" + td + "/ns/session-broker"},
		"an upper-case name":          {"spiffe://" + td + "/Session-Broker"},
		"a trailing slash":            {"spiffe://" + td + "/session-broker/"},
		"user information":            {"spiffe://root@" + td + "/session-broker"},
		"a query string":              {"spiffe://" + td + "/session-broker?x=1"},
		"a fragment":                  {"spiffe://" + td + "/session-broker#x"},
		"a name starting with a dash": {"spiffe://" + td + "/-broker"},
		"a name with an underscore":   {"spiffe://" + td + "/session_broker"},
		"an opaque form":              {"spiffe:" + td + "/session-broker"},
	} {
		got, err := mtls.ServiceFromCertificate(certWithURIs(t, uris...), td)
		if err == nil {
			t.Errorf("%s: accepted as %q", name, got)
		} else if !errors.Is(err, mtls.ErrNoIdentity) {
			t.Errorf("%s: error does not wrap ErrNoIdentity: %v", name, err)
		}
	}

	if _, err := mtls.ServiceFromCertificate(nil, td); err == nil {
		t.Error("a nil certificate was accepted")
	}
}

func TestServiceNamesAndTrustDomains(t *testing.T) {
	for _, ok := range []string{"a", "ssh-proxy", "password-vault", "x1", strings.Repeat("a", 63)} {
		if !mtls.ValidServiceName(ok) {
			t.Errorf("%q should be a valid service name", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a_b", "a b", "a/b", "a.b", strings.Repeat("a", 64)} {
		if mtls.ValidServiceName(bad) {
			t.Errorf("%q should not be a valid service name", bad)
		}
	}
	for _, ok := range []string{"openbastion.local", "a.b.c", "prod"} {
		if !mtls.ValidTrustDomain(ok) {
			t.Errorf("%q should be a valid trust domain", ok)
		}
	}
	for _, bad := range []string{"", ".a", "a.", "a..b", "A.b", "a b", "a:443"} {
		if mtls.ValidTrustDomain(bad) {
			t.Errorf("%q should not be a valid trust domain", bad)
		}
	}
	if u, err := mtls.SPIFFEID("openbastion.local", "ssh-proxy"); err != nil || u.String() != "spiffe://openbastion.local/ssh-proxy" {
		t.Errorf("SPIFFEID: %v, %v", u, err)
	}
	if _, err := mtls.SPIFFEID("openbastion.local", "Bad Name"); err == nil {
		t.Error("SPIFFEID accepted an invalid service name")
	}
}
