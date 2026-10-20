package pki_test

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestIssue_ProducesAVerifiableIdentity(t *testing.T) {
	ca, err := pki.NewCA("openbastion.test", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue("ssh-proxy", pki.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	if svc, err := mtls.ServiceFromCertificate(leaf.Cert, "openbastion.test"); err != nil || svc != "ssh-proxy" {
		t.Fatalf("identity %q, %v", svc, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}, DNSName: "localhost"}); err != nil {
			t.Errorf("does not verify for use %v: %v", usage, err)
		}
	}
	if err := leaf.Cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("not valid for the loopback address: %v", err)
	}
	if leaf.Cert.IsCA {
		t.Error("a leaf is a CA")
	}
	if !ca.Cert.IsCA || ca.Cert.MaxPathLen != 0 || !ca.Cert.MaxPathLenZero {
		t.Error("the CA must issue leaves only")
	}
	if got := leaf.Cert.NotAfter.Sub(leaf.Cert.NotBefore); got < time.Hour || got > time.Hour+2*time.Minute {
		t.Errorf("lifetime %s", got)
	}
}

func TestIssue_NeverOutlivesTheAuthorityAndRejectsBadNames(t *testing.T) {
	ca, err := pki.NewCA("openbastion.test", 2*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue("ssh-proxy", pki.IssueOptions{TTL: 100 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Cert.NotAfter.After(ca.Cert.NotAfter) {
		t.Error("a certificate outlives its authority")
	}
	if _, err := ca.Issue("Not A Service", pki.IssueOptions{}); err == nil {
		t.Error("issued for an invalid service name")
	}
	if _, err := ca.Issue("ssh-proxy", pki.IssueOptions{TTL: -time.Hour}); err == nil {
		t.Error("issued for a negative lifetime")
	}
	if _, err := pki.NewCA("Not A Domain", time.Hour, time.Now()); err == nil {
		t.Error("created a CA for an invalid trust domain")
	}
	if _, err := pki.NewCA("openbastion.test", 0, time.Now()); err == nil {
		t.Error("created a CA with no lifetime")
	}
}

func TestIssue_ExplicitNamesReplaceTheDefaults(t *testing.T) {
	ca, _ := pki.NewCA("openbastion.test", time.Hour, time.Now())
	leaf, err := ca.Issue("password-vault", pki.IssueOptions{DNSNames: []string{"vault.internal"}, IPs: []net.IP{net.ParseIP("10.0.0.7")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Cert.VerifyHostname("vault.internal"); err != nil {
		t.Error(err)
	}
	if err := leaf.Cert.VerifyHostname("10.0.0.7"); err != nil {
		t.Error(err)
	}
	if err := leaf.Cert.VerifyHostname("localhost"); err == nil {
		t.Error("the default names were kept alongside explicit ones")
	}
}

func TestCA_RoundTripsThroughPEM(t *testing.T) {
	ca, _ := pki.NewCA("openbastion.test", time.Hour, time.Now())
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	back, err := pki.LoadCA(ca.CertPEM(), keyPEM, "openbastion.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := back.Issue("ssh-proxy", pki.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("a certificate issued by the reloaded CA does not verify against the original: %v", err)
	}
	if _, err := pki.LoadCA([]byte("x"), keyPEM, "openbastion.test"); err == nil {
		t.Error("loaded a CA from garbage")
	}
	if _, err := pki.LoadCA(ca.CertPEM(), []byte("x"), "openbastion.test"); err == nil {
		t.Error("loaded a CA with a garbage key")
	}
}
