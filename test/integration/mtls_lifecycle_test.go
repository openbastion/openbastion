// The life of an identity under ADR-0010, on real processes: certificates that
// are renewed while the service runs, an authority that is replaced, and
// services that refuse to start without a proper identity of their own.
//
// The product has no revocation list: certificates are short-lived, and a
// compromise is answered by replacing the authority. These tests are the proof
// that this works without a restart and without opening a window.
package integration_test

import (
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestMTLS_CertificatesAndAuthoritiesRotateOnALiveProcess_WithoutARestart(t *testing.T) {
	root := repoRoot(t)
	p := newTestPKI(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-rotation")
	// Looks at its files at most every 200 ms instead of every 5 s, so the test is quick.
	svc := startMTLSService(t, root, auditBin, "18821", p, mtls.AuditService, "TLS_RELOAD_INTERVAL=200ms")
	pid := svc.cmd.Process.Pid
	url := svc.baseURL
	admin := p.clientAs(t, mtls.AdminCLI)

	serial := servedSerial(t, admin, url)
	probe := admin // the client that is expected to be accepted; it changes with the authority
	stillTheSameProcess := func(t *testing.T) {
		t.Helper()
		if !svc.alive() || svc.cmd.Process.Pid != pid {
			t.Fatalf("the service is no longer the process it was\n%s", svc.out.String())
		}
		if status, _, err := call(probe, http.MethodGet, url+"/healthz", nil); err != nil || status != http.StatusOK {
			t.Fatalf("the service no longer answers: %d %v\n%s", status, err, svc.out.String())
		}
	}
	// Each check of the files happens at a handshake, so the test makes some.
	poke := func() { _, _, _ = call(admin, http.MethodGet, url+"/healthz", nil) }

	t.Run("a renewed certificate is served from the next handshake on", func(t *testing.T) {
		if _, err := pki.IssueToDir(p.ca, p.dir, mtls.AuditService, pki.IssueOptions{TTL: 2 * time.Hour}); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, 5*time.Second, "the renewed certificate to be served", func() bool {
			return servedSerial(t, admin, url) != serial
		})
		serial = servedSerial(t, admin, url)
		stillTheSameProcess(t)
		if !strings.Contains(svc.out.String(), "reloaded the identity of audit-service") {
			t.Fatalf("the reload should be logged:\n%s", svc.out.String())
		}
	})

	t.Run("a replacement signed by another authority is refused, and the current identity kept", func(t *testing.T) {
		other, err := pki.NewCA(mtlsDomain, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := other.Issue(mtls.AuditService, pki.IssueOptions{TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		writeIdentity(t, p, mtls.AuditService, leaf)
		waitUntil(t, 5*time.Second, "the refusal to be logged", func() bool {
			poke()
			return strings.Contains(svc.out.String(), "NOT reloading the identity of audit-service, keeping the current one")
		})
		if got := servedSerial(t, admin, url); got != serial {
			t.Fatalf("the service switched to a certificate its own authority did not sign (%s → %s)", serial, got)
		}
		stillTheSameProcess(t)
	})

	t.Run("a certificate that belongs to another service is refused too", func(t *testing.T) {
		leaf, err := p.ca.Issue(mtls.PasswordVault, pki.IssueOptions{TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		writeIdentity(t, p, mtls.AuditService, leaf)
		waitUntil(t, 5*time.Second, "the refusal to be logged", func() bool {
			poke()
			return strings.Contains(svc.out.String(), `the new certificate is for "password-vault" but this process is "audit-service"`)
		})
		if got := servedSerial(t, admin, url); got != serial {
			t.Fatalf("the service took on the identity of another service (%s → %s)", serial, got)
		}
		stillTheSameProcess(t)
	})

	t.Run("a good certificate put back is taken up again", func(t *testing.T) {
		if _, err := pki.IssueToDir(p.ca, p.dir, mtls.AuditService, pki.IssueOptions{TTL: 2 * time.Hour}); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, 5*time.Second, "the good certificate to be served again", func() bool {
			return servedSerial(t, admin, url) != serial
		})
		serial = servedSerial(t, admin, url)
		stillTheSameProcess(t)
	})

	// -- replacing the authority, in the order that never locks anyone out ----
	newCA, err := pki.NewCA(mtlsDomain, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	newAdminLeaf, err := newCA.Issue(mtls.AdminCLI, pki.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	bothRoots := x509.NewCertPool()
	bothRoots.AddCert(p.ca.Cert)
	bothRoots.AddCert(newCA.Cert)
	newAdmin := clientWith(t, bothRoots, newAdminLeaf)
	oldAndNew := append(append([]byte{}, p.ca.CertPEM()...), newCA.CertPEM()...)

	t.Run("a certificate from a new authority is refused until that authority is in the bundle", func(t *testing.T) {
		if status, raw, err := call(newAdmin, http.MethodGet, url+"/healthz", nil); err == nil {
			t.Fatalf("answered a certificate from an authority it does not know: %d %q", status, raw)
		}
	})

	t.Run("adding the new authority to the bundle admits its certificates at once, and keeps the old", func(t *testing.T) {
		if err := pki.WriteFileAtomic(pki.CAFile(p.dir), oldAndNew, 0o644); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, 5*time.Second, "the new authority to be trusted", func() bool {
			status, _, err := call(newAdmin, http.MethodGet, url+"/healthz", nil)
			return err == nil && status == http.StatusOK
		})
		if status, _, err := call(admin, http.MethodGet, url+"/healthz", nil); err != nil || status != http.StatusOK {
			t.Fatalf("the old authority's certificates stopped working during the overlap: %d %v", status, err)
		}
		stillTheSameProcess(t)
	})

	t.Run("dropping the old authority while the service still holds its certificate is refused", func(t *testing.T) {
		// The service's own certificate is the old authority's: a bundle without it
		// would leave the service unable to vouch for itself. It keeps what it has.
		if err := pki.WriteFileAtomic(pki.CAFile(p.dir), newCA.CertPEM(), 0o644); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, 5*time.Second, "the refusal to be logged", func() bool {
			poke()
			return strings.Contains(svc.out.String(), "does not chain to the CA bundle")
		})
		if status, _, err := call(admin, http.MethodGet, url+"/healthz", nil); err != nil || status != http.StatusOK {
			t.Fatalf("a half-done rollover locked everyone out: %d %v", status, err)
		}
		stillTheSameProcess(t)
	})

	t.Run("once the service holds a certificate of the new authority, the old authority's are refused", func(t *testing.T) {
		leaf, err := newCA.Issue(mtls.AuditService, pki.IssueOptions{TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		writeIdentity(t, p, mtls.AuditService, leaf)
		waitUntil(t, 5*time.Second, "the old authority to be dropped", func() bool {
			_, _, err := call(admin, http.MethodGet, url+"/healthz", nil)
			return err != nil
		})
		// This is how a compromise of the old authority is answered: no revocation
		// list to distribute, just a bundle that no longer contains it.
		probe = newAdmin
		if status, raw, err := call(newAdmin, http.MethodGet, url+"/healthz", nil); err != nil || status != http.StatusOK {
			t.Fatalf("the new authority's certificate is not accepted: %d %q %v\n%s", status, raw, err, svc.out.String())
		}
		stillTheSameProcess(t)
	})
}

// writeIdentity replaces the service's key and certificate on disk, key first —
// the order a careful operator (and pki.IssueToDir) uses.
func writeIdentity(t *testing.T, p *testPKI, service string, leaf *pki.Leaf) {
	t.Helper()
	if err := pki.WriteFileAtomic(pki.KeyFile(p.dir, service), leaf.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteFileAtomic(pki.CertFile(p.dir, service), leaf.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMTLS_AServiceWithoutAProperIdentityOfItsOwnDoesNotStart(t *testing.T) {
	root := repoRoot(t)
	p := newTestPKI(t)
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-refusals")
	sshBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-refusals")

	expiredDir := t.TempDir()
	if _, err := pki.IssueToDir(p.ca, expiredDir, mtls.Authorization, pki.IssueOptions{NotBefore: time.Now().Add(-3 * time.Hour), TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		bin  string
		env  []string
		want string
	}{
		{"no INTERNAL_TLS setting and no certificate: the default is mutual TLS, not its absence",
			authzBin, []string{"INTERNAL_TLS="},
			"TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE are not set"},
		{"a mistyped INTERNAL_TLS does not select either side",
			authzBin, append(p.env(mtls.Authorization), "INTERNAL_TLS=requried"),
			`INTERNAL_TLS must be "required"`},
		{"another service's certificate, however valid",
			authzBin, p.env(mtls.PasswordVault),
			`refusing to start with another service's identity`},
		{"an expired certificate",
			authzBin, []string{
				"INTERNAL_TLS=required", "TLS_TRUST_DOMAIN=" + mtlsDomain,
				"TLS_CERT_FILE=" + pki.CertFile(expiredDir, mtls.Authorization),
				"TLS_KEY_FILE=" + pki.KeyFile(expiredDir, mtls.Authorization),
				"TLS_CA_FILE=" + pki.CAFile(p.dir),
			},
			"expired at"},
		{"a certificate of another trust domain",
			authzBin, append(p.env(mtls.Authorization), "TLS_TRUST_DOMAIN=elsewhere.test"),
			"trust domain"},
		{"a proxy that names itself something other than its certificate does",
			sshBin, p.env(mtls.SSHProxy, "PROXY_SERVICE_ID=some-other-proxy", "RECORDING_POLICY=best-effort"),
			"remove PROXY_SERVICE_ID"},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			out := runUntilExit(t, root, c.bin, c.env...)
			if !strings.Contains(out, c.want) {
				t.Fatalf("the refusal should say %q; it said:\n%s", c.want, out)
			}
		})
	}
}
