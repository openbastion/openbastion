package mtls_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

// open lets any authenticated service call "/".
var open = []mtls.Rule{{Path: "/", Callers: []string{mtls.Any}}}

func TestHandshake_AValidServiceGetsThrough(t *testing.T) {
	e := newEnv(t)
	srv := e.serve(e.creds("password-vault"), open)
	client, err := e.creds("ssh-proxy").Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
	must(t, err)

	status, body, err := get(client, srv.URL+"/")
	if err != nil || status != http.StatusOK {
		t.Fatalf("status %d, err %v", status, err)
	}
	if body != "ssh-proxy" {
		t.Errorf("the server saw the caller as %q, want ssh-proxy — identity must come from the certificate", body)
	}
}

func TestHandshake_TheServerAcceptsNoOneWithoutAnIdentityOfItsOwnDomain(t *testing.T) {
	e := newEnv(t)
	srv := e.serve(e.creds("password-vault"), open)
	stranger := newEnv(t) // a different CA, same trust-domain name

	good := e.certFor("ssh-proxy", pki.IssueOptions{})
	base := func(certs ...tls.Certificate) *tls.Config {
		return &tls.Config{RootCAs: e.pool(), Certificates: certs, MinVersion: tls.VersionTLS13}
	}

	attacks := map[string]*tls.Config{
		"no client certificate at all":         base(),
		"a certificate from another authority": base(stranger.certFor("ssh-proxy", pki.IssueOptions{})),
		"an expired certificate": base(e.certFor("ssh-proxy", pki.IssueOptions{
			NotBefore: time.Now().Add(-3 * time.Hour), TTL: time.Hour})),
		"a certificate of another trust domain (same CA)": base(e.forge("spiffe://elsewhere.test/ssh-proxy")),
		"a certificate with two identities":               base(e.forge("spiffe://"+testDomain+"/ssh-proxy", "spiffe://"+testDomain+"/password-vault")),
		"a certificate with no identity":                  base(e.forge()),
		"a certificate with a malformed identity":         base(e.forge("spiffe://" + testDomain + "/Ssh/Proxy")),
	}
	for name, cfg := range attacks {
		t.Run(name, func(t *testing.T) {
			if status, _, err := get(rawClient(cfg), srv.URL+"/"); err == nil {
				t.Fatalf("got through with status %d", status)
			}
		})
	}
	if hits := srv.served(); len(hits) != 0 {
		t.Fatalf("handlers ran for %v — nothing should get past the handshake", hits)
	}

	t.Run("TLS 1.2 is not spoken", func(t *testing.T) {
		cfg := base(good)
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		if _, _, err := get(rawClient(cfg), srv.URL+"/"); err == nil {
			t.Fatal("a TLS 1.2 client was served")
		}
	})

	t.Run("the control: the same client with a good certificate is served", func(t *testing.T) {
		if status, who, err := get(rawClient(base(good)), srv.URL+"/"); err != nil || status != 200 || who != "ssh-proxy" {
			t.Fatalf("%d %q %v", status, who, err)
		}
	})
}

func TestHandshake_TheClientKnowsWhoItIsTalkingTo(t *testing.T) {
	e := newEnv(t)
	// A server that is a perfectly valid member of the deployment — but it is the
	// command-recorder, not the Vault.
	impostor := e.serve(e.creds("command-recorder"), open)
	me := e.creds("session-broker")

	t.Run("a valid certificate of the wrong service is refused", func(t *testing.T) {
		client, err := me.Client(mtls.Peer{URL: impostor.URL, Service: "password-vault"})
		must(t, err)
		_, _, err = get(client, impostor.URL+"/")
		if err == nil {
			t.Fatal("the client talked to the wrong service")
		}
		if !strings.Contains(err.Error(), `answered as "command-recorder", expected "password-vault"`) {
			t.Errorf("the refusal does not say why: %v", err)
		}
		if hits := impostor.served(); len(hits) != 0 {
			t.Fatalf("a request reached the impostor: %v", hits)
		}
	})
	t.Run("the control: the right expectation is served", func(t *testing.T) {
		client, err := me.Client(mtls.Peer{URL: impostor.URL, Service: "command-recorder"})
		must(t, err)
		if status, _, err := get(client, impostor.URL+"/"); err != nil || status != 200 {
			t.Fatalf("%d %v", status, err)
		}
	})
	t.Run("an address that is not a registered peer is not dialled", func(t *testing.T) {
		client, err := me.Client(mtls.Peer{URL: impostor.URL, Service: "command-recorder"})
		must(t, err)
		other := e.serve(e.creds("audit-service"), open)
		if _, _, err := get(client, other.URL+"/"); err == nil || !strings.Contains(err.Error(), "not a registered peer") {
			t.Fatalf("expected a refusal to dial, got %v", err)
		}
		if len(other.served()) != 0 {
			t.Fatal("the unregistered server was reached")
		}
	})
	t.Run("plaintext is refused", func(t *testing.T) {
		client, err := me.Client(mtls.Peer{URL: impostor.URL, Service: "command-recorder"})
		must(t, err)
		if _, _, err := get(client, "http://"+impostor.Addr+"/"); err == nil || !strings.Contains(err.Error(), "plaintext") {
			t.Fatalf("expected a refusal of plaintext, got %v", err)
		}
	})
	t.Run("an http:// peer is a configuration error, caught at start", func(t *testing.T) {
		if _, err := me.Client(mtls.Peer{URL: "http://127.0.0.1:8081", Service: "password-vault"}); err == nil || !strings.Contains(err.Error(), "requires https") {
			t.Fatalf("expected an https requirement, got %v", err)
		}
	})
	t.Run("one address cannot be two services", func(t *testing.T) {
		if _, err := me.Client(
			mtls.Peer{URL: "https://127.0.0.1:9000", Service: "password-vault"},
			mtls.Peer{URL: "https://127.0.0.1:9000", Service: "command-recorder"}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("a server presenting a certificate for another address is refused", func(t *testing.T) {
		// Valid for the right service, but for the wrong machine.
		s := e.issue("audit-service", pki.IssueOptions{DNSNames: []string{"elsewhere.test"}, IPs: []net.IP{}})
		c, err := mtls.NewCredentials(s)
		must(t, err)
		srv := e.serve(c, open)
		client, err := me.Client(mtls.Peer{URL: srv.URL, Service: "audit-service"})
		must(t, err)
		if _, _, err := get(client, srv.URL+"/"); err == nil {
			t.Fatal("a certificate that does not name this address was accepted")
		}
	})
}

func TestHandshake_InternalTrafficIgnoresTheEgressProxy(t *testing.T) {
	e := newEnv(t)
	srv := e.serve(e.creds("password-vault"), open)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	client, err := e.creds("ssh-proxy").Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
	must(t, err)
	// Go never proxies loopback addresses, so the call above cannot tell a
	// client that honours HTTPS_PROXY from one that does not: assert the
	// property itself — a production address like vault.internal would be sent
	// to the proxy by a default transport, leaking the client certificate's use.
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("the internal client may route through an egress proxy")
	}
	if status, _, err := get(client, srv.URL+"/"); err != nil || status != 200 {
		t.Fatalf("%d %v", status, err)
	}
}

func TestHandshake_AServerWithoutGuardStillDemandsACertificate(t *testing.T) {
	// ServerTLS alone — before any route is considered — is the first wall.
	e := newEnv(t)
	c := e.creds("password-vault")
	cfg := c.ServerTLS()
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("the fallback configuration does not demand a client certificate: %v", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("minimum version %x", cfg.MinVersion)
	}
	dyn, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	must(t, err)
	if dyn.ClientAuth != tls.RequireAndVerifyClientCert || dyn.MinVersion != tls.VersionTLS13 || dyn.ClientCAs == nil || len(dyn.Certificates) != 1 {
		t.Errorf("per-handshake configuration is not strict: %+v", dyn)
	}
}
