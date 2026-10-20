package mtls_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

// logSink collects what Credentials says about itself.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, sprintf(format, args...))
}

func (l *logSink) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, substr) {
			n++
		}
	}
	return n
}

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

func credsWithLog(t *testing.T, s mtls.Settings, now func() time.Time) (*mtls.Credentials, *logSink) {
	t.Helper()
	sink := &logSink{}
	c, err := mtls.NewCredentialsAt(s, now, sink.logf)
	must(t, err)
	return c, sink
}

func TestRotation_AServerPresentsItsNewCertificateWithoutARestart(t *testing.T) {
	e := newEnv(t)
	srv := e.serve(e.creds("password-vault"), open)
	client, err := e.creds("ssh-proxy").Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
	must(t, err)

	before, err := serverSerial(client, srv.URL+"/")
	must(t, err)

	e.issue("password-vault", pki.IssueOptions{}) // the issuer renews: same identity, new certificate

	eventually(t, "the server to present its renewed certificate", func() bool {
		now, err := serverSerial(client, srv.URL+"/")
		return err == nil && now != before
	})
	if status, _, err := get(client, srv.URL+"/"); err != nil || status != 200 {
		t.Fatalf("after rotation: %d %v", status, err)
	}
}

func TestRotation_AClientPresentsItsNewCertificateWithoutARestart(t *testing.T) {
	e := newEnv(t)
	srv := e.serve(e.creds("password-vault"), open)
	proxy := e.creds("ssh-proxy")
	client, err := proxy.Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
	must(t, err)

	_, _, err = get(client, srv.URL+"/")
	must(t, err)
	before := srv.lastClientSerial()

	e.issue("ssh-proxy", pki.IssueOptions{})

	eventually(t, "the client to present its renewed certificate", func() bool {
		client.CloseIdleConnections()
		_, _, err := get(client, srv.URL+"/")
		return err == nil && srv.lastClientSerial() != before
	})
}

func TestRotation_ANewAuthorityIsTrustedOnceItIsInTheBundle(t *testing.T) {
	// The deployment moves to a second CA. Servers must keep refusing its
	// certificates until the bundle says otherwise — and accept them the moment
	// it does, with no restart.
	old := newEnv(t)
	next := newEnv(t)

	srv := old.serve(old.creds("password-vault"), open)

	// The client's identity comes from the new CA; its own bundle trusts both
	// (it must still verify the server, signed by the old one).
	s := next.issue("ssh-proxy", pki.IssueOptions{})
	both := append(old.ca.CertPEM(), next.ca.CertPEM()...)
	must(t, os.WriteFile(s.CAFile, both, 0o600))
	client, err := func() (*http.Client, error) {
		c, err := mtls.NewCredentials(s)
		if err != nil {
			return nil, err
		}
		return c.Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
	}()
	must(t, err)

	if _, _, err := get(client, srv.URL+"/"); err == nil {
		t.Fatal("a certificate from a CA the server does not trust was accepted")
	}

	// the operator adds the new authority to the server's bundle
	serverCA := old.settingsFor("password-vault").CAFile
	must(t, os.WriteFile(serverCA, append(old.ca.CertPEM(), next.ca.CertPEM()...), 0o600))

	eventually(t, "the server to trust the new authority", func() bool {
		client.CloseIdleConnections()
		status, _, err := get(client, srv.URL+"/")
		return err == nil && status == 200
	})
}

func TestRotation_ABadReplacementKeepsTheServiceRunningAndIsReportedOnce(t *testing.T) {
	e := newEnv(t)
	s := e.issue("password-vault", pki.IssueOptions{})
	creds, sink := credsWithLog(t, s, time.Now)
	srv := e.serve(creds, open)
	client, err := e.creds("ssh-proxy").Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
	must(t, err)
	before, err := serverSerial(client, srv.URL+"/")
	must(t, err)

	must(t, os.WriteFile(s.CertFile, []byte("-----BEGIN CERTIFICATE-----\ntorn write"), 0o600))

	// many handshakes, over many reload intervals
	for i := 0; i < 8; i++ {
		time.Sleep(30 * time.Millisecond)
		got, err := serverSerial(client, srv.URL+"/")
		if err != nil || got != before {
			t.Fatalf("the service stopped presenting its working certificate: %q %v", got, err)
		}
	}
	if n := sink.count("NOT reloading"); n != 1 {
		t.Errorf("the failed reload was reported %d times, want exactly once", n)
	}

	// a good replacement then takes over
	e.issue("password-vault", pki.IssueOptions{})
	eventually(t, "the repaired certificate to be picked up", func() bool {
		got, err := serverSerial(client, srv.URL+"/")
		return err == nil && got != before
	})
	if sink.count("reloaded the identity of password-vault") != 1 {
		t.Errorf("the successful reload was not reported once: %v", sink.lines)
	}
}

func TestRotation_AReplacementThatWouldChangeWhoTheServiceIsOrIsExpiredIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		install func(e *env, s mtls.Settings)
		logged  string
	}{
		"a certificate of another service": {
			func(e *env, s mtls.Settings) {
				leaf, err := e.ca.Issue("authorization", pki.IssueOptions{})
				must(t, err)
				must(t, os.WriteFile(s.KeyFile, leaf.KeyPEM, 0o600))
				must(t, os.WriteFile(s.CertFile, leaf.CertPEM, 0o600))
			}, `but this process is "password-vault"`,
		},
		"an expired certificate": {
			func(e *env, s mtls.Settings) {
				leaf, err := e.ca.Issue("password-vault", pki.IssueOptions{NotBefore: time.Now().Add(-3 * time.Hour), TTL: time.Hour})
				must(t, err)
				must(t, os.WriteFile(s.KeyFile, leaf.KeyPEM, 0o600))
				must(t, os.WriteFile(s.CertFile, leaf.CertPEM, 0o600))
			}, "expired",
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			s := e.issue("password-vault", pki.IssueOptions{})
			creds, sink := credsWithLog(t, s, time.Now)
			srv := e.serve(creds, open)
			client, err := e.creds("ssh-proxy").Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
			must(t, err)
			before, err := serverSerial(client, srv.URL+"/")
			must(t, err)

			tc.install(e, s)
			eventually(t, "the refusal to be logged", func() bool {
				_, _ = serverSerial(client, srv.URL+"/")
				return sink.count(tc.logged) > 0
			})
			if got, err := serverSerial(client, srv.URL+"/"); err != nil || got != before {
				t.Fatalf("the service switched to a certificate it should have refused: %q %v", got, err)
			}
			if creds.Identity() != "password-vault" {
				t.Errorf("identity is now %q", creds.Identity())
			}
		})
	}
}

func TestRotation_ExpiryIsAnnouncedBeforeAndWhenItHappens(t *testing.T) {
	e := newEnv(t)
	s := e.issue("password-vault", pki.IssueOptions{TTL: 10 * time.Hour})

	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }

	creds, sink := credsWithLog(t, s, now)
	touch := func() { _, _ = creds.ServerTLS().GetConfigForClient(&tls.ClientHelloInfo{}) } // a handshake

	advance(time.Second)
	touch()
	if sink.count("expires at") != 0 || sink.count("EXPIRED") != 0 {
		t.Fatalf("a fresh certificate was reported: %v", sink.lines)
	}

	advance(8*time.Hour + 30*time.Minute) // inside the last fifth of its life
	touch()
	touch()
	advance(time.Minute)
	touch()
	if n := sink.count("expires at"); n != 1 {
		t.Errorf("the approaching expiry was announced %d times, want once: %v", n, sink.lines)
	}

	advance(2 * time.Hour) // past NotAfter
	touch()
	touch()
	if n := sink.count("EXPIRED"); n != 1 {
		t.Errorf("the expiry was announced %d times, want once: %v", n, sink.lines)
	}
}
