package hostkey_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/hostkey"
)

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func line(k ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) }

type certOpt func(*ssh.Certificate)

// certify returns host's key certified by ca, for target.example, valid an hour around now.
func certify(t *testing.T, ca ssh.Signer, host ssh.PublicKey, opts ...certOpt) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{Key: host, CertType: ssh.HostCert, KeyId: "target", ValidPrincipals: []string{"target.example"},
		ValidAfter: uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix())}
	for _, o := range opts {
		o(c)
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func trust(t *testing.T, l string) hostkey.Trust {
	t.Helper()
	tr, err := hostkey.Parse(l)
	if err != nil {
		t.Fatalf("Parse(%q): %v", l, err)
	}
	return tr
}

func check(tr hostkey.Trust, key ssh.PublicKey) error {
	cfg := &ssh.ClientConfig{}
	tr.Configure(cfg, func() time.Time { return now })
	return cfg.HostKeyCallback("10.0.0.9:22", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 22}, key)
}

func TestNormalize_AKeyOrOneAuthorityLine_NothingElse(t *testing.T) {
	ca, host := signer(t), signer(t)
	k := line(host.PublicKey())
	for in, want := range map[string]string{
		k:                              k,
		k + " root@target":             k,
		"target.example,10.0.0.9 " + k: k,
		"@cert-authority Target.Example " + line(ca.PublicKey()) + " ca@org": "@cert-authority target.example " + line(ca.PublicKey()),
		"@cert-authority 10.0.0.9 " + line(ca.PublicKey()):                   "@cert-authority 10.0.0.9 " + line(ca.PublicKey()),
		"@cert-authority 2001:db8::9 " + line(ca.PublicKey()):                "@cert-authority 2001:db8::9 " + line(ca.PublicKey()),
	} {
		got, fp, err := hostkey.Normalize(in)
		if err != nil || got != want || fp == "" {
			t.Fatalf("Normalize(%q) = %q, %q, %v; want %q", in, got, fp, err, want)
		}
	}
	_, fp, _ := hostkey.Normalize("@cert-authority target.example " + line(ca.PublicKey()))
	if fp != ssh.FingerprintSHA256(ca.PublicKey()) {
		t.Fatalf("the fingerprint of an authority line is %s, want the authority's", fp)
	}
	cert := certify(t, ca, host.PublicKey())
	for _, bad := range []string{
		"", "   ", "not a key", k + "\n" + k,
		"@revoked target.example " + k,
		"@cert-authority " + line(ca.PublicKey()),                       // no name
		"@cert-authority *.example " + line(ca.PublicKey()),             // a pattern
		"@cert-authority ?arget " + line(ca.PublicKey()),                // a pattern
		"@cert-authority !evil " + line(ca.PublicKey()),                 // a negation
		"@cert-authority a.example,b.example " + line(ca.PublicKey()),   // a list
		"@cert-authority [target.example]:2222 " + line(ca.PublicKey()), // a port
		"@cert-authority target.example:22 " + line(ca.PublicKey()),     // a port
		"@cert-authority target.example not-a-key",
		"@cert-authority " + strings.Repeat("a", hostkey.MaxNameBytes+1) + " " + line(ca.PublicKey()),
		"@CERT-AUTHORITY target.example " + line(ca.PublicKey()),
		line(cert), // a certificate is presented, not pinned
		"@cert-authority target.example " + line(cert), // nor is it an authority
	} {
		if _, _, err := hostkey.Normalize(bad); !errors.Is(err, hostkey.ErrBadLine) {
			t.Fatalf("Normalize(%.80q) = %v, want ErrBadLine", bad, err)
		}
	}
}

func TestPinned_ExactlyTheKey(t *testing.T) {
	ca, host, other := signer(t), signer(t), signer(t)
	tr := trust(t, line(host.PublicKey()))
	if err := check(tr, host.PublicKey()); err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]ssh.PublicKey{
		"another key": other.PublicKey(),
		// The pinned key itself, in a certificate: a pinned account takes nothing but its key.
		"a certificate of the pinned key": certify(t, ca, host.PublicKey()),
	} {
		if err := check(tr, k); !errors.Is(err, hostkey.ErrMismatch) {
			t.Fatalf("%s: %v, want ErrMismatch", name, err)
		}
	}
}

func TestAuthority_AHostCertificateOfThisAuthorityForThisName_DuringItsPeriod(t *testing.T) {
	ca, host := signer(t), signer(t)
	tr := trust(t, "@cert-authority target.example "+line(ca.PublicKey()))
	if err := check(tr, certify(t, ca, host.PublicKey())); err != nil {
		t.Fatalf("a valid certificate was refused: %v", err)
	}
	if err := check(tr, certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.ValidPrincipals = []string{"other.example", "target.example"} })); err != nil {
		t.Fatalf("a certificate whose names include the account's was refused: %v", err)
	}
}

func TestAuthority_EveryImpostorIsRefused(t *testing.T) {
	ca, host, rogue := signer(t), signer(t), signer(t)
	tr := trust(t, "@cert-authority target.example "+line(ca.PublicKey()))
	forged := certify(t, ca, host.PublicKey())
	forged.Signature.Blob[0] ^= 0xff // the authority's signature, broken
	for name, key := range map[string]ssh.PublicKey{
		"a plain key":                           host.PublicKey(),
		"the authority's own key":               ca.PublicKey(),
		"a certificate of another authority":    certify(t, rogue, host.PublicKey()),
		"a user certificate":                    certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.CertType = ssh.UserCert }),
		"a certificate for another name":        certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.ValidPrincipals = []string{"other.example"} }),
		"a certificate for any name":            certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.ValidPrincipals = nil }),
		"a certificate for the dialled address": certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.ValidPrincipals = []string{"10.0.0.9"} }),
		"an expired certificate":                certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.ValidBefore = uint64(now.Add(-time.Minute).Unix()) }),
		"a certificate not yet valid":           certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.ValidAfter = uint64(now.Add(time.Minute).Unix()) }),
		"a certificate without an end":          certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.ValidBefore = ssh.CertTimeInfinity }),
		"a certificate with a critical option":  certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "x"} }),
		"a forged signature":                    forged,
	} {
		if err := check(tr, key); !errors.Is(err, hostkey.ErrMismatch) {
			t.Fatalf("%s: %v, want ErrMismatch", name, err)
		}
	}
}

// A real handshake: a client configured for an authority offers certificate algorithms only, and
// is sent the target's certificate; a target that has none cannot be negotiated with.
func TestAuthority_ARealHandshake(t *testing.T) {
	ca, host := signer(t), signer(t)
	cert := certify(t, ca, host.PublicKey(), func(c *ssh.Certificate) {
		c.ValidAfter, c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix()), uint64(time.Now().Add(time.Hour).Unix())
	})
	certSigner, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(serverKey ssh.Signer) error {
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(serverKey)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_, _, _, _ = ssh.NewServerConn(c, cfg)
				c.Close()
			}
		}()
		cc := &ssh.ClientConfig{User: "u", Timeout: 5 * time.Second}
		trust(t, "@cert-authority target.example "+line(ca.PublicKey())).Configure(cc, nil)
		client, err := ssh.Dial("tcp", ln.Addr().String(), cc)
		if err == nil {
			client.Close()
		}
		return err
	}
	if err := dial(certSigner); err != nil {
		t.Fatalf("a target with a valid certificate: %v", err)
	}
	// A target without a certificate is negotiated with, and refused by the verification: what
	// makes the refusal a host key mismatch, said and audited, rather than a negotiation failure.
	if err := dial(host); err == nil || !strings.Contains(err.Error(), "plain key") {
		t.Fatalf("a target with a plain key: %v, want a refusal of the plain key", err)
	}
}

// The command the administration guide gives, run with OpenSSH's own ssh-keygen: the certificate
// it makes is accepted for its name, and for no other.
func TestAuthority_ACertificateMadeByOpenSSHsKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(keygen, args...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
		}
	}
	ca, host := filepath.Join(dir, "ca_hosts"), filepath.Join(dir, "ssh_host_ed25519_key")
	run("-q", "-t", "ed25519", "-N", "", "-f", ca)
	run("-q", "-t", "ed25519", "-N", "", "-f", host)
	// ssh-keygen refuses a private key others can read; some environments' defaults allow it.
	if err := os.Chmod(ca, 0o600); err != nil {
		t.Fatal(err)
	}
	run("-s", ca, "-h", "-I", "cible", "-n", "cible.example", "-V", "+4w", host+".pub")
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(read(host + "-cert.pub")))
	if err != nil {
		t.Fatal(err)
	}
	check := func(l string) error {
		cfg := &ssh.ClientConfig{}
		trust(t, l).Configure(cfg, nil)
		return cfg.HostKeyCallback("10.0.0.9:22", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 22}, certKey)
	}
	if err := check("@cert-authority cible.example " + read(ca+".pub")); err != nil {
		t.Fatalf("OpenSSH's certificate was refused: %v", err)
	}
	if err := check("@cert-authority autre.example " + read(ca+".pub")); !errors.Is(err, hostkey.ErrMismatch) {
		t.Fatalf("OpenSSH's certificate for cible.example was accepted for autre.example: %v", err)
	}
}
