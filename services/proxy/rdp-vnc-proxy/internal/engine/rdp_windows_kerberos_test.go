package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// Kerberos against Windows (ADR-0100, increment 4): the Windows of the interop test made its own
// domain controller (prepare.sh DOMAIN=kerberos), so the KDC is Microsoft's and the target its
// Remote Desktop Services, NLA on. The domain refuses incoming NTLM, as one that has closed it: a
// session that opens there was made by Kerberos, and the counter-proof shows NTLM refused by the
// same target for the same user.
//
//	set -a; . "$DIR/test.env"; set +a; go test ./services/proxy/rdp-vnc-proxy/internal/engine -run TestRDPWindowsKerberos -v
type rdpWindowsKerberos struct {
	realm, kdc, user, password string
}

func windowsKerberos(t *testing.T) (rdpWindowsTarget, rdpWindowsKerberos) {
	t.Helper()
	if os.Getenv("RDP_WINDOWS_KERBEROS") == "" {
		t.Skip("RDP_WINDOWS_KERBEROS not set: this test needs the Windows domain controller of prepare.sh DOMAIN=kerberos")
	}
	target := windowsTarget(t)
	k := rdpWindowsKerberos{realm: os.Getenv("RDP_WINDOWS_KERBEROS_REALM"), kdc: os.Getenv("RDP_WINDOWS_KERBEROS_KDC"),
		user: os.Getenv("RDP_WINDOWS_KERBEROS_USER"), password: os.Getenv("RDP_WINDOWS_KERBEROS_PASSWORD")}
	if k.realm == "" || k.kdc == "" || k.user == "" || k.password == "" {
		t.Fatal("RDP_WINDOWS_KERBEROS_REALM, _KDC, _USER and _PASSWORD are all needed")
	}
	return target, k
}

// credssp is one CredSSP exchange with the target, Kerberos when k is given, NTLM otherwise.
func (w rdpWindowsTarget) credssp(ctx context.Context, user, password string, k *rdp.KerberosConfig) error {
	transport, err := rdp.DialHybrid(ctx, rdp.TransportConfig{Address: w.address, TLSFingerprint: w.pin, TLSRoots: w.roots,
		TLSServerName: w.name, DialTimeout: 10 * time.Second})
	if err != nil {
		return err
	}
	defer transport.Close()
	session, err := transport.EstablishCredSSP(ctx, rdp.CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password),
		Timeout: 15 * time.Second, Kerberos: k})
	if err != nil {
		return err
	}
	session.Close()
	return nil
}

func TestRDPWindowsKerberos(t *testing.T) {
	target, k := windowsKerberos(t)
	kerberos := &rdp.KerberosConfig{Realm: k.realm, KDCs: []string{k.kdc}, ServicePrincipal: "TERMSRV/" + target.name, Timeout: 15 * time.Second}

	// The readiness task restarts Remote Desktop Services just after it installs the pinned
	// certificate: the first exchange is retried for a while, the others are not.
	t.Run("Windows accepts Kerberos alone, its own KDC issuing the tickets", func(t *testing.T) {
		deadline := time.Now().Add(5 * time.Minute)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := target.credssp(ctx, k.user, k.password, kerberos)
			cancel()
			if err == nil {
				return
			}
			if errors.Is(err, rdp.ErrTargetCredentialsRefused) || time.Now().After(deadline) {
				t.Fatalf("CredSSP with Kerberos: %v", err)
			}
			t.Logf("not yet: %v", err)
			time.Sleep(15 * time.Second)
		}
	})

	t.Run("the whole proxy: the account's realm, a ticket for the pinned name, the user's session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
			Type: "password", Material: []byte(k.password), TargetHost: target.address, TargetUser: k.user,
			TLSCertificateSHA256: target.pin, TargetDomain: target.name, KerberosRealm: k.realm, KerberosKDCs: []string{k.kdc},
		}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
		if err != nil {
			t.Fatal(err)
		}
		session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second}).Open(ctx, cred)
		if err != nil {
			var failure *proxycore.ScreenFailure
			if errors.As(err, &failure) {
				t.Fatalf("opening the screen with Kerberos: %s: %v", failure.ScreenEndCode(), failure.Err)
			}
			t.Fatalf("opening the screen with Kerberos: %v", err)
		}
		defer session.Close()
		var frame screenstream.Message
		select {
		case message, ok := <-session.Frames():
			if !ok {
				t.Fatalf("the stream ended before a frame: %v", session.Err())
			}
			frame = message
		case <-time.After(90 * time.Second):
			t.Fatalf("no frame in 90 s: %v", session.Err())
		}
		// Wait for Windows to say the session opened: a frame alone can be the logon screen.
		logon := false
		for end := time.Now().Add(90 * time.Second); time.Now().Before(end) && !logon; {
			if adapter, ok := session.(*rdpScreenSessionAdapter); ok {
				if rdpTarget, ok := adapter.target.(*rdpTargetSession); ok {
					logon = rdpTarget.session.LogonNotified()
				}
			}
			select {
			case message, ok := <-session.Frames():
				if ok {
					frame = message
				}
			case <-time.After(2 * time.Second):
			}
		}
		if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
			_ = os.WriteFile(filepath.Join(dir, "windows-kerberos.png"), frame.PNG, 0o644)
		}
		if !logon {
			t.Fatal("Windows did not say the session opened: the delegated credentials did not open it (windows-kerberos.png)")
		}
		t.Logf("the user's session opened by Kerberos: %dx%d", frame.Width, frame.Height)
	})

	t.Run("the counter-proof: the same user over NTLM is refused by this domain", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := target.credssp(ctx, k.user, k.password, nil)
		if err == nil {
			t.Fatal("NTLM opened: the domain does not refuse it, and Kerberos proved nothing")
		}
		if errors.Is(err, rdp.ErrTLSVerification) {
			t.Fatalf("not an NTLM refusal: %v", err)
		}
		t.Logf("NTLM refused: %v", err)
	})

	t.Run("a KDC out of reach ends the screen with kerberos_failed, never NTLM", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
			Type: "password", Material: []byte(k.password), TargetHost: target.address, TargetUser: k.user,
			TLSCertificateSHA256: target.pin, TargetDomain: target.name, KerberosRealm: k.realm, KerberosKDCs: []string{"127.0.0.1:1"},
		}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
		if err != nil {
			t.Fatal(err)
		}
		_, err = (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second}).Open(ctx, cred)
		var failure *proxycore.ScreenFailure
		if !errors.As(err, &failure) || failure.ScreenEndCode() != "kerberos_failed" {
			t.Fatalf("a KDC out of reach: %v", err)
		}
		t.Logf("kerberos_failed: %v", failure.Err)
	})

	t.Run("a wrong password stops at the KDC, said as refused credentials", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := target.credssp(ctx, k.user, k.password+"-not", kerberos)
		if !errors.Is(err, rdp.ErrTargetCredentialsRefused) || !errors.Is(err, rdp.ErrRDPKerberos) {
			t.Fatalf("a wrong password: %v", err)
		}
		t.Logf("refused by the KDC: %v", err)
	})
}
