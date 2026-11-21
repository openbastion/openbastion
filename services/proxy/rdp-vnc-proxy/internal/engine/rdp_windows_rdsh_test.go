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
)

// The RDS licensing exchange against Windows (ADR-0099, increment 2): the Windows of the interop test
// made a Remote Desktop Session Host with its own license server (prepare.sh DOMAIN=rdsh), which
// challenges the client and issues it a license. The proxy keeps it, and presents it again at the next
// connection: the user's session opens each time, and the cache says the license was issued, then
// presented.
//
//	set -a; . "$DIR/test.env"; set +a; go test ./services/proxy/rdp-vnc-proxy/internal/engine -run TestRDPWindowsRDSH -v
func TestRDPWindowsRDSH(t *testing.T) {
	if os.Getenv("RDP_WINDOWS_RDSH") == "" {
		t.Skip("RDP_WINDOWS_RDSH not set: this test needs the session host of prepare.sh DOMAIN=rdsh")
	}
	target := windowsTarget(t)
	cache, err := rdp.NewLicenseCache()
	if err != nil {
		t.Fatal(err)
	}
	// open opens the user's session through the whole proxy, with the cache, and waits for Windows
	// to say it opened.
	open := func(t *testing.T, name string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
			Type: "password", Material: []byte(target.password), TargetHost: target.address, TargetUser: target.user,
			TLSCertificateSHA256: target.pin, TargetDomain: target.name,
		}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
		if err != nil {
			return err
		}
		session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second, Licenses: cache}).Open(ctx, cred)
		if err != nil {
			var failure *proxycore.ScreenFailure
			if errors.As(err, &failure) {
				return errors.Join(err, failure.Err)
			}
			return err
		}
		defer session.Close()
		logon := false
		for end := time.Now().Add(90 * time.Second); time.Now().Before(end) && !logon; {
			select {
			case message, ok := <-session.Frames():
				if !ok {
					return errors.Join(errors.New("the stream ended"), session.Err())
				}
				if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
					_ = os.WriteFile(filepath.Join(dir, name), message.PNG, 0o644)
				}
			case <-time.After(2 * time.Second):
			}
			if adapter, ok := session.(*rdpScreenSessionAdapter); ok {
				if rdpTarget, ok := adapter.target.(*rdpTargetSession); ok {
					logon = rdpTarget.session.LogonNotified()
				}
			}
		}
		if !logon {
			return errors.New("Windows did not say the session opened")
		}
		return nil
	}

	t.Run("the session opens through the host's licensing", func(t *testing.T) {
		// The readiness task restarts Remote Desktop Services just after it installs the pinned
		// certificate: the first session is retried for a while.
		deadline := time.Now().Add(5 * time.Minute)
		for {
			err := open(t, "windows-rdsh-first.png")
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the first session: %v", err)
			}
			t.Logf("not yet: %v", err)
			time.Sleep(15 * time.Second)
		}
		// What the host did: a host in its grace period licenses no one (STATUS_VALID_CLIENT), one
		// that issues challenges, then issues a license (CI of PR #259: the grace period, so far).
		t.Logf("after the first session: %+v", cache.Stats())
	})

	t.Run("the next session presents the license kept, and opens", func(t *testing.T) {
		if cache.Stats().Issued == 0 {
			t.Skip("the host issued no license (a session host in its grace period licenses no one): nothing to present again; the exchange of a license is proven against the test's host only")
		}
		if err := open(t, "windows-rdsh-second.png"); err != nil {
			t.Fatalf("the second session: %v", err)
		}
		stats := cache.Stats()
		t.Logf("after the second session: %+v", stats)
		if stats.Presented != 1 || stats.Held != 1 {
			t.Fatal("the license kept was not presented again")
		}
	})
}
