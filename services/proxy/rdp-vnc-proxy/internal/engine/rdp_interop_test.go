package engine

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/rdp"
)

// A real RDP server, FreeRDP 3 (test/integration/testdata/rdp/freerdp, ADR-0071): every byte of this
// client's protocol stack has only ever met fakes written from the same reading of the specification
// until this test, and they shared its mistakes. Not Windows: that criterion stays open.
//
//	make test-rdp-interop
type rdpInteropTarget struct {
	address, container, pin string
	roots                   *x509.CertPool
}

const (
	rdpInteropUser     = "operator"
	rdpInteropPassword = "Demo-RDP-Pass1"
	rdpInteropName     = "rdp-target"
)

func startRDPInteropTarget(t *testing.T) rdpInteropTarget {
	t.Helper()
	if os.Getenv("RDP_INTEROP") == "" {
		t.Skip("RDP_INTEROP not set: this test builds and starts a real RDP server in Docker")
	}
	_, here, _, _ := runtime.Caller(0)
	context := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "..", "test", "integration", "testdata", "rdp", "freerdp")
	const image = "openbastion-test-freerdp:latest"
	if out, err := exec.Command("docker", "build", "-q", "-t", image, context).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	container := fmt.Sprintf("ob-rdp-interop-%d", os.Getpid())
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::3389",
		"-e", "RDP_USER="+rdpInteropUser, "-e", "RDP_PASSWORD="+rdpInteropPassword, image).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	port, err := exec.Command("docker", "port", container, "3389/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	target := rdpInteropTarget{address: strings.TrimSpace(strings.Split(string(port), "\n")[0]), container: container}
	deadline := time.Now().Add(30 * time.Second)
	for {
		// The certificate, once the server listens (0D3D is 3389 in /proc/net/tcp).
		raw, err := exec.Command("docker", "exec", container, "sh", "-c", "grep -qs :0D3D /proc/net/tcp /proc/net/tcp6 && cat ~/.config/freerdp/shadow/shadow.crt").Output()
		logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
		if block, _ := pem.Decode(raw); err == nil && block != nil {
			sum := sha256.Sum256(block.Bytes)
			target.pin = hex.EncodeToString(sum[:])
			target.roots = x509.NewCertPool()
			target.roots.AppendCertsFromPEM(raw)
			return target
		}
		if time.Now().After(deadline) {
			t.Fatalf("the target did not start: %s", logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (r rdpInteropTarget) logs(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "logs", r.container).CombinedOutput()
	if err != nil {
		t.Fatalf("docker logs: %v", err)
	}
	return string(out)
}

func (r rdpInteropTarget) authenticate(ctx context.Context, password string) (*rdp.CredSSPClientSession, error) {
	transport, err := rdp.DialHybrid(ctx, rdp.TransportConfig{
		Address: r.address, TLSFingerprint: r.pin, TLSRoots: r.roots, TLSServerName: rdpInteropName, DialTimeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	session, err := transport.EstablishCredSSP(ctx, rdp.CredSSPClientConfig{
		Version: 6, Username: rdpInteropUser, Password: []byte(password), Timeout: 10 * time.Second,
	})
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return session, nil
}

func TestRDPInterop_CredSSP(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("the server accepts the proof, and this client the server's", func(t *testing.T) {
		session, err := target.authenticate(ctx, rdpInteropPassword)
		if err != nil {
			t.Fatalf("%v\n%s", err, target.logs(t))
		}
		session.Close()
	})
	t.Run("a wrong password authenticates nothing", func(t *testing.T) {
		if session, err := target.authenticate(ctx, "not-the-password"); err == nil {
			session.Close()
			t.Fatal("authenticated with a wrong password")
		}
		if logs := target.logs(t); !strings.Contains(logs, "MESSAGE_ALTERED") && !strings.Contains(logs, "LOGON_FAILURE") {
			t.Fatalf("the server did not refuse the proof: nothing above says why it failed\n%s", logs)
		}
	})
	t.Run("an impostor's pin stops before any CredSSP byte", func(t *testing.T) {
		before := target.logs(t)
		other := target
		other.pin = strings.Repeat("0", 64)
		_, err := other.authenticate(ctx, rdpInteropPassword)
		if !errors.Is(err, rdp.ErrTLSVerification) {
			t.Fatalf("%v", err)
		}
		time.Sleep(time.Second)
		if logs := target.logs(t)[len(before):]; strings.Contains(logs, "NTLM") || strings.Contains(logs, "AcceptSecurityContext") {
			t.Fatalf("the target received CredSSP: %s", logs)
		}
	})
}
