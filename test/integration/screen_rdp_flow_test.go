// ADR-0088 on real processes: an RDP session from the public API to a real RDP server and back.
// The same eight services under mutual TLS as VNC's flow (screen_flow_test.go), with RDP switched
// on (RDP_ENABLED=true at the Broker and at the screen proxy), the real Video Recorder on
// PostgreSQL, and FreeRDP 3 in Docker as the target (test/integration/testdata/rdp/freerdp).
//
// The claims: an operator asks for an RDP session on a pinned account and gets a path and an
// HttpOnly cookie, never a ticket; the screen is the target's, its keys are scancodes and reach
// it; ending the session cuts the screen; what the operator saw is, to the byte, what an auditor
// replays. A second deployment, RDP off, refuses connect before any Vault scope.
//
// Skipped without RDP_INTEROP (Docker) or TEST_DATABASE_URL (the Video Recorder).
package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/mtls"
)

func TestScreenFlow_RDPFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses(t *testing.T) {
	if os.Getenv("RDP_INTEROP") == "" {
		t.Skip("RDP_INTEROP not set: this test builds and starts a real RDP server in Docker")
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: the Video Recorder needs PostgreSQL")
	}
	root := repoRoot(t)
	p := newTestPKI(t)
	target := startFreeRDPTarget(t, root)

	const (
		vaultURL       = "https://127.0.0.1:18881"
		auditURL       = "https://127.0.0.1:18882"
		authzURL       = "https://127.0.0.1:18883"
		brokerURL      = "https://127.0.0.1:18884"
		screenProxyURL = "https://127.0.0.1:18885"
		authnURL       = "https://127.0.0.1:18887"
		commandURL     = "https://127.0.0.1:18889"
		videoGRPCURL   = "https://127.0.0.1:18891"
		gatewayURL     = "http://127.0.0.1:18888"
	)
	rootsFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(rootsFile, target.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	store := newFakeObjectStore(t)
	audit := startScreenAuditSpy(t, p, auditURL)
	bin := func(path, name string) string { return buildBinary(t, root, path, name+"-rdp-screen") }
	start := func(path, name, port, identity string, env ...string) *mtlsProc {
		t.Helper()
		return startMTLSService(t, root, bin(path, name), port, p, identity, env...)
	}
	start("./services/vault/password-vault/cmd/password-vault", "vault", "18881", mtls.PasswordVault, "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authzURL, "AUDIT_URL="+auditURL)
	start("./services/recording-audit/audit-service/cmd/audit-service", "audit", "18882", mtls.AuditService)
	start("./services/access/authorization/cmd/authorization", "authz", "18883", mtls.Authorization)
	start("./services/access/authentication/cmd/authentication", "authn", "18887", mtls.Authentication, "SKIP_DEMO_SEED=1", "AUDIT_URL="+auditURL)
	start("./services/recording-audit/command-recorder/cmd/command-recorder", "command", "18889", mtls.CommandRecorder, "AUTHORIZATION_URL="+authzURL, "AUDIT_URL="+auditURL)
	video := start("./services/recording-audit/video-recorder/cmd/video-recorder", "video", "18890", mtls.VideoRecorder,
		"GRPC_PORT=18891", "DATABASE_URL="+dsn, "VIDEO_RECORDER_KMS_KEY_HEX="+strings.Repeat("ab", 32),
		"S3_ENDPOINT="+store.URL, "S3_BUCKET=screens", "S3_ACCESS_KEY=test", "S3_SECRET_KEY=test-secret", "S3_ALLOW_HTTP=true", "S3_CREATE_BUCKET=true",
		"AUTHORIZATION_URL="+authzURL, "AUDIT_URL="+auditURL)
	proxy := start("./services/proxy/rdp-vnc-proxy/cmd/rdp-vnc-proxy", "screen-proxy", "18885", mtls.RDPVNCProxy,
		"VAULT_URL="+vaultURL, "AUDIT_URL="+audit.URL, "VIDEO_RECORDER_GRPC_URL="+videoGRPCURL,
		"TARGET_TLS_ROOTS_FILE="+rootsFile, "RDP_VNC_PROXY_PUBLIC_ENDPOINT=127.0.0.1:18885", "RDP_ENABLED=true")
	start("./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy", "18886", mtls.SSHProxy, "SSH_PORT=18892", "VAULT_URL="+vaultURL, "AUDIT_URL="+auditURL, "RECORDER_URL="+commandURL, "RECORDING_POLICY=required")
	start("./services/access/session-broker/cmd/session-broker", "broker", "18884", mtls.SessionBroker,
		"AUTHORIZATION_URL="+authzURL, "VAULT_URL="+vaultURL, "AUDIT_URL="+auditURL, "SSH_PROXY_URL=https://127.0.0.1:18886", "RDP_VNC_PROXY_URLS="+screenProxyURL, "RDP_ENABLED=true")
	gateway := startService(t, root, bin("./services/access/api-gateway/cmd/api-gateway", "gateway"), "18888", p.env(mtls.APIGateway,
		"AUTHENTICATION_URL="+authnURL, "SESSION_BROKER_URL="+brokerURL, "VAULT_URL="+vaultURL,
		"AUTHORIZATION_URL="+authzURL, "COMMAND_RECORDER_URL="+commandURL, "VIDEO_RECORDER_GRPC_URL="+videoGRPCURL,
		"SESSION_REQUEST_BURST=100", "SESSION_ACTION_BURST=100", "VAULT_ACCOUNT_ACTION_BURST=100", "CLIENT_REQUEST_BURST=1000")...)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("video-recorder:\n%s\nrdp-vnc-proxy:\n%s\ngateway:\n%s", video.out.String(), proxy.out.String(), gateway.out.String())
		}
	})

	admin := p.clientAs(t, mtls.AdminCLI)
	mtlsCreateUser(t, admin, authnURL, "rdp-admin", "root-pw-123456", []string{"platform-admin", "vault-admin"})
	mtlsCreateUser(t, admin, authnURL, "rdp-operator", "op-password-123", []string{"rdp-ops"})
	mtlsCreateUser(t, admin, authnURL, "rdp-auditor", "aud-password-123", []string{"session-auditor"})
	login := func(user, password string) string {
		token, status := gatewayLogin(t, gatewayURL, user, password)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return token
	}
	adminToken, operatorToken, auditorToken := login("rdp-admin", "root-pw-123456"), login("rdp-operator", "op-password-123"), login("rdp-auditor", "aud-password-123")
	for _, pol := range []struct{ name, role, resource string }{
		{"rdp-vault-admins", "vault-admin", "vault:account-admin:*"},
		{"rdp-operators", "rdp-ops", "vault:account:*"},
		{"rdp-auditors", "session-auditor", "recording:session:*"},
	} {
		if status := gatewayCreatePolicy(t, gatewayURL, adminToken, pol.name, pol.role, pol.resource, "allow", "ignored"); status != http.StatusCreated {
			t.Fatalf("policy %s: %d", pol.name, status)
		}
	}

	api := screenAPI{t: t, url: gatewayURL}
	status, raw := api.call(adminToken, http.MethodPost, "/vault/accounts", map[string]any{
		"id": "acc_rdp", "name": "acc_rdp", "username": freeRDPUser, "targetHost": target.address, "protocol": "rdp", "rotationPolicy": "manual", "initialSecret": []byte(freeRDPPassword),
	})
	if status != http.StatusCreated {
		t.Fatalf("onboarding the RDP account: %d %s", status, raw)
	}
	status, raw = api.call(adminToken, http.MethodPut, "/vault/accounts/acc_rdp/tls-pin", map[string]any{"tlsCertificateSha256": target.pin, "targetDomain": freeRDPName})
	if status != http.StatusOK {
		t.Fatalf("pinning the RDP account: %d %s", status, raw)
	}
	status, raw = api.call(operatorToken, http.MethodPost, "/sessions", map[string]any{"targetAccountId": "acc_rdp", "protocol": "rdp", "justification": "ADR-0088", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("RDP session: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")

	// connect answers a path and an HttpOnly cookie: the proxy's ticket stays in the Gateway.
	attach := api.connect(operatorToken, id)
	conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
	defer conn.Close(websocket.StatusNormalClosure, "")
	// One reader for the whole session: a read whose context ends closes a WebSocket.
	messages := make(chan screenMessage, 256)
	go func() {
		defer close(messages)
		for {
			_, data, err := conn.Read(context.Background())
			if err != nil || len(data) < 32 {
				return
			}
			m := screenMessage{kind: data[1], sequence: binary.BigEndian.Uint64(data[4:12])}
			switch payload := data[32:]; m.kind {
			case 1:
				m.png = payload
			case 2:
				m.helloProtocol, m.helloSession = payload[0], string(payload[14:])
			case 3:
				m.endText = string(payload[4:])
			}
			messages <- m
		}
	}()
	next := func(limit time.Duration) (screenMessage, bool) {
		select {
		case m, ok := <-messages:
			if !ok {
				t.Fatal("the screen closed without an END")
			}
			return m, true
		case <-time.After(limit):
			return screenMessage{}, false
		}
	}
	if hello, ok := next(20 * time.Second); !ok || hello.kind != 2 || hello.helloProtocol != 1 || hello.helloSession != id {
		t.Fatalf("first message: %+v", hello)
	}
	shown := map[uint64][]byte{}
	var last screenMessage
	// Frames until none comes for quiet; the first one may take its time.
	settle := func(quiet time.Duration) {
		limit := 20 * time.Second
		for {
			m, ok := next(limit)
			if !ok {
				if last.kind == 0 {
					t.Fatal("no frame from the target")
				}
				return
			}
			if m.kind == 3 {
				t.Fatalf("the session ended: %q", m.endText)
			}
			if m.kind == 1 {
				shown[m.sequence], last, limit = m.png, m, quiet
			}
		}
	}
	settle(3 * time.Second)
	before := last

	// RDP takes scancodes (ADR-0088): xterm runs `cat`, what is typed shows only if it arrived.
	writeScreen(t, conn, inputPointer(100, 100, 0))
	for _, scancode := range []uint16{0x1e, 0x30, 0x1c} { // a, b, Enter
		writeScreen(t, conn, inputScancode(scancode, true))
		writeScreen(t, conn, inputScancode(scancode, false))
	}
	settle(3 * time.Second)
	if bytes.Equal(last.png, before.png) {
		t.Fatal("the keys changed nothing on the target's screen")
	}

	// Ending the session cuts the screen.
	status, raw = api.call(operatorToken, http.MethodDelete, "/sessions/"+id, nil)
	if status/100 != 2 {
		t.Fatalf("terminate: %d %s", status, raw)
	}
	for {
		m, ok := next(20 * time.Second)
		if !ok {
			t.Fatal("no END after the session was ended")
		}
		if m.kind == 1 {
			shown[m.sequence] = m.png
		}
		if m.kind == 3 {
			if m.endText != "session_revoked" {
				t.Fatalf("END = %q, want session_revoked", m.endText)
			}
			break
		}
	}

	// What the operator saw is what an auditor replays, through the public API.
	var replayed map[uint64][]byte
	complete := false
	waitUntil(t, 20*time.Second, "the sealed recording", func() bool {
		replayed, complete = map[uint64][]byte{}, false
		for firstSequence := uint64(1); ; {
			status, raw := api.call(auditorToken, http.MethodGet, fmt.Sprintf("/sessions/%s/recording/video/segments/%d", id, firstSequence), nil)
			if status == http.StatusNotFound && firstSequence > 1 {
				return complete
			}
			if status != http.StatusOK {
				return false
			}
			var segment struct {
				FirstSequence uint64 `json:"firstSequence"`
				LastSequence  uint64 `json:"lastSequence"`
				Complete      bool   `json:"complete"`
				Frames        []struct {
					FrameData string `json:"frameData"`
				} `json:"frames"`
			}
			if json.Unmarshal([]byte(raw), &segment) != nil || segment.LastSequence < segment.FirstSequence {
				return false
			}
			for i, frame := range segment.Frames {
				data, err := base64.StdEncoding.DecodeString(frame.FrameData)
				if err != nil {
					return false
				}
				replayed[segment.FirstSequence+uint64(i)] = data
			}
			complete = segment.Complete
			firstSequence = segment.LastSequence + 1
		}
	})
	for sequence, png := range shown {
		if !bytes.Equal(replayed[sequence], png) {
			t.Fatalf("frame %d: %d bytes replayed, %d shown", sequence, len(replayed[sequence]), len(png))
		}
	}
	t.Logf("%d frame(s) shown, %d replayed through the public API, sealed", len(shown), len(replayed))
	// The proxy says why it cut the connection, and that the credential was purged.
	waitUntil(t, 5*time.Second, "the revocation and the purge on the record", func() bool {
		return audit.saw("session.revoked", id) && audit.saw("session.terminate", id)
	})
}

func inputScancode(scancode uint16, pressed bool) []byte {
	m := make([]byte, 16)
	m[0], m[1] = 1, 1
	if pressed {
		m[2] = 1
	}
	binary.BigEndian.PutUint16(m[8:10], scancode)
	return m
}

// -- FreeRDP 3, the target ------------------------------------------------------------------------

const (
	freeRDPUser     = "operator"
	freeRDPPassword = "Demo-RDP-Pass1"
	freeRDPName     = "rdp-target"
)

type freeRDPTarget struct {
	address, pin string
	certPEM      []byte
}

func startFreeRDPTarget(t *testing.T, root string) freeRDPTarget {
	t.Helper()
	const image = "openbastion-test-freerdp:latest"
	if out, err := exec.Command("docker", "build", "-q", "-t", image, filepath.Join(root, "test", "integration", "testdata", "rdp", "freerdp")).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	container := fmt.Sprintf("ob-rdp-flow-%d", os.Getpid())
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::3389",
		"-e", "RDP_USER="+freeRDPUser, "-e", "RDP_PASSWORD="+freeRDPPassword, image).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	port, err := exec.Command("docker", "port", container, "3389/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	address := strings.TrimSpace(strings.Split(string(port), "\n")[0])
	deadline := time.Now().Add(30 * time.Second)
	for {
		raw, err := exec.Command("docker", "exec", container, "sh", "-c", "grep -qs :0D3D /proc/net/tcp /proc/net/tcp6 && cat ~/.config/freerdp/shadow/shadow.crt").Output()
		if block, _ := pem.Decode(raw); err == nil && block != nil {
			sum := sha256.Sum256(block.Bytes)
			return freeRDPTarget{address: address, pin: hex.EncodeToString(sum[:]), certPEM: raw}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
			t.Fatalf("the RDP target did not start: %s", logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
