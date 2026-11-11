// ADR-0071 on real processes: a VNC session from the public API to the target and back. Eight
// services under mutual TLS, the real Video Recorder on PostgreSQL, and a target — the fake RFB
// server below, which can say what reached it, and a real one when OPENBASTION_VNC_TARGET names it
// (test/integration/testdata/vnc/target.sh).
//
// The claims: the browser gets a path and an HttpOnly cookie, never a ticket; the cookie attaches
// once; the operator sees, byte for byte, what the recorder acknowledged and an auditor replays;
// the secret goes only to the target that presents the pinned certificate; the keyboard reaches
// the target; ending the session cuts the target and the screen; a recorder that is down refuses
// the session before the target is contacted.
//
// Skipped without TEST_DATABASE_URL: the Video Recorder refuses to run without durable metadata.
package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image/png"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestScreenFlow_VNCFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: the Video Recorder needs PostgreSQL")
	}
	root := repoRoot(t)
	p := newTestPKI(t)

	const (
		vaultURL       = "https://127.0.0.1:18841"
		auditURL       = "https://127.0.0.1:18842"
		authzURL       = "https://127.0.0.1:18843"
		brokerURL      = "https://127.0.0.1:18844"
		screenProxyURL = "https://127.0.0.1:18845"
		authnURL       = "https://127.0.0.1:18847"
		commandURL     = "https://127.0.0.1:18849"
		videoGRPCURL   = "https://127.0.0.1:18851"
		gatewayURL     = "http://127.0.0.1:18848"
	)

	const vaultSecret = "the-vault-secret-of-the-target"
	good := newFakeRFBTarget(t, "vnc-target.test", vaultSecret)
	imposter := newFakeRFBTarget(t, "vnc-target.test", vaultSecret)
	lasting := newFakeRFBTarget(t, "vnc-target.test", vaultSecret) // for the session that expires

	refusals := []struct {
		name, account, want string
		target              *fakeRFBTarget
		secret              string // what the account holds, vaultSecret if empty
		secretReachesTarget bool
	}{
		{
			name: "a target without VeNCrypt gets nothing", account: "refused_no_vencrypt", want: "tls_required",
			target: newFakeRFBTarget(t, "vnc-target.test", vaultSecret, fakeRFBBehavior{securityTypes: []byte{1, 2}}), // None, VNC Authentication
		},
		{
			name: "a target with VeNCrypt but without X.509 gets nothing", account: "refused_no_x509", want: "tls_required",
			target: newFakeRFBTarget(t, "vnc-target.test", vaultSecret, fakeRFBBehavior{subtype: 257}), // TLSNone
		},
		{
			name: "a target in RFB 3.3 gets nothing", account: "refused_rfb33", want: "protocol_version_unsupported",
			target: newFakeRFBTarget(t, "vnc-target.test", vaultSecret, fakeRFBBehavior{version: "RFB 003.003\n"}),
		},
		{
			name: "a secret of more than 8 bytes is not truncated for X509Vnc", account: "refused_truncation", want: "codec_unsupported",
			target: newFakeRFBTarget(t, "vnc-target.test", vaultSecret, fakeRFBBehavior{subtype: 261}),
		},
		{
			name: "a target refusing the password shows no frame", account: "refused_password", want: "target_unreachable",
			target: newFakeRFBTarget(t, "vnc-target.test", vaultSecret), secret: "not-what-the-target-expects", secretReachesTarget: true,
		},
		{
			name: "a rectangle out of bounds ends the session", account: "refused_rectangle", want: "codec_unsupported", secretReachesTarget: true,
			target: newFakeRFBTarget(t, "vnc-target.test", vaultSecret, fakeRFBBehavior{firstUpdate: rfbUpdate(0, 0, 9, 1, 0)}), // the desktop is 8 wide
		},
		{
			name: "an encoding that was not asked for ends the session", account: "refused_encoding", want: "codec_unsupported", secretReachesTarget: true,
			target: newFakeRFBTarget(t, "vnc-target.test", vaultSecret, fakeRFBBehavior{firstUpdate: rfbUpdate(0, 0, 8, 6, 7)}), // Tight
		},
	}

	// The proxy trusts every certificate, as an installation trusts its whole authority: the pin
	// is what tells them apart, not the chain.
	rootsFile := filepath.Join(t.TempDir(), "roots.pem")
	roots := append(append(append([]byte{}, good.certPEM...), imposter.certPEM...), lasting.certPEM...)
	for _, tc := range refusals {
		roots = append(roots, tc.target.certPEM...)
	}
	real := realVNCTargetFromEnv(t)
	if real != nil {
		roots = append(roots, real.certPEM...)
	}
	if err := os.WriteFile(rootsFile, roots, 0o600); err != nil {
		t.Fatal(err)
	}

	store := newFakeObjectStore(t)
	audit := startScreenAuditSpy(t, p, auditURL)

	bin := func(path, name string) string { return buildBinary(t, root, path, name+"-screen") }
	outputs := map[string]*syncBuffer{}
	start := func(path, name, port, identity string, env ...string) *mtlsProc {
		t.Helper()
		proc := startMTLSService(t, root, bin(path, name), port, p, identity, env...)
		outputs[name] = proc.out
		return proc
	}
	start("./services/vault/password-vault/cmd/password-vault", "vault", "18841", mtls.PasswordVault, "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authzURL, "AUDIT_URL="+auditURL)
	start("./services/recording-audit/audit-service/cmd/audit-service", "audit", "18842", mtls.AuditService)
	start("./services/access/authorization/cmd/authorization", "authz", "18843", mtls.Authorization)
	start("./services/access/authentication/cmd/authentication", "authn", "18847", mtls.Authentication, "SKIP_DEMO_SEED=1", "AUDIT_URL="+auditURL)
	start("./services/recording-audit/command-recorder/cmd/command-recorder", "command", "18849", mtls.CommandRecorder, "AUTHORIZATION_URL="+authzURL, "AUDIT_URL="+auditURL)
	video := start("./services/recording-audit/video-recorder/cmd/video-recorder", "video", "18850", mtls.VideoRecorder,
		"GRPC_PORT=18851", "DATABASE_URL="+dsn, "VIDEO_RECORDER_KMS_KEY_HEX="+strings.Repeat("ab", 32),
		"S3_ENDPOINT="+store.URL, "S3_BUCKET=screens", "S3_ACCESS_KEY=test", "S3_SECRET_KEY=test-secret", "S3_ALLOW_HTTP=true", "S3_CREATE_BUCKET=true",
		"AUTHORIZATION_URL="+authzURL, "AUDIT_URL="+auditURL)
	proxy := start("./services/proxy/rdp-vnc-proxy/cmd/rdp-vnc-proxy", "screen-proxy", "18845", mtls.RDPVNCProxy,
		"VAULT_URL="+vaultURL, "AUDIT_URL="+audit.URL, "VIDEO_RECORDER_GRPC_URL="+videoGRPCURL,
		"TARGET_TLS_ROOTS_FILE="+rootsFile, "RDP_VNC_PROXY_PUBLIC_ENDPOINT=127.0.0.1:18845")
	start("./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy", "18846", mtls.SSHProxy, "SSH_PORT=18852", "VAULT_URL="+vaultURL, "AUDIT_URL="+auditURL, "RECORDER_URL="+commandURL, "RECORDING_POLICY=required")
	start("./services/access/session-broker/cmd/session-broker", "broker", "18844", mtls.SessionBroker,
		"AUTHORIZATION_URL="+authzURL, "VAULT_URL="+vaultURL, "AUDIT_URL="+auditURL, "SSH_PROXY_URL=https://127.0.0.1:18846", "RDP_VNC_PROXY_URLS="+screenProxyURL)
	gateway := startService(t, root, bin("./services/access/api-gateway/cmd/api-gateway", "gateway"), "18848", p.env(mtls.APIGateway,
		"AUTHENTICATION_URL="+authnURL, "SESSION_BROKER_URL="+brokerURL, "VAULT_URL="+vaultURL,
		"AUTHORIZATION_URL="+authzURL, "COMMAND_RECORDER_URL="+commandURL, "VIDEO_RECORDER_GRPC_URL="+videoGRPCURL,
		"SESSION_REQUEST_BURST=100", "SESSION_ACTION_BURST=100", "VAULT_ACCOUNT_ACTION_BURST=100", "CLIENT_REQUEST_BURST=1000")...)
	outputs["gateway"] = gateway.out
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("video-recorder:\n%s\nrdp-vnc-proxy:\n%s", video.out.String(), proxy.out.String())
		}
	})

	admin := p.clientAs(t, mtls.AdminCLI)
	mtlsCreateUser(t, admin, authnURL, "screen-admin", "root-pw-123456", []string{"platform-admin", "vault-admin"})
	mtlsCreateUser(t, admin, authnURL, "screen-operator", "op-password-123", []string{"screen-ops"})
	mtlsCreateUser(t, admin, authnURL, "screen-refused", "ref-password-123", []string{"screen-ops"})
	mtlsCreateUser(t, admin, authnURL, "screen-auditor", "aud-password-123", []string{"session-auditor"})
	adminToken, status := gatewayLogin(t, gatewayURL, "screen-admin", "root-pw-123456")
	if status != http.StatusOK {
		t.Fatalf("admin login: %d", status)
	}
	operatorToken, status := gatewayLogin(t, gatewayURL, "screen-operator", "op-password-123")
	if status != http.StatusOK {
		t.Fatalf("operator login: %d", status)
	}
	// A second operator: the upgrades are budgeted per user (ADR-0071 §10), and the refusals below
	// would spend the budget of the first one.
	refusedToken, status := gatewayLogin(t, gatewayURL, "screen-refused", "ref-password-123")
	if status != http.StatusOK {
		t.Fatalf("second operator login: %d", status)
	}
	auditorToken, status := gatewayLogin(t, gatewayURL, "screen-auditor", "aud-password-123")
	if status != http.StatusOK {
		t.Fatalf("auditor login: %d", status)
	}
	for _, pol := range []struct{ name, role, resource string }{
		{"screen-vault-admins", "vault-admin", "vault:account-admin:*"},
		{"screen-operators", "screen-ops", "vault:account:*"},
		{"screen-auditors", "session-auditor", "recording:session:*"},
	} {
		if status := gatewayCreatePolicy(t, gatewayURL, adminToken, pol.name, pol.role, pol.resource, "allow", "ignored"); status != http.StatusCreated {
			t.Fatalf("policy %s: %d", pol.name, status)
		}
	}

	api := screenAPI{t: t, url: gatewayURL}
	onboard := func(t *testing.T, id, address, user, secret string, pin *pinnedTarget) {
		t.Helper()
		api := api.in(t)
		status, raw := api.call(adminToken, http.MethodPost, "/vault/accounts", map[string]any{
			"id": id, "name": id, "username": user, "targetHost": address, "protocol": "vnc", "rotationPolicy": "manual", "initialSecret": []byte(secret),
		})
		if status != http.StatusCreated {
			t.Fatalf("onboarding %s: %d %s", id, status, raw)
		}
		if pin != nil {
			status, raw := api.call(adminToken, http.MethodPut, "/vault/accounts/"+id+"/tls-pin", map[string]any{"tlsCertificateSha256": pin.fingerprint, "targetDomain": pin.domain})
			if status != http.StatusOK {
				t.Fatalf("pinning %s: %d %s", id, status, raw)
			}
		}
	}
	sessionFor := func(t *testing.T, token, account string) string {
		t.Helper()
		api := api.in(t)
		status, raw := api.call(token, http.MethodPost, "/sessions", map[string]any{"targetAccountId": account, "protocol": "vnc", "justification": "ADR-0071", "durationMinutes": 10})
		if status != http.StatusCreated {
			t.Fatalf("session on %s: %d %s", account, status, raw)
		}
		return jsonField(t, raw, "id")
	}
	newSession := func(t *testing.T, account string) string {
		t.Helper()
		return sessionFor(t, operatorToken, account)
	}

	// refused opens the screen of a new session on the account and returns why it ended.
	refused := func(t *testing.T, account string) string {
		t.Helper()
		api := api.in(t)
		attach := api.connect(refusedToken, sessionFor(t, refusedToken, account))
		conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
		defer conn.Close(websocket.StatusNormalClosure, "")
		for {
			msg := readScreen(t, conn)
			if msg.kind == 3 {
				return msg.endText
			}
			if msg.kind == 1 {
				t.Fatal("the operator received a frame of a target that had to be refused")
			}
		}
	}

	journey := func(t *testing.T, account string, target *fakeRFBTarget, openConnections func() int) {
		api := api.in(t)
		id := newSession(t, account)
		attach := api.connect(operatorToken, id)
		conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
		defer conn.Close(websocket.StatusNormalClosure, "")

		hello := readScreen(t, conn)
		// VNC draws no pointer yet (ADR-0091, increment 3): the page keeps the browser's.
		if hello.kind != 2 || hello.helloProtocol != 2 || hello.helloSession != id || hello.helloFlags != 0 {
			t.Fatalf("first message: %+v", hello)
		}
		first := readFrame(t, conn)
		if _, err := png.Decode(bytes.NewReader(first.png)); err != nil {
			t.Fatalf("the frame is not a PNG: %v", err)
		}

		t.Run("the attach cookie does not work twice", func(t *testing.T) {
			second, err := tryDialScreen(gatewayURL, attach.path, attach.cookie)
			if err != nil {
				return // refused at the upgrade: as good
			}
			defer second.Close(websocket.StatusNormalClosure, "")
			msg := readScreen(t, second)
			if msg.kind != 3 || msg.endText != "ticket_invalid" {
				t.Fatalf("a replayed cookie got %+v", msg)
			}
		})

		t.Run("the keyboard and the pointer reach the target", func(t *testing.T) {
			writeScreen(t, conn, inputKey(0x61, true))
			writeScreen(t, conn, inputKey(0x61, false))
			writeScreen(t, conn, inputPointer(1, 1, 1))
			writeScreen(t, conn, inputPointer(1, 1, 0))
			writeScreen(t, conn, inputReleaseAll())
			if target != nil {
				waitUntil(t, 5*time.Second, "the key to reach the target", func() bool { return target.sawKey(0x61) })
			}
		})

		t.Run("ending the session cuts the target and the screen", func(t *testing.T) {
			api := api.in(t)
			if target != nil {
				target.change()
			}
			status, raw := api.call(operatorToken, http.MethodDelete, "/sessions/"+id, nil)
			if status/100 != 2 {
				t.Fatalf("terminate: %d %s", status, raw)
			}
			end := readUntilEnd(t, conn)
			if end.endText != "session_revoked" {
				t.Fatalf("END = %q, want session_revoked", end.endText)
			}
			waitUntil(t, 5*time.Second, "the target connection to be cut", func() bool { return openConnections() == 0 })
		})

		t.Run("what the operator saw is, to the byte, what an auditor replays", func(t *testing.T) {
			api := api.in(t)
			var segment struct {
				Complete bool `json:"complete"`
				Frames   []struct {
					FrameData string `json:"frameData"`
					Codec     string `json:"codec"`
				} `json:"frames"`
			}
			var last string
			defer func() {
				if t.Failed() {
					t.Logf("last answer of the replay: %s", last)
				}
			}()
			waitUntil(t, 10*time.Second, "the segment to be readable", func() bool {
				status, raw := api.call(auditorToken, http.MethodGet, "/sessions/"+id+"/recording/video/segments/1", nil)
				last = fmt.Sprintf("%d %s", status, raw)
				if status != http.StatusOK {
					return false
				}
				return json.Unmarshal([]byte(raw), &segment) == nil && len(segment.Frames) > 0
			})
			replayed, err := base64.StdEncoding.DecodeString(segment.Frames[0].FrameData)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(replayed, first.png) {
				t.Fatalf("replayed %d bytes differ from the %d shown", len(replayed), len(first.png))
			}
			if !segment.Complete {
				t.Fatal("the recording of an ended session is not sealed")
			}
			if store.holds(first.png) {
				t.Fatal("the object store holds the frame in clear")
			}
		})
	}

	onboard(t, "screen_good", good.address, "operator", vaultSecret, good.pin())

	// Asked for now, since a session lasts a minute at least; looked at last.
	onboard(t, "screen_lasting", lasting.address, "operator", vaultSecret, lasting.pin())
	status, raw := api.call(operatorToken, http.MethodPost, "/sessions", map[string]any{"targetAccountId": "screen_lasting", "protocol": "vnc", "justification": "ADR-0071", "durationMinutes": 1})
	if status != http.StatusCreated {
		t.Fatalf("short session: %d %s", status, raw)
	}
	shortSession := jsonField(t, raw, "id")
	shortAttach := api.connect(operatorToken, shortSession)
	shortScreen := dialScreen(t, gatewayURL, shortAttach.path, shortAttach.cookie)
	defer shortScreen.Close(websocket.StatusNormalClosure, "")
	readFrame(t, shortScreen)

	t.Run("the journey, against the fake target", func(t *testing.T) {
		before := good.authenticated()
		journey(t, "screen_good", good, good.openConnections)
		if good.authenticated() != before+1 {
			t.Fatalf("the target authenticated %d times, want one", good.authenticated()-before)
		}
		if got := good.lastPassword(); got != vaultSecret {
			t.Fatalf("the target received %q", got)
		}
	})

	if real != nil {
		// The real server cannot say what reached it; the relay in front of it can say when the
		// connection ends. What it received is proved on the fake target and by pkg/vnc.TestRealTarget.
		relay := newTCPRelay(t, real.address)
		onboard(t, "screen_real", relay.address, real.user, real.password, real.pin())
		t.Run("the journey, against a real target", func(t *testing.T) { journey(t, "screen_real", nil, relay.openConnections) })
		t.Run("a real target refuses a wrong password, and the operator is told so without detail", func(t *testing.T) {
			onboard(t, "screen_real_wrong", relay.address, real.user, wrongPasswordFor(real), real.pin())
			if end := refused(t, "screen_real_wrong"); end != "target_unreachable" {
				t.Fatalf("END = %q, want target_unreachable", end)
			}
			waitUntil(t, 5*time.Second, "the target connection to be cut", func() bool { return relay.openConnections() == 0 })
		})
	}

	t.Run("the browser never sees a ticket nor the proxy's address", func(t *testing.T) {
		api := api.in(t)
		id := newSession(t, "screen_good")
		attach := api.connect(operatorToken, id)
		for _, leak := range []string{"ticket", "proxyEndpoint", "18845"} {
			if strings.Contains(attach.body, leak) {
				t.Fatalf("the answer carries %q: %s", leak, attach.body)
			}
		}
		for _, want := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=/sessions/" + id + "/screen"} {
			if !strings.Contains(attach.setCookie, want) {
				t.Fatalf("the cookie lacks %s: %s", want, attach.setCookie)
			}
		}
		_, _ = api.call(operatorToken, http.MethodDelete, "/sessions/"+id, nil)
	})

	t.Run("the cookie of one session does not open another", func(t *testing.T) {
		api := api.in(t)
		a, b := newSession(t, "screen_good"), newSession(t, "screen_good")
		attachA := api.connect(operatorToken, a)
		conn, err := tryDialScreen(gatewayURL, "/sessions/"+b+"/screen", attachA.cookie)
		if err == nil {
			defer conn.Close(websocket.StatusNormalClosure, "")
			if msg := readScreen(t, conn); msg.kind != 3 || msg.endText != "ticket_invalid" {
				t.Fatalf("session %s attached with the cookie of %s: %+v", b, a, msg)
			}
		}
		_, _ = api.call(operatorToken, http.MethodDelete, "/sessions/"+a, nil)
		_, _ = api.call(operatorToken, http.MethodDelete, "/sessions/"+b, nil)
	})

	t.Run("a target with another certificate gets nothing of the secret", func(t *testing.T) {
		api := api.in(t)
		// The imposter answers at the account's address; its certificate chains, its pin differs.
		onboard(t, "screen_imposter", imposter.address, "operator", vaultSecret, good.pin())
		id := newSession(t, "screen_imposter")
		attach := api.connect(operatorToken, id)
		conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
		defer conn.Close(websocket.StatusNormalClosure, "")
		end := readUntilEnd(t, conn)
		if end.endText != "pin_mismatch" {
			t.Fatalf("END = %q, want pin_mismatch", end.endText)
		}
		if imposter.authenticated() != 0 || imposter.lastPassword() != "" {
			t.Fatalf("the imposter received a secret: %q", imposter.lastPassword())
		}
		waitUntil(t, 5*time.Second, "the mismatch on the record", func() bool { return audit.saw("session.tls_certificate_mismatch", id) })
	})

	// The exit criteria of increment 1, each one with the code ADR-0071 §12 gives the operator. What
	// the target received is asked of the target, not of the proxy.
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.target
			secret := tc.secret
			if secret == "" {
				secret = vaultSecret
			}
			onboard(t, tc.account, target.address, "operator", secret, target.pin())
			if end := refused(t, tc.account); end != tc.want {
				t.Fatalf("END = %q, want %s", end, tc.want)
			}
			if !tc.secretReachesTarget && (target.authenticated() != 0 || target.tlsHandshakes() != 0) {
				t.Fatalf("the target went through %d TLS handshakes and received %q", target.tlsHandshakes(), target.lastPassword())
			}
			waitUntil(t, 5*time.Second, "the target connection to be cut", func() bool { return target.openConnections() == 0 })
		})
	}

	t.Run("an account without a pin opens no session", func(t *testing.T) {
		api := api.in(t)
		onboard(t, "screen_unpinned", good.address, "operator", vaultSecret, nil)
		before := good.connections()
		status, raw := api.call(operatorToken, http.MethodPost, "/sessions", map[string]any{"targetAccountId": "screen_unpinned", "protocol": "vnc", "justification": "ADR-0071", "durationMinutes": 10})
		if status != http.StatusConflict || !strings.Contains(raw, "no pinned TLS certificate") {
			t.Fatalf("session on an unpinned account: %d %s", status, raw)
		}
		if good.connections() != before {
			t.Fatal("the target was contacted")
		}
	})

	t.Run("the client does not choose the protocol", func(t *testing.T) {
		api := api.in(t)
		status, raw := api.call(operatorToken, http.MethodPost, "/sessions", map[string]any{"targetAccountId": "screen_good", "protocol": "ssh", "justification": "ADR-0071", "durationMinutes": 10})
		if status != http.StatusConflict {
			t.Fatalf("ssh asked on a VNC account: %d %s", status, raw)
		}
	})

	t.Run("the deadline of the session cuts the screen, says why, and is on the record", func(t *testing.T) {
		end := readUntilEndWithin(t, shortScreen, 90*time.Second)
		if end.endText != "session_expired" {
			t.Fatalf("END = %q, want session_expired", end.endText)
		}
		waitUntil(t, 5*time.Second, "the expiry on the record", func() bool {
			return audit.saw("session.expire", shortSession) && audit.saw("session.terminate", shortSession)
		})
		waitUntil(t, 5*time.Second, "the expired session's target to be cut", func() bool { return lasting.openConnections() == 0 })
	})

	t.Run("no secret of a target is in the output of any service", func(t *testing.T) {
		secrets := []string{vaultSecret, "not-what-the-target-expects"}
		if real != nil {
			secrets = append(secrets, real.password, wrongPasswordFor(real))
		}
		for name, output := range outputs {
			for _, secret := range secrets {
				if strings.Contains(output.String(), secret) {
					t.Errorf("%s logged the secret %q", name, secret)
				}
			}
		}
	})

	// Last: it stops the recorder.
	t.Run("a recorder that is down refuses the session before the target is contacted", func(t *testing.T) {
		api := api.in(t)
		id := newSession(t, "screen_good")
		before := good.connections()
		_ = video.cmd.Process.Kill()
		_, _ = video.cmd.Process.Wait()
		status, raw := api.call(operatorToken, http.MethodPost, "/sessions/"+id+"/connect", nil)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("connect without a recorder: %d %s", status, raw)
		}
		if good.connections() != before {
			t.Fatal("the target was contacted without a recorder")
		}
		waitUntil(t, 5*time.Second, "the refusal on the record", func() bool { return audit.saw("session.recording_unavailable", id) })
	})
}

// -- the public API, as the Admin UI uses it ------------------------------------------------------

type screenAPI struct {
	t   *testing.T
	url string
}

// in is the same API, failing the subtest that uses it.
func (a screenAPI) in(t *testing.T) screenAPI {
	a.t = t
	return a
}

func (a screenAPI) do(token, method, path string, body any) (*http.Response, string) {
	a.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			a.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.url+path, reader)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

func (a screenAPI) call(token, method, path string, body any) (int, string) {
	a.t.Helper()
	resp, raw := a.do(token, method, path, body)
	return resp.StatusCode, raw
}

type screenAttachment struct{ path, cookie, setCookie, body string }

func (a screenAPI) connect(token, sessionID string) screenAttachment {
	a.t.Helper()
	resp, raw := a.do(token, http.MethodPost, "/sessions/"+sessionID+"/connect", nil)
	if resp.StatusCode != http.StatusOK {
		a.t.Fatalf("connect: %d %s", resp.StatusCode, raw)
	}
	setCookie := resp.Header.Get("Set-Cookie")
	value := regexp.MustCompile(`ob_screen_attach=([^;]+)`).FindStringSubmatch(setCookie)
	if value == nil {
		a.t.Fatalf("no attach cookie: %q", setCookie)
	}
	return screenAttachment{path: jsonField(a.t, raw, "attach"), cookie: value[1], setCookie: setCookie, body: raw}
}

// -- the screen, as a browser opens it ------------------------------------------------------------

func tryDialScreen(gatewayURL, path, cookie string) (*websocket.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	headers := http.Header{"Cookie": {"ob_screen_attach=" + cookie}, "Origin": {gatewayURL}}
	url := "ws" + strings.TrimPrefix(gatewayURL, "http") + path
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: headers, Subprotocols: []string{"openbastion.screen.v1"}})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(8 << 20)
	return conn, nil
}

func dialScreen(t *testing.T, gatewayURL, path, cookie string) *websocket.Conn {
	t.Helper()
	conn, err := tryDialScreen(gatewayURL, path, cookie)
	if err != nil {
		t.Fatalf("opening the screen: %v", err)
	}
	return conn
}

type screenMessage struct {
	kind          byte
	sequence      uint64
	png           []byte
	helloProtocol byte
	helloFlags    byte // bit 0: the pointer is in the frames (ADR-0091)
	helloSession  string
	endText       string
}

func readScreen(t *testing.T, conn *websocket.Conn) screenMessage {
	t.Helper()
	return readScreenWithin(t, conn, 20*time.Second)
}

func readScreenWithin(t *testing.T, conn *websocket.Conn, limit time.Duration) screenMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("reading the screen: %v", err)
	}
	if typ != websocket.MessageBinary || len(data) < 32 || data[0] != 1 {
		t.Fatalf("not a screen message: type %v, %d bytes", typ, len(data))
	}
	m := screenMessage{kind: data[1], sequence: binary.BigEndian.Uint64(data[4:12])}
	payload := data[32:]
	switch m.kind {
	case 1:
		m.png = payload
	case 2:
		m.helloProtocol, m.helloFlags = payload[0], payload[1]
		m.helloSession = string(payload[14:])
	case 3:
		m.endText = string(payload[4:])
	}
	return m
}

func readFrame(t *testing.T, conn *websocket.Conn) screenMessage {
	t.Helper()
	for {
		m := readScreen(t, conn)
		if m.kind == 3 {
			t.Fatalf("the session ended before a frame: %q", m.endText)
		}
		if m.kind == 1 {
			return m
		}
	}
}

func readUntilEnd(t *testing.T, conn *websocket.Conn) screenMessage {
	t.Helper()
	for {
		if m := readScreen(t, conn); m.kind == 3 {
			return m
		}
	}
}

func readUntilEndWithin(t *testing.T, conn *websocket.Conn, limit time.Duration) screenMessage {
	t.Helper()
	for {
		if m := readScreenWithin(t, conn, limit); m.kind == 3 {
			return m
		}
	}
}

func writeScreen(t *testing.T, conn *websocket.Conn, message []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, message); err != nil {
		t.Fatalf("writing input: %v", err)
	}
}

func inputKey(keysym uint32, pressed bool) []byte {
	m := make([]byte, 16)
	m[0], m[1] = 1, 1
	if pressed {
		m[2] = 1
	}
	binary.BigEndian.PutUint32(m[4:8], keysym)
	return m
}

func inputPointer(x, y uint16, buttons byte) []byte {
	m := make([]byte, 16)
	m[0], m[1] = 1, 2
	binary.BigEndian.PutUint16(m[10:12], x)
	binary.BigEndian.PutUint16(m[12:14], y)
	m[14] = buttons
	return m
}

func inputReleaseAll() []byte {
	m := make([]byte, 16)
	m[0], m[1] = 1, 3
	return m
}

// -- targets --------------------------------------------------------------------------------------

type pinnedTarget struct{ fingerprint, domain string }

type realVNCTarget struct {
	address, user, password string
	certPEM                 []byte
	fingerprint, domain     string
}

func (r *realVNCTarget) pin() *pinnedTarget {
	return &pinnedTarget{fingerprint: r.fingerprint, domain: r.domain}
}

func realVNCTargetFromEnv(t *testing.T) *realVNCTarget {
	t.Helper()
	address := os.Getenv("OPENBASTION_VNC_TARGET")
	if address == "" {
		return nil
	}
	certPEM, err := os.ReadFile(os.Getenv("OPENBASTION_VNC_CA_FILE"))
	if err != nil {
		t.Fatalf("OPENBASTION_VNC_CA_FILE: %v", err)
	}
	return &realVNCTarget{
		address: address, user: os.Getenv("OPENBASTION_VNC_USER"), password: os.Getenv("OPENBASTION_VNC_PASSWORD"),
		certPEM: certPEM, fingerprint: os.Getenv("OPENBASTION_VNC_PIN"), domain: os.Getenv("OPENBASTION_VNC_SERVER_NAME"),
	}
}

// wrongPasswordFor is not the target's password, in a length its security type can carry.
func wrongPasswordFor(r *realVNCTarget) string {
	if len(r.password) <= 8 {
		return "wrongpw1"
	}
	return r.password + "-wrong"
}

// fakeRFBBehavior is what a target does instead of what a conforming server does.
type fakeRFBBehavior struct {
	version       string // RFB 3.8 if empty
	securityTypes []byte // VeNCrypt alone if empty
	subtype       uint32 // X509Plain if zero
	firstUpdate   []byte // answered to the first request instead of a valid update
	listen        string // the loopback if empty; containers reach a target on the host elsewhere
}

// rfbUpdate is a FramebufferUpdate that announces one rectangle, and carries no pixel of it.
func rfbUpdate(x, y, width, height uint16, encoding int32) []byte {
	m := make([]byte, 16)
	m[3] = 1
	binary.BigEndian.PutUint16(m[4:6], x)
	binary.BigEndian.PutUint16(m[6:8], y)
	binary.BigEndian.PutUint16(m[8:10], width)
	binary.BigEndian.PutUint16(m[10:12], height)
	binary.BigEndian.PutUint32(m[12:16], uint32(encoding))
	return m
}

// tcpRelay stands in front of a target that cannot testify, and says when its connections end.
type tcpRelay struct {
	address string
	mu      sync.Mutex
	open    int
}

func (r *tcpRelay) openConnections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.open
}

func newTCPRelay(t *testing.T, upstream string) *tcpRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	relay := &tcpRelay{address: listener.Addr().String()}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			relay.mu.Lock()
			relay.open++
			relay.mu.Unlock()
			go func() {
				defer func() {
					conn.Close()
					relay.mu.Lock()
					relay.open--
					relay.mu.Unlock()
				}()
				target, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer target.Close()
				// Either side ending ends the connection: that is the event being witnessed.
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(target, conn); done <- struct{}{} }()
				go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return relay
}

// fakeRFBTarget speaks RFB 3.8 and VeNCrypt X509Plain as a real server does, and remembers what
// reached it: the point of a fake is what it can testify to.
type fakeRFBTarget struct {
	t        *testing.T
	address  string
	domain   string
	certPEM  []byte
	cert     tls.Certificate
	password string
	behavior fakeRFBBehavior

	mu       sync.Mutex
	conns    int
	open     int
	tlsDone  int
	auths    int
	lastPass string
	keys     map[uint32]bool
	updates  chan struct{}
}

func newFakeRFBTarget(t *testing.T, domain, password string, behavior ...fakeRFBBehavior) *fakeRFBTarget {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listen := "127.0.0.1:0"
	if len(behavior) > 0 && behavior[0].listen != "" {
		listen = behavior[0].listen
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	target := &fakeRFBTarget{
		t: t, address: listener.Addr().String(), domain: domain, password: password,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		keys:    map[uint32]bool{}, updates: make(chan struct{}, 16),
	}
	if len(behavior) > 0 {
		target.behavior = behavior[0]
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			target.mu.Lock()
			target.conns++
			target.open++
			target.mu.Unlock()
			go func() {
				defer func() {
					conn.Close()
					target.mu.Lock()
					target.open--
					target.mu.Unlock()
				}()
				_ = target.serve(conn)
			}()
		}
	}()
	return target
}

func (f *fakeRFBTarget) pin() *pinnedTarget {
	sum := sha256.Sum256(f.cert.Certificate[0])
	return &pinnedTarget{fingerprint: hex.EncodeToString(sum[:]), domain: f.domain}
}

func (f *fakeRFBTarget) connections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

func (f *fakeRFBTarget) openConnections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

func (f *fakeRFBTarget) authenticated() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auths
}

func (f *fakeRFBTarget) tlsHandshakes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tlsDone
}

func (f *fakeRFBTarget) lastPassword() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastPass
}

func (f *fakeRFBTarget) sawKey(keysym uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[keysym]
}

// change makes the desktop change, as a real one does: the next incremental request is answered.
func (f *fakeRFBTarget) change() {
	select {
	case f.updates <- struct{}{}:
	default:
	}
}

func (f *fakeRFBTarget) serve(conn net.Conn) error {
	version := f.behavior.version
	if version == "" {
		version = "RFB 003.008\n"
	}
	if _, err := conn.Write([]byte(version)); err != nil {
		return err
	}
	var answered [12]byte
	if _, err := io.ReadFull(conn, answered[:]); err != nil {
		return err
	}
	securityTypes := f.behavior.securityTypes
	if len(securityTypes) == 0 {
		securityTypes = []byte{19} // VeNCrypt only
	}
	if _, err := conn.Write(append([]byte{byte(len(securityTypes))}, securityTypes...)); err != nil {
		return err
	}
	var choice [1]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0, 2}); err != nil {
		return err
	}
	var venVersion [2]byte
	if _, err := io.ReadFull(conn, venVersion[:]); err != nil {
		return err
	}
	offered := f.behavior.subtype
	if offered == 0 {
		offered = 262 // X509Plain
	}
	agreed := []byte{0, 1, 0, 0, 0, 0} // agreed; one subtype
	binary.BigEndian.PutUint32(agreed[2:], offered)
	if _, err := conn.Write(agreed); err != nil {
		return err
	}
	var subtype [4]byte
	if _, err := io.ReadFull(conn, subtype[:]); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}
	secured := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err != nil {
		return err // what an imposter gets: the client hung up on its certificate
	}
	f.mu.Lock()
	f.tlsDone++
	f.mu.Unlock()
	var lengths [8]byte
	if _, err := io.ReadFull(secured, lengths[:]); err != nil {
		return err
	}
	user := make([]byte, binary.BigEndian.Uint32(lengths[0:4]))
	pass := make([]byte, binary.BigEndian.Uint32(lengths[4:8]))
	if _, err := io.ReadFull(secured, user); err != nil {
		return err
	}
	if _, err := io.ReadFull(secured, pass); err != nil {
		return err
	}
	f.mu.Lock()
	f.auths++
	f.lastPass = string(pass)
	f.mu.Unlock()
	if string(pass) != f.password {
		reason := "bad password"
		var m bytes.Buffer
		_ = binary.Write(&m, binary.BigEndian, uint32(1))
		_ = binary.Write(&m, binary.BigEndian, uint32(len(reason)))
		m.WriteString(reason)
		_, _ = secured.Write(m.Bytes())
		return nil
	}
	if _, err := secured.Write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}
	var shared [1]byte
	if _, err := io.ReadFull(secured, shared[:]); err != nil {
		return err
	}
	const width, height = 8, 6
	var init [24]byte
	binary.BigEndian.PutUint16(init[0:2], width)
	binary.BigEndian.PutUint16(init[2:4], height)
	init[4], init[5], init[7] = 32, 24, 1
	binary.BigEndian.PutUint16(init[8:10], 255)
	binary.BigEndian.PutUint16(init[10:12], 255)
	binary.BigEndian.PutUint16(init[12:14], 255)
	init[14], init[15] = 16, 8
	if _, err := secured.Write(init[:]); err != nil {
		return err
	}

	writes := make(chan struct{}, 16)
	shade := byte(0)
	sendRaw := func() error {
		if f.behavior.firstUpdate != nil {
			_, err := secured.Write(f.behavior.firstUpdate)
			return err
		}
		shade += 40
		var m bytes.Buffer
		m.Write([]byte{0, 0, 0, 1})
		var rect [12]byte
		binary.BigEndian.PutUint16(rect[4:6], width)
		binary.BigEndian.PutUint16(rect[6:8], height)
		m.Write(rect[:])
		m.Write(bytes.Repeat([]byte{shade, 20, 30, 0}, width*height))
		_, err := secured.Write(m.Bytes())
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-f.updates:
				select {
				case writes <- struct{}{}:
				default:
				}
			case <-done:
				return
			}
		}
	}()
	// Client messages arrive on one goroutine; updates are answered on another, as a server may.
	requests := make(chan bool, 64)
	readErr := make(chan error, 1)
	go func() { readErr <- f.readClient(secured, requests) }()
	full := false
	pendingIncremental := false
	for {
		select {
		case err := <-readErr:
			return err
		case incremental := <-requests:
			if !incremental {
				full = true
			} else {
				pendingIncremental = true
			}
		case <-writes:
			if pendingIncremental {
				pendingIncremental = false
				if err := sendRaw(); err != nil {
					return err
				}
			}
		}
		if full {
			full = false
			if err := sendRaw(); err != nil {
				return err
			}
		}
	}
}

func (f *fakeRFBTarget) readClient(conn io.Reader, requests chan<- bool) error {
	for {
		var kind [1]byte
		if _, err := io.ReadFull(conn, kind[:]); err != nil {
			return err
		}
		switch kind[0] {
		case 0:
			var rest [19]byte
			if _, err := io.ReadFull(conn, rest[:]); err != nil {
				return err
			}
		case 2:
			var hdr [3]byte
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return err
			}
			encodings := make([]byte, int(binary.BigEndian.Uint16(hdr[1:]))*4)
			if _, err := io.ReadFull(conn, encodings); err != nil {
				return err
			}
		case 3:
			var rest [9]byte
			if _, err := io.ReadFull(conn, rest[:]); err != nil {
				return err
			}
			requests <- rest[0] == 1
		case 4:
			var rest [7]byte
			if _, err := io.ReadFull(conn, rest[:]); err != nil {
				return err
			}
			if rest[0] == 1 {
				f.mu.Lock()
				f.keys[binary.BigEndian.Uint32(rest[3:])] = true
				f.mu.Unlock()
			}
		case 5:
			var rest [5]byte
			if _, err := io.ReadFull(conn, rest[:]); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected client message %d", kind[0])
		}
	}
}

// -- what the proxy tells the audit, on its way to the real Audit Service --------------------------

type screenAuditSpy struct {
	URL    string
	mu     sync.Mutex
	events []string
}

func (s *screenAuditSpy) saw(action, sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		if strings.Contains(event, `"`+action+`"`) && strings.Contains(event, sessionID) {
			return true
		}
	}
	return false
}

// startScreenAuditSpy serves under the Audit Service's own certificate, since the proxy accepts no
// other, and forwards under the proxy's: the real audit chain stays complete.
func startScreenAuditSpy(t *testing.T, p *testPKI, upstream string) *screenAuditSpy {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(pki.CertFile(p.dir, mtls.AuditService), pki.KeyFile(p.dir, mtls.AuditService))
	if err != nil {
		t.Fatal(err)
	}
	forward := p.clientAs(t, mtls.RDPVNCProxy)
	spy := &screenAuditSpy{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		spy.mu.Lock()
		spy.events = append(spy.events, string(body))
		spy.mu.Unlock()
		req, err := http.NewRequest(r.Method, upstream+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := forward.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.roots(), MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	spy.URL = srv.URL
	return spy
}

// -- an S3 endpoint of the size the Video Recorder needs -------------------------------------------

type fakeObjectStore struct {
	URL     string
	mu      sync.Mutex
	objects map[string][]byte
}

func (s *fakeObjectStore) holds(plaintext []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, object := range s.objects {
		if bytes.Contains(object, plaintext) {
			return true
		}
	}
	return false
}

func newFakeObjectStore(t *testing.T) *fakeObjectStore {
	t.Helper()
	store := &fakeObjectStore{objects: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		isBucket := !strings.Contains(strings.TrimSuffix(key, "/"), "/")
		switch {
		case r.URL.Query().Has("location"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
		case isBucket:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
				body = decodeAWSChunked(t, body)
			}
			store.mu.Lock()
			store.objects[key] = body
			store.mu.Unlock()
			w.Header().Set("ETag", `"`+hex.EncodeToString(sha256.New().Sum(body)[:16])+`"`)
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			store.mu.Lock()
			body, ok := store.objects[key]
			store.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("ETag", `"fake"`)
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Accept-Ranges", "bytes")
			http.ServeContent(w, r, "", time.Now(), bytes.NewReader(body))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	store.URL = srv.URL
	return store
}

// decodeAWSChunked undoes the framing a signed S3 client puts around a body sent over plain HTTP:
// "<hex size>;chunk-signature=…\r\n<bytes>\r\n", until a chunk of size 0.
func decodeAWSChunked(t *testing.T, framed []byte) []byte {
	t.Helper()
	var out []byte
	for {
		line, rest, ok := bytes.Cut(framed, []byte("\r\n"))
		if !ok {
			t.Fatalf("aws-chunked: no chunk header in %d bytes", len(framed))
		}
		sizeField, _, _ := bytes.Cut(line, []byte(";"))
		size, err := strconv.ParseUint(string(sizeField), 16, 32)
		if err != nil || uint64(len(rest)) < size {
			t.Fatalf("aws-chunked: chunk header %q over %d bytes", line, len(rest))
		}
		if size == 0 {
			return out
		}
		out = append(out, rest[:size]...)
		framed = bytes.TrimPrefix(rest[size:], []byte("\r\n"))
	}
}
