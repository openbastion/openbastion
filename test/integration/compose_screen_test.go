// ADR-0071 on the real installation: the images, the networks and the secrets of
// deploy/docker-compose, with its profiles recording and rdp-vnc. screen_flow_test.go proves the
// behaviours on processes; this one proves that what an administrator deploys can do it.
//
// The target stays on the host, where the test can ask it what it received. The Video Recorder uses
// a local key, through an override: Transit and its renewal are proved by transit_flow_test.go, and
// a deployment without one refuses to start.
package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestCompose_AVNCSessionOnTheRealStackWithItsProfiles(t *testing.T) {
	if os.Getenv("COMPOSE_TEST") == "" {
		t.Skip("COMPOSE_TEST not set — skipping the docker-compose test (it builds and starts the whole stack)")
	}
	root := repoRoot(t)
	dir := t.TempDir()
	// A new installation: init.sh has drawn the recording credentials with the others.
	envFile := filepath.Join(dir, ".env")
	if out, err := exec.Command("sh", filepath.Join(root, "deploy/docker-compose/init.sh"), envFile).CombinedOutput(); err != nil {
		t.Fatalf("init.sh: %v\n%s", err, out)
	}

	const secret = "the-vault-secret-of-the-target"
	target := newFakeRFBTarget(t, "vnc-target.test", secret, fakeRFBBehavior{listen: "0.0.0.0:0"})
	_, targetPort, err := net.SplitHostPort(target.address)
	if err != nil {
		t.Fatal(err)
	}
	// The service runs as an unprivileged user: a bind-mounted secret keeps the mode of its file.
	caFile := filepath.Join(dir, "screen-target-ca.pem")
	if err := os.WriteFile(caFile, target.certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(dir, "override.yml")
	if err := os.WriteFile(override, []byte("services:\n  video-recorder:\n    environment:\n      VIDEO_RECORDER_KMS_KEY_HEX: "+strings.Repeat("cd", 32)+"\n      TRANSIT_TOKEN_FILE: \"\"\n      TRANSIT_CA_FILE: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const project, gatewayPort, sshPort = "obcompose-screen", "18981", "18923"
	compose := func(args ...string) *exec.Cmd {
		cmd := exec.Command("docker", append([]string{"compose", "-f", filepath.Join(root, "deploy/docker-compose/docker-compose.yml"), "-f", override,
			"--env-file", envFile, "-p", project,
			"--profile", "recording", "--profile", "rdp-vnc"}, args...)...)
		cmd.Env = append(os.Environ(), "OB_GATEWAY_PORT="+gatewayPort, "OB_SSH_PORT="+sshPort, "SCREEN_TARGET_CA_FILE="+caFile)
		return cmd
	}
	run := func(t *testing.T, stdin string, args ...string) string {
		t.Helper()
		cmd := compose(args...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := compose("logs", "--no-color", "--tail", "40").CombinedOutput()
			t.Logf("stack logs:\n%s", out)
		}
		_, _ = compose("--profile", "cli", "down", "-v", "--remove-orphans").CombinedOutput()
	})
	run(t, "", "up", "-d", "--build", "--wait", "--wait-timeout", "240")
	gatewayURL := "http://127.0.0.1:" + gatewayPort
	waitUntil(t, 60*time.Second, "the Gateway to answer", func() bool {
		resp, err := http.Get(gatewayURL + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	// From a container, the host is the gateway of its network.
	raw, err := exec.Command("docker", "network", "inspect", project+"_internal", "--format", "{{(index .IPAM.Config 0).Gateway}}").CombinedOutput()
	if err != nil {
		t.Fatalf("docker network inspect: %v\n%s", err, raw)
	}
	targetAddress := net.JoinHostPort(strings.TrimSpace(string(raw)), targetPort)

	t.Run("the object store's configuration job runs again, with its one capability", func(t *testing.T) {
		run(t, "", "run", "--rm", "seaweedfs-config")
	})

	t.Run("neither the screen proxy nor the object store is published", func(t *testing.T) {
		for _, service := range []string{"rdp-vnc-proxy", "video-recorder", "seaweedfs"} {
			if ports := strings.TrimSpace(run(t, "", "ps", "--format", "{{.Publishers}}", service)); strings.Contains(ports, "127.0.0.1") || strings.Contains(ports, "0.0.0.0") {
				t.Fatalf("%s is published: %s", service, ports)
			}
		}
	})

	cliUser := func(name, password, roles string) {
		t.Helper()
		out := run(t, password+"\n", "run", "--rm", "-T", "cli", "user", "create",
			"-authn", "https://authentication:8086", "-username", name, "-roles", roles)
		if !strings.Contains(out, "user "+name+" created") {
			t.Fatalf("cli user create %s: %s", name, out)
		}
	}
	cliUser("root-admin", "root-pw-123456", "platform-admin,vault-admin")
	cliUser("operator", "op-password-123", "screen-ops")
	cliUser("auditor", "aud-password-123", "session-auditor")
	adminToken, status := gatewayLogin(t, gatewayURL, "root-admin", "root-pw-123456")
	if status != http.StatusOK {
		t.Fatalf("admin login: %d", status)
	}
	operatorToken, _ := gatewayLogin(t, gatewayURL, "operator", "op-password-123")
	auditorToken, _ := gatewayLogin(t, gatewayURL, "auditor", "aud-password-123")
	for _, pol := range []struct{ name, role, resource string }{
		{"vault-admins", "vault-admin", "vault:account-admin:*"},
		{"operators", "screen-ops", "vault:account:*"},
		{"auditors", "session-auditor", "recording:session:*"},
	} {
		if status := gatewayCreatePolicy(t, gatewayURL, adminToken, pol.name, pol.role, pol.resource, "allow", "ignored"); status != http.StatusCreated {
			t.Fatalf("policy %s: %d", pol.name, status)
		}
	}

	api := screenAPI{t: t, url: gatewayURL}
	const account = "acc_screen"
	if status, body := api.call(adminToken, http.MethodPost, "/vault/accounts", map[string]any{
		"id": account, "name": account, "username": "operator", "targetHost": targetAddress, "protocol": "vnc", "rotationPolicy": "manual", "initialSecret": []byte(secret),
	}); status != http.StatusCreated {
		t.Fatalf("onboarding: %d %s", status, body)
	}
	pin := target.pin()
	if status, body := api.call(adminToken, http.MethodPut, "/vault/accounts/"+account+"/tls-pin", map[string]any{"tlsCertificateSha256": pin.fingerprint, "targetDomain": pin.domain}); status != http.StatusOK {
		t.Fatalf("pinning: %d %s", status, body)
	}
	status, body := api.call(operatorToken, http.MethodPost, "/sessions", map[string]any{"targetAccountId": account, "protocol": "vnc", "justification": "ADR-0071", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("session: %d %s", status, body)
	}
	session := jsonField(t, body, "id")

	attach := api.connect(operatorToken, session)
	conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
	defer conn.Close(websocket.StatusNormalClosure, "")
	if hello := readScreen(t, conn); hello.kind != 2 || hello.helloProtocol != 2 || hello.helloSession != session {
		t.Fatalf("first message: %+v", hello)
	}
	first := readFrame(t, conn)
	if _, err := png.Decode(bytes.NewReader(first.png)); err != nil {
		t.Fatalf("the frame is not a PNG: %v", err)
	}
	if got := target.lastPassword(); got != secret {
		t.Fatalf("the target received %q", got)
	}

	writeScreen(t, conn, inputKey(0x61, true))
	writeScreen(t, conn, inputKey(0x61, false))
	waitUntil(t, 10*time.Second, "the key to reach the target", func() bool { return target.sawKey(0x61) })

	target.change()
	if status, body := api.call(operatorToken, http.MethodDelete, "/sessions/"+session, nil); status/100 != 2 {
		t.Fatalf("terminate: %d %s", status, body)
	}
	if end := readUntilEnd(t, conn); end.endText != "session_revoked" {
		t.Fatalf("END = %q, want session_revoked", end.endText)
	}
	waitUntil(t, 10*time.Second, "the target connection to be cut", func() bool { return target.openConnections() == 0 })

	t.Run("what the operator saw is what an auditor replays, sealed in the real object store", func(t *testing.T) {
		var segment struct {
			Complete bool `json:"complete"`
			Frames   []struct {
				FrameData string `json:"frameData"`
			} `json:"frames"`
		}
		var last string
		waitUntil(t, 20*time.Second, "the segment to be readable", func() bool {
			status, raw := api.in(t).call(auditorToken, http.MethodGet, "/sessions/"+session+"/recording/video/segments/1", nil)
			last = raw
			return status == http.StatusOK && json.Unmarshal([]byte(raw), &segment) == nil && len(segment.Frames) > 0
		})
		replayed, err := base64.StdEncoding.DecodeString(segment.Frames[0].FrameData)
		if err != nil {
			t.Fatalf("%v: %s", err, last)
		}
		if !bytes.Equal(replayed, first.png) {
			t.Fatalf("replayed %d bytes differ from the %d shown", len(replayed), len(first.png))
		}
		if !segment.Complete {
			t.Fatal("the recording of an ended session is not sealed")
		}
	})

	t.Run("the audit chain verifies, by the CLI", func(t *testing.T) {
		out := run(t, "", "run", "--rm", "-T", "cli", "audit", "verify-chain", "-audit", "https://audit-service:8082")
		if !strings.Contains(out, "the audit chain verifies") {
			t.Fatalf("cli audit verify-chain: %s", out)
		}
	})

	t.Run("with the recorder stopped, the stack refuses before the target is contacted", func(t *testing.T) {
		api := api.in(t)
		status, body := api.call(operatorToken, http.MethodPost, "/sessions", map[string]any{"targetAccountId": account, "protocol": "vnc", "justification": "ADR-0071", "durationMinutes": 10})
		if status != http.StatusCreated {
			t.Fatalf("session: %d %s", status, body)
		}
		id := jsonField(t, body, "id")
		before := target.connections()
		run(t, "", "stop", "video-recorder")
		if status, body := api.call(operatorToken, http.MethodPost, "/sessions/"+id+"/connect", nil); status != http.StatusServiceUnavailable {
			t.Fatalf("connect without a recorder: %d %s", status, body)
		}
		if target.connections() != before {
			t.Fatal("the target was contacted without a recorder")
		}
	})

	t.Run("no secret of the target is in any log of the stack", func(t *testing.T) {
		if logs := run(t, "", "logs", "--no-color"); strings.Contains(logs, secret) {
			t.Fatal("the target's secret is in the logs of the stack")
		}
	})
}
