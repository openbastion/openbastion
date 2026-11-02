package integration_test

// The MVP's third exit criterion (docs/roadmap.md §2) — a reproducible docker-compose deployment —
// as a test (ADR-0033). It builds the real image, starts the real stack (eight services
// under mutual TLS, one database per service), creates the first users with the CLI, and goes
// through the journey on the published ports only: policies, an account, a session, an SSH
// connection through the proxy, the commands read back by an auditor, the audit chain
// verified. Then the claims that make it a deployment and not a demo: the target's secret is
// in no log of the stack, and after a restart everything is still there.
//
// It needs Docker and minutes: it runs only with COMPOSE_TEST=1.

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompose_TheMVPJourneyOnARealDockerComposeStack(t *testing.T) {
	if os.Getenv("COMPOSE_TEST") == "" {
		t.Skip("COMPOSE_TEST not set — skipping the docker-compose test (it builds and starts the whole stack)")
	}
	root := repoRoot(t)
	envFile := filepath.Join(t.TempDir(), ".env")
	init := exec.Command("sh", filepath.Join(root, "deploy/docker-compose/init.sh"), envFile)
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init.sh: %v\n%s", err, out)
	}
	if out, err := exec.Command("sh", filepath.Join(root, "deploy/docker-compose/init.sh"), envFile).CombinedOutput(); err == nil ||
		!strings.Contains(string(out), "refusing to overwrite") {
		t.Fatalf("init.sh over an existing file: %v\n%s", err, out)
	}
	secrets := readEnvFile(t, envFile)

	const gatewayPort, sshPort = "18980", "18922"
	compose := func(args ...string) *exec.Cmd {
		cmd := exec.Command("docker", append([]string{"compose", "-f", filepath.Join(root, "deploy/docker-compose/docker-compose.yml"),
			"--env-file", envFile, "-p", "obcompose-test", "--profile", "demo"}, args...)...)
		cmd.Env = append(os.Environ(), "OB_GATEWAY_PORT="+gatewayPort, "OB_SSH_PORT="+sshPort)
		return cmd
	}
	run := func(stdin string, args ...string) string {
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
	run("", "up", "-d", "--build", "--wait", "--wait-timeout", "180")
	gatewayURL := "http://127.0.0.1:" + gatewayPort
	waitUntil(t, 60*time.Second, "the Gateway to answer", func() bool {
		resp, err := http.Get(gatewayURL + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	t.Run("the Admin UI is served by the Gateway, under its strict policy", func(t *testing.T) {
		resp, err := http.Get(gatewayURL + "/ui/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `src="/ui/assets/`) {
			t.Fatalf("/ui/: %d %.200s", resp.StatusCode, body)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe") {
			t.Fatalf("/ui/ policy: %q", csp)
		}
		if resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("/ui/ without Referrer-Policy: no-referrer")
		}
	})

	t.Run("only the Gateway and the SSH proxy are published", func(t *testing.T) {
		out := run("", "ps", "-a", "--format", "{{.Service}}{{range .Publishers}} {{.URL}}:{{.PublishedPort}}{{end}}")
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			for _, pub := range fields[1:] {
				if strings.HasSuffix(pub, ":0") {
					continue // exposed to the internal network, not published
				}
				want := map[string]string{"api-gateway": "127.0.0.1:" + gatewayPort, "ssh-proxy": "127.0.0.1:" + sshPort}[fields[0]]
				if pub != want {
					t.Fatalf("%s publishes %s; only the Gateway and the SSH proxy publish, on 127.0.0.1", fields[0], pub)
				}
			}
		}
	})

	t.Run("each service holds its own key and the authority's certificate, never the authority's key", func(t *testing.T) {
		out := run("", "run", "--rm", "--no-deps", "-T", "--entrypoint", "sh", "-v", "obcompose-test_pki:/look:ro", "pki",
			"-c", "cd /look && find . -type f | sort")
		want := ""
		for _, svc := range []string{"admin-cli", "api-gateway", "audit-service", "authentication", "authorization", "command-recorder", "password-vault", "seaweedfs", "session-broker", "ssh-proxy", "video-recorder"} {
			want += "./" + svc + "/ca.pem\n./" + svc + "/cert.pem\n./" + svc + "/key.pem\n"
		}
		if got := out[strings.Index(out, "./"):]; got != want {
			t.Fatalf("the volume mounted by the services holds:\n%s\nwant exactly each service's own three files:\n%s", got, want)
		}
	})

	t.Run("a service's role cannot open another service's database", func(t *testing.T) {
		psql := func(role, password, db string) error {
			cmd := compose("exec", "-T", "-e", "PGPASSWORD="+password, "postgres", "psql", "-h", "127.0.0.1", "-U", role, "-d", db, "-c", "SELECT 1")
			return cmd.Run()
		}
		if err := psql("session_broker", secrets["PG_PASSWORD_SESSION_BROKER"], "session_broker"); err != nil {
			t.Fatalf("the Broker's role cannot open its own database: %v", err)
		}
		for _, db := range []string{"authentication", "password_vault", "audit_service", "command_recorder", "authorization"} {
			if err := psql("session_broker", secrets["PG_PASSWORD_SESSION_BROKER"], db); err == nil {
				t.Fatalf("the Broker's role opens the %s database", db)
			}
		}
	})

	t.Run("there is no demonstration account", func(t *testing.T) {
		if _, status := gatewayLogin(t, gatewayURL, "demo-dba", "demo-password"); status == http.StatusOK {
			t.Fatal("demo-dba / demo-password logs in")
		}
	})

	// The first users exist only through the CLI, under the admin-cli identity.
	cliUser := func(name, password, roles string) {
		t.Helper()
		out := run(password+"\n", "run", "--rm", "-T", "cli", "user", "create",
			"-authn", "https://authentication:8086", "-username", name, "-roles", roles)
		if !strings.Contains(out, "user "+name+" created") {
			t.Fatalf("cli user create %s: %s", name, out)
		}
	}
	cliUser("root-admin", "root-pw-123456", "platform-admin,vault-admin")
	cliUser("operator", "op-password-123", "dba")
	cliUser("auditor", "aud-password-123", "session-auditor")

	adminToken, status := gatewayLogin(t, gatewayURL, "root-admin", "root-pw-123456")
	if status != http.StatusOK {
		t.Fatalf("admin login: %d", status)
	}
	const accountID = "acc_compose"
	for _, pol := range []struct{ name, role, resource string }{
		{"vault-admins", "vault-admin", "vault:account-admin:*"},
		{"dba-on-target", "dba", "vault:account:" + accountID},
		{"auditors", "session-auditor", "recording:session:*"},
	} {
		if status := gatewayCreatePolicy(t, gatewayURL, adminToken, pol.name, pol.role, pol.resource, "allow", "ignored"); status != http.StatusCreated {
			t.Fatalf("policy %s: %d", pol.name, status)
		}
	}
	targetSecret := secrets["DEMO_TARGET_PASSWORD"]
	// The target's host key, read where an administrator reads it — out of band, here the
	// target's own log — and pinned at onboarding (ADR-0039).
	var demoHostKey string
	for _, line := range strings.Split(run("", "logs", "--no-color", "demo-ssh-target"), "\n") {
		if _, k, ok := strings.Cut(line, "demo-ssh-target host key: "); ok {
			demoHostKey = strings.TrimSpace(k)
		}
	}
	if demoHostKey == "" {
		t.Fatal("the demonstration target printed no host key")
	}
	if status := gatewayOnboardAccountWith(t, gatewayURL, adminToken, map[string]any{
		"id": accountID, "name": "compose-account", "username": "root", "targetHost": "demo-ssh-target:2022",
		"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(targetSecret), "hostKey": demoHostKey,
	}); status != http.StatusCreated {
		t.Fatalf("onboarding: %d", status)
	}
	operatorToken, _ := gatewayLogin(t, gatewayURL, "operator", "op-password-123")
	auditorToken, _ := gatewayLogin(t, gatewayURL, "auditor", "aud-password-123")
	sess, status := gatewayCreateSession(t, gatewayURL, operatorToken, "someone-else", []string{"platform-admin"}, accountID)
	if status != http.StatusCreated {
		t.Fatalf("create session: %d", status)
	}
	_, ticket, status := gatewayConnect(t, gatewayURL, operatorToken, sess.ID)
	if status != http.StatusOK {
		t.Fatalf("connect: %d", status)
	}
	sh := openShell(t, "127.0.0.1:"+sshPort, ticket)
	fmt.Fprint(sh.stdin, "whoami\r")
	sh.waitFor("out:whoami")
	fmt.Fprint(sh.stdin, "id\r")
	sh.waitFor("out:id")

	readBack := func(t *testing.T) {
		t.Helper()
		var page recordingPage
		waitUntil(t, 10*time.Second, "the recording to be readable", func() bool {
			status, _, pg := gatewayGetRecording(t, gatewayURL, auditorToken, sess.ID, "")
			page = pg
			return status == http.StatusOK && pg.TotalEntries >= 2
		})
		if got := page.commands(); len(got) != 2 || got[0] != "whoami" || got[1] != "id" {
			t.Fatalf("recorded commands: %q", got)
		}
	}
	verifyChain := func(t *testing.T) {
		t.Helper()
		out := run("", "run", "--rm", "-T", "cli", "audit", "verify-chain", "-audit", "https://audit-service:8082")
		if !strings.Contains(out, "the audit chain verifies") {
			t.Fatalf("cli audit verify-chain: %s", out)
		}
	}

	t.Run("an auditor reads back what the operator typed, with the published ports only", readBack)
	t.Run("the audit chain verifies, by the CLI", verifyChain)

	t.Run("no secret is in any log of the stack", func(t *testing.T) {
		logs := run("", "logs", "--no-color")
		if !strings.Contains(logs, "api-gateway listening") || !strings.Contains(logs, "internal mTLS on as session-broker") {
			t.Fatalf("the logs read are not the stack's: nothing below would mean anything")
		}
		for _, name := range []string{"DEMO_TARGET_PASSWORD", "TOKEN_SIGNING_KEY_HEX", "VAULT_KMS_KEY_HEX", "RECORDER_KMS_KEY_HEX",
			"AUDIT_CHAIN_KEY_HEX", "PG_PASSWORD_SESSION_BROKER", "PG_SUPERUSER_PASSWORD"} {
			if v := secrets[name]; v == "" || strings.Contains(logs, v) {
				t.Fatalf("%s is in the logs of the stack (or was not drawn)", name)
			}
		}
		for _, pw := range []string{"root-pw-123456", "op-password-123", ticket} {
			if strings.Contains(logs, pw) {
				t.Fatalf("a password or the ticket is in the logs of the stack")
			}
		}
	})

	// The trail as the Audit Service's own database holds it.
	auditActions := func(t *testing.T) string {
		t.Helper()
		out, err := compose("exec", "-T", "-e", "PGPASSWORD="+secrets["PG_PASSWORD_AUDIT_SERVICE"], "postgres",
			"psql", "-h", "127.0.0.1", "-U", "audit_service", "-d", "audit_service", "-tAc",
			"SELECT string_agg(action, ',' ORDER BY seq) FROM audit_events").Output()
		if err != nil {
			t.Fatalf("reading the audit events: %v", err)
		}
		return strings.TrimSpace(string(out))
	}

	t.Run("after a restart of the whole stack, everything is still there", func(t *testing.T) {
		before := auditActions(t)
		// Since ADR-0064 the logins are in it too: the refused one first, then the administrator's,
		// the operator's and the auditor's, before the session.
		if before != "auth.login_refused,auth.login,auth.login,auth.login,session.create,session.connect,recording.read" {
			t.Fatalf("the trail before the restart: %q, want a refused login, three logins, then the session created, connected, its recording read", before)
		}
		since := time.Now().UTC().Format(time.RFC3339)
		run("", "restart")
		// Ready means every service has listened again — not a login polled until it works:
		// logins are budgeted per address (ADR-0014), and a polling loop would spend the budget.
		waitUntil(t, 60*time.Second, "every service to listen again after the restart", func() bool {
			logs, _ := compose("logs", "--no-color", "--since", since).CombinedOutput()
			for _, svc := range []string{"authentication", "authorization", "session-broker", "password-vault", "audit-service", "command-recorder", "api-gateway"} {
				if !strings.Contains(string(logs), svc+" listening on") {
					return false
				}
			}
			return true
		})
		var status int
		auditorToken, status = gatewayLogin(t, gatewayURL, "auditor", "aud-password-123")
		if status != http.StatusOK {
			t.Fatalf("the auditor's login after the restart: %d", status)
		}
		readBack(t)
		verifyChain(t)
		// The restart cuts the operator's open connection: the proxy may write its end
		// (session.terminate) before it stops, or not — what was there before must be intact at
		// the head of the trail, and the new read at its end.
		if after := auditActions(t); !strings.HasPrefix(after, before+",") || !strings.HasSuffix(after, ",recording.read") {
			t.Fatalf("the trail after the restart: %q, want what was there before, then the new read", after)
		}
		adminToken, _ = gatewayLogin(t, gatewayURL, "root-admin", "root-pw-123456")
		if _, status := gatewayGetAccount(t, gatewayURL, adminToken, accountID); status != http.StatusOK {
			t.Fatalf("the account after the restart: %d", status)
		}
	})
}

func readEnvFile(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && !strings.HasPrefix(k, "#") {
			out[k] = v
		}
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the env file is not private: %v %v", info.Mode(), err)
	}
	return out
}

func TestComposeRecordingCredentialsUpgradeIsAdditiveAndIdempotent(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	baseEnv := filepath.Join(dir, ".env")
	recordingEnv := filepath.Join(dir, ".env.recording")
	original := []byte("# Existing installation\nPG_SUPERUSER_PASSWORD=preserved\n")
	if err := os.WriteFile(baseEnv, original, 0o600); err != nil {
		t.Fatal(err)
	}

	run := func() string {
		t.Helper()
		cmd := exec.Command(filepath.Join(root, "deploy/docker-compose/init-recording.sh"), baseEnv, recordingEnv)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("init-recording.sh: %v\n%s", err, out)
		}
		return string(out)
	}
	firstOutput := run()
	recording := readEnvFile(t, recordingEnv)
	wantKeys := []string{"PG_PASSWORD_VIDEO_RECORDER", "VIDEO_RECORDER_S3_ACCESS_KEY", "VIDEO_RECORDER_S3_SECRET_KEY"}
	if len(recording) != len(wantKeys) {
		t.Fatalf("recording env has %d values, want %d", len(recording), len(wantKeys))
	}
	for _, key := range wantKeys {
		value := recording[key]
		if len(value) != 64 || strings.Trim(value, "0123456789abcdef") != "" {
			t.Fatalf("%s is not a 64-character lowercase hex value", key)
		}
		if strings.Contains(firstOutput, value) {
			t.Fatalf("init-recording.sh printed the value of %s", key)
		}
	}
	if got, err := os.ReadFile(baseEnv); err != nil || string(got) != string(original) {
		t.Fatalf("the existing env file changed: %v", err)
	}

	before, err := os.ReadFile(recordingEnv)
	if err != nil {
		t.Fatal(err)
	}
	run()
	after, err := os.ReadFile(recordingEnv)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("a repeated init changed the recording credentials")
	}

	partialEnv := filepath.Join(dir, ".env.partial")
	if err := os.WriteFile(partialEnv, []byte(string(original)+"PG_PASSWORD_VIDEO_RECORDER=present\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	partialOut := filepath.Join(dir, ".env.partial.recording")
	cmd := exec.Command(filepath.Join(root, "deploy/docker-compose/init-recording.sh"), partialEnv, partialOut)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "only some recording credentials") {
		t.Fatalf("a partially configured env should be refused: %v\n%s", err, out)
	}
	if _, err := os.Stat(partialOut); !os.IsNotExist(err) {
		t.Fatalf("partial configuration created an output file: %v", err)
	}
}

func TestComposeRecordingDatabaseUpgradeOnExistingVolume(t *testing.T) {
	if os.Getenv("COMPOSE_TEST") == "" {
		t.Skip("COMPOSE_TEST not set — this test starts an isolated PostgreSQL Compose stack")
	}
	root := repoRoot(t)
	dir := t.TempDir()
	fullEnv := filepath.Join(dir, ".env.full")
	oldEnv := filepath.Join(dir, ".env")
	recordingEnv := filepath.Join(dir, ".env.recording")
	init := exec.Command("sh", filepath.Join(root, "deploy/docker-compose/init.sh"), fullEnv)
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init.sh: %v\n%s", err, out)
	}
	full, err := os.ReadFile(fullEnv)
	if err != nil {
		t.Fatal(err)
	}
	var old strings.Builder
	for _, line := range strings.Split(string(full), "\n") {
		if strings.HasPrefix(line, "PG_PASSWORD_VIDEO_RECORDER=") ||
			strings.HasPrefix(line, "VIDEO_RECORDER_S3_ACCESS_KEY=") ||
			strings.HasPrefix(line, "VIDEO_RECORDER_S3_SECRET_KEY=") {
			continue
		}
		old.WriteString(line + "\n")
	}
	if err := os.WriteFile(oldEnv, []byte(old.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	initRecording := exec.Command(filepath.Join(root, "deploy/docker-compose/init-recording.sh"), oldEnv, recordingEnv)
	if out, err := initRecording.CombinedOutput(); err != nil {
		t.Fatalf("init-recording.sh: %v\n%s", err, out)
	}

	project := fmt.Sprintf("ob-video-db-upgrade-%d", os.Getpid())
	compose := func(recording bool, envFiles []string, args ...string) *exec.Cmd {
		cmdArgs := []string{"compose"}
		for _, path := range envFiles {
			cmdArgs = append(cmdArgs, "--env-file", path)
		}
		cmdArgs = append(cmdArgs, "-f", filepath.Join(root, "deploy/docker-compose/docker-compose.yml"), "-p", project)
		if recording {
			cmdArgs = append(cmdArgs, "--profile", "recording")
		}
		return exec.Command("docker", append(cmdArgs, args...)...)
	}
	t.Cleanup(func() {
		out, err := compose(true, []string{oldEnv, recordingEnv}, "down", "-v", "--remove-orphans").CombinedOutput()
		if err != nil {
			t.Logf("temporary Compose cleanup: %v\n%s", err, out)
		}
	})
	run := func(cmd *exec.Cmd) string {
		t.Helper()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker compose: %v\n%s", err, out)
		}
		return string(out)
	}
	run(compose(false, []string{oldEnv}, "up", "-d", "--wait", "--wait-timeout", "120", "postgres"))
	run(compose(true, []string{oldEnv, recordingEnv}, "run", "--rm", "video-recorder-db-init"))
	got := strings.TrimSpace(run(compose(true, []string{oldEnv, recordingEnv}, "exec", "-T", "postgres", "psql",
		"--no-password", "-U", "openbastion", "-d", "postgres", "-Atc",
		"SELECT (SELECT rolname FROM pg_roles WHERE rolname='video_recorder') || ':' || (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='video_recorder')")))
	if got != "video_recorder:video_recorder" {
		t.Fatalf("upgraded Video Recorder database ownership: got %q", got)
	}
}
