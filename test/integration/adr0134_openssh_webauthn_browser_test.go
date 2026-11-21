package integration_test

// ADR-0134: the operator's own OpenSSH opens a ticketed session through the SSH proxy, and the
// Vault secret is typed into it after a WebAuthn step-up made in a real browser — the Admin UI in
// headless Chrome, its navigator.credentials ceremonies answered by Chrome's virtual authenticator
// (CDP WebAuthn domain: a real ceremony, origin and RP ID checked by Authentication, the private key
// never leaving the authenticator). Every service is a real process; the target is a test SSH
// server whose prompt is masked, as sudo's is.
//
// Run from the Admin UI browser CI job (integration.yml): skipped without CHROME, or without ssh.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The page's own fetch, observed: the bearer token the Admin UI holds (the operator calls the
// public API with it for what the page has no button for, ADR-0134 step 3), the bodies it sends to
// /secret-injection (to replay one), and every use of the clipboard (there must be none).
const adr0134Instrumentation = `(() => {
	const ob = window.__ob = { auth: "", injections: [], clipboard: 0 };
	const original = window.fetch.bind(window);
	window.fetch = (input, init) => {
		try {
			const headers = new Headers((init && init.headers) || {});
			const auth = headers.get("Authorization");
			if (auth) ob.auth = auth;
			const url = typeof input === "string" ? input : input.url;
			if (/\/secret-injection$/.test(url) && init && init.body) ob.injections.push(String(init.body));
		} catch (e) {}
		return original(input, init);
	};
	if (navigator.clipboard) {
		for (const name of ["readText", "writeText", "read", "write"]) {
			const real = navigator.clipboard[name];
			if (typeof real === "function") navigator.clipboard[name] = (...args) => { ob.clipboard++; return real.apply(navigator.clipboard, args); };
		}
	}
})();`

func TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser(t *testing.T) {
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		t.Skip("CHROME is not set; run from the dedicated Admin UI browser CI job")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no OpenSSH client (ssh) on PATH")
	}
	keyscan, err := exec.LookPath("ssh-keyscan")
	if err != nil {
		t.Skip("no ssh-keyscan on PATH")
	}
	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "vault-0134")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-0134")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authz-0134")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authn-0134")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "recorder-0134")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "broker-0134")
	proxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "proxy-0134")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "gateway-0134")

	// The WebAuthn origin is the page's: known before Authentication starts.
	uiPort := freeLocalPort(t)
	origin := fmt.Sprintf("http://localhost:%d", uiPort)
	const proxySSH = "127.0.0.1:18346"

	vault := startService(t, root, vaultBin, "18341", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18343")
	audit := startService(t, root, auditBin, "18342")
	auditSpy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "18343")
	// dba is a strict role (ADR-0065): its second factor is a key, TOTP is never offered.
	authn := startService(t, root, authnBin, "18344", "SKIP_DEMO_SEED=1", "MFA_SECRET_KEY_HEX="+testKMSKeyHex(t),
		"MFA_REQUIRED_ROLES=dba", "MFA_PHISHING_RESISTANT_ROLES=dba", "WEBAUTHN_RP_ID=localhost", "WEBAUTHN_ORIGINS="+origin)
	recorder := startService(t, root, recorderBin, "18347", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	proxy := startServiceWithExtraPort(t, root, proxyBin, "18345", "18346", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+auditSpy.baseURL,
		"RECORDER_URL="+recorder.baseURL, "PROXY_SERVICE_ID=ssh-proxy", "RECORDING_POLICY=required", "SSH_PUBLIC_ENDPOINT="+proxySSH)
	broker := startService(t, root, brokerBin, "18348", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL="+proxy.baseURL, "AUTHENTICATION_URL="+authn.baseURL)
	gateway := startService(t, root, gatewayBin, "18349", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL="+recorder.baseURL, "AUTHORIZATION_URL="+authz.baseURL,
		// More step-ups than an operator makes in a minute: the per-user action budget (ADR-0016) is not under test here.
		"SESSION_ACTION_BURST=100")

	const accountID = "acc_adr0134"
	const credential = "adr0134-Vault-Secret!"
	target := startMaskedPromptTarget(t, credential)
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "adr0134-account", "root", target.addr, credential, []string{"vault-admin"})
	for _, resource := range []string{"vault:account:" + accountID, "secret:inject:account:" + accountID, "recording:session:*"} {
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", resource, "allow")
	}
	const operator, operatorPassword = "adr0134-operator", "operator-password-0134"
	authCreateUser(t, authn.baseURL, operator, "ADR-0134 Operator", operatorPassword, []string{"dba"})

	startAdminUIPreviewOn(t, root, gateway.baseURL, uiPort)
	page := startHeadlessChrome(t, chrome)
	page.dump = os.Getenv("ADMIN_UI_DUMP")
	page.call("Page.enable", map[string]any{})
	page.call("Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": adr0134Instrumentation})
	page.call("WebAuthn.enable", map[string]any{"enableUI": false})
	var authenticator struct {
		AuthenticatorID string `json:"authenticatorId"`
	}
	if err := json.Unmarshal(page.call("WebAuthn.addVirtualAuthenticator", map[string]any{"options": map[string]any{
		"protocol": "ctap2", "transport": "usb", "hasResidentKey": true, "hasUserVerification": true,
		"isUserVerified": true, "automaticPresenceSimulation": true,
	}}), &authenticator); err != nil || authenticator.AuthenticatorID == "" {
		t.Fatalf("virtual authenticator: %v", err)
	}
	page.viewport(1400, 1000)
	page.call("Page.navigate", map[string]any{"url": origin + "/"})

	// 1. The operator signs in; a strict role enrolls its key with an administrator's code, in the page.
	page.waitTrue("the login form", `!!document.querySelector('input[name="username"]')`, 60*time.Second)
	page.fill(`input[name="username"]`, operator)
	page.fill(`input[name="password"]`, operatorPassword)
	page.clickButton("Se connecter")
	page.waitTrue("the key enrollment", `!!document.querySelector('input[name="enrollmentCode"]')`, 30*time.Second)
	if string(page.eval(`!!document.querySelector('#second-factor-code, input[name="totp_code"]')`)) == "true" {
		t.Fatal("a strict role was offered a TOTP code (ADR-0065, SSH-MFA-012)")
	}
	status, issued := postJSONTo(t, authn.baseURL+"/auth/v1/mfa/enrollment-codes", map[string]string{"source": "local", "loginName": operator})
	if status != http.StatusOK || issued["enrollmentCode"] == nil {
		t.Fatalf("enrollment code: %d %#v", status, issued)
	}
	page.fill(`input[name="enrollmentCode"]`, issued["enrollmentCode"].(string))
	page.clickButton("Enrôler une clé de sécurité")
	page.waitTrue("the signed-in page", `[...document.querySelectorAll("nav button")].some((b) => b.innerText.trim() === "Sessions")`, 30*time.Second)
	page.screenshot(page.dump, "adr0134-1-signed-in.png")
	var credentials struct {
		Credentials []json.RawMessage `json:"credentials"`
	}
	_ = json.Unmarshal(page.call("WebAuthn.getCredentials", map[string]any{"authenticatorId": authenticator.AuthenticatorID}), &credentials)
	if len(credentials.Credentials) != 1 {
		t.Fatalf("the virtual authenticator holds %d credential(s), want the one key enrolled", len(credentials.Credentials))
	}
	var bearer string
	_ = json.Unmarshal(page.eval(`window.__ob.auth`), &bearer)
	token := strings.TrimPrefix(bearer, "Bearer ")
	if token == "" || token == bearer {
		t.Fatalf("the page sent no bearer token: %q", bearer)
	}

	// 2-3. A session, then a ticket, through the public API with the page's token (SSH-MFA-004:
	// the actor is the token's, whatever the body claims).
	sess, status := gatewayCreateSession(t, gateway.baseURL, token, "someone-else", []string{"platform-admin"}, accountID)
	if status != http.StatusCreated || sess == nil {
		t.Fatalf("create session: %d", status)
	}
	endpoint, ticket, status := gatewayConnect(t, gateway.baseURL, token, sess.ID)
	if status != http.StatusOK || ticket == "" || endpoint != proxySSH {
		t.Fatalf("connect: %d endpoint %q", status, endpoint)
	}
	if strings.Contains(ticket, credential) {
		t.Fatal("the ticket carries the credential")
	}

	// 4. The operator's own OpenSSH, the ticket at the password prompt (SSH-MFA-002): through an
	// askpass program reading a 0600 file, never in an argument or the environment's value.
	work := t.TempDir()
	knownHosts := filepath.Join(work, "known_hosts")
	scan, err := exec.Command(keyscan, "-p", "18346", "-T", "5", "127.0.0.1").Output()
	if err != nil || len(scan) == 0 {
		t.Fatalf("ssh-keyscan of the proxy: %v", err)
	}
	if err := os.WriteFile(knownHosts, scan, 0o600); err != nil {
		t.Fatal(err)
	}
	client := startOpenSSH(t, sshBin, work, knownHosts, ticket)
	client.waitFor(t, "target-shell-ready", 30*time.Second)
	// SSH-MFA-003: neither the ticket nor the credential is in the client's arguments.
	if args, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", client.cmd.Process.Pid)); err == nil {
		if bytes.Contains(args, []byte(ticket)) || bytes.Contains(args, []byte(credential)) {
			t.Fatal("the ticket or the credential is in the ssh process's arguments")
		}
	}
	// A05: the ticket is spent; a second ssh with it is refused at authentication.
	if out := runOpenSSHOnce(t, sshBin, work, knownHosts, ticket); !strings.Contains(out, "Permission denied") {
		t.Fatalf("the same ticket, a second time: want a refused authentication, ssh said:\n%s", out)
	}

	// 6. The target waits at a masked prompt.
	client.send(t, "sudo -v")
	client.waitFor(t, "PROMPT-MASKED", 15*time.Second)

	// 7-11. In the Admin UI: the session, "Saisir le secret Vault", the warning, the key.
	page.showSession(sess.ID)
	page.waitTrue("the secret injection", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Saisir le secret Vault" && !b.disabled)`, 30*time.Second)
	page.clickButton("Saisir le secret Vault")
	page.waitTrue("the warning", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Continuer vers la confirmation MFA")`, 10*time.Second)
	page.clickButton("Continuer vers la confirmation MFA")
	page.waitTrue("the key button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Utiliser ma clé de sécurité")`, 15*time.Second)
	if string(page.eval(`!!document.querySelector('#secret-injection-totp')`)) == "true" {
		t.Fatal("the step-up of a strict role offered TOTP (SSH-MFA-012)")
	}
	page.clickButton("Utiliser ma clé de sécurité")
	page.waitTrue("the proxy's confirmation", `document.body.innerText.includes("Le proxy a confirmé la saisie du secret Vault dans la session.")`, 45*time.Second)
	page.screenshot(page.dump, "adr0134-2-injected.png")
	select {
	case got := <-target.typed:
		if got != credential {
			t.Fatalf("the target's masked prompt received %q", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the target's masked prompt received nothing")
	}
	client.waitFor(t, "SUDO-ACCEPTED", 15*time.Second)

	// D03: the assertion the page sent, replayed with the operator's own token, types nothing.
	var injections []string
	_ = json.Unmarshal(page.eval(`window.__ob.injections`), &injections)
	if len(injections) != 1 {
		t.Fatalf("the page sent %d injection proof(s), want 1", len(injections))
	}
	if !strings.Contains(injections[0], `"factor":"webauthn"`) || strings.Contains(injections[0], "totp_code") {
		t.Fatalf("the proof is not a WebAuthn assertion: %.200s", injections[0])
	}
	replay, _ := http.NewRequest(http.MethodPost, gateway.baseURL+"/sessions/"+sess.ID+"/secret-injection", strings.NewReader(injections[0]))
	replay.Header.Set("Authorization", "Bearer "+token)
	replay.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(replay); err != nil {
		t.Fatal(err)
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("a replayed assertion: %d %s, want a refusal", resp.StatusCode, body)
		}
		if bytes.Contains(body, []byte(credential)) {
			t.Fatal("the refusal carries the credential")
		}
		t.Logf("the replayed assertion: %d %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	select {
	case got := <-target.typed:
		t.Fatalf("the replayed assertion typed again: %q", got)
	case <-time.After(2 * time.Second):
	}

	// F06, F07: the client never shows the credential; the page never touched the clipboard.
	if strings.Contains(client.output(), credential) {
		t.Fatal("the credential is in what the operator's OpenSSH received")
	}
	if string(page.eval(`window.__ob.clipboard`)) != "0" {
		t.Fatalf("the page used the clipboard %s time(s)", page.eval(`window.__ob.clipboard`))
	}

	// D06: the ceremony cancelled in the page types nothing.
	page.clickButton("Saisir le secret Vault")
	page.waitTrue("the warning", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Continuer vers la confirmation MFA")`, 10*time.Second)
	page.clickButton("Continuer vers la confirmation MFA")
	page.waitTrue("the key button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Utiliser ma clé de sécurité")`, 15*time.Second)
	page.clickButton("Annuler")
	page.waitTrue("the step-up closed", `![...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Utiliser ma clé de sécurité")`, 10*time.Second)
	// D03: an assertion whose signature the authenticator spoiled is refused, and types nothing.
	page.call("WebAuthn.setResponseOverrideBits", map[string]any{"authenticatorId": authenticator.AuthenticatorID, "isBogusSignature": true})
	page.clickButton("Saisir le secret Vault")
	page.waitTrue("the warning", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Continuer vers la confirmation MFA")`, 10*time.Second)
	page.clickButton("Continuer vers la confirmation MFA")
	page.waitTrue("the key button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Utiliser ma clé de sécurité")`, 15*time.Second)
	page.clickButton("Utiliser ma clé de sécurité")
	page.waitTrue("the refusal of a bad signature", `!!document.querySelector('[role="alert"]')`, 30*time.Second)
	page.call("WebAuthn.setResponseOverrideBits", map[string]any{"authenticatorId": authenticator.AuthenticatorID, "isBogusSignature": false})
	page.clickButton("Annuler")
	select {
	case got := <-target.typed:
		t.Fatalf("a cancelled ceremony or a spoiled signature typed %q", got)
	case <-time.After(2 * time.Second):
	}
	if n := auditSpy.count("session.secret_injected", sess.ID); n != 1 {
		t.Fatalf("%d session.secret_injected event(s) after a cancellation and a spoiled signature, want 1", n)
	}

	// H02: a second step-up, then the session is ended before the key answers: nothing is typed, and
	// the operator's OpenSSH is cut (ADR-0018).
	page.clickButton("Saisir le secret Vault")
	page.waitTrue("the warning", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Continuer vers la confirmation MFA")`, 10*time.Second)
	page.clickButton("Continuer vers la confirmation MFA")
	page.waitTrue("the key button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Utiliser ma clé de sécurité")`, 15*time.Second)
	terminate, _ := http.NewRequest(http.MethodDelete, gateway.baseURL+"/sessions/"+sess.ID, nil)
	terminate.Header.Set("Authorization", "Bearer "+token)
	if resp, err := http.DefaultClient.Do(terminate); err != nil || resp.StatusCode/100 != 2 {
		t.Fatalf("terminate: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}
	client.waitExit(t, 20*time.Second)
	page.clickButton("Utiliser ma clé de sécurité")
	page.waitTrue("the refusal", `!!document.querySelector('[role="alert"]')`, 30*time.Second)
	page.screenshot(page.dump, "adr0134-3-refused-after-revocation.png")
	select {
	case got := <-target.typed:
		t.Fatalf("an injection after the session ended typed %q", got)
	case <-time.After(3 * time.Second):
	}
	if n := auditSpy.count("session.secret_injected", sess.ID); n != 1 {
		t.Fatalf("%d session.secret_injected event(s), want the one injection", n)
	}

	// A05: a ticket issued, then its session ended before any connection, opens nothing.
	sess2, status := gatewayCreateSession(t, gateway.baseURL, token, operator, nil, accountID)
	if status != http.StatusCreated || sess2 == nil {
		t.Fatalf("second session: %d", status)
	}
	_, ticket2, status := gatewayConnect(t, gateway.baseURL, token, sess2.ID)
	if status != http.StatusOK || ticket2 == "" {
		t.Fatalf("second connect: %d", status)
	}
	terminate2, _ := http.NewRequest(http.MethodDelete, gateway.baseURL+"/sessions/"+sess2.ID, nil)
	terminate2.Header.Set("Authorization", "Bearer "+token)
	if resp, err := http.DefaultClient.Do(terminate2); err != nil || resp.StatusCode/100 != 2 {
		t.Fatalf("terminate the second session: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}
	if out := runOpenSSHOnce(t, sshBin, work, knownHosts, ticket2); !strings.Contains(out, "Permission denied") {
		t.Fatalf("a ticket of an ended session: want a refused authentication, ssh said:\n%s", out)
	}

	// SSH-MFA-003, G06: no credential and no ticket in any service's output.
	for name, out := range map[string]string{"Gateway": gateway.out.String(), "Broker": broker.out.String(), "proxy": proxy.out.String(),
		"Vault": vault.out.String(), "Authentication": authn.out.String(), "recorder": recorder.out.String(), "audit": audit.out.String()} {
		for what, secret := range map[string]string{"credential": credential, "ticket": ticket, "second ticket": ticket2} {
			if strings.Contains(out, secret) {
				t.Errorf("the %s is in the %s's output", what, name)
			}
		}
	}
	t.Logf("OpenSSH %s through the proxy, the key enrolled and used in the page, the credential typed once at the masked prompt", proxySSH)
}

// -- the operator's OpenSSH --------------------------------------------------------------------

type openSSHClient struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	mu    sync.Mutex
	out   bytes.Buffer
	lines chan string
	done  chan struct{}
}

func openSSHArgs(work, knownHosts string) []string {
	return []string{"-F", "/dev/null", "-p", "18346", "-o", "UserKnownHostsFile=" + knownHosts, "-o", "StrictHostKeyChecking=yes",
		"-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
		"-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10", "-o", "IdentityAgent=none", "operator@127.0.0.1"}
}

// openSSHEnv gives OpenSSH the ticket through an askpass program that reads a 0600 file: the
// ticket is in no argument and in no environment variable's value.
func openSSHEnv(t *testing.T, work, ticket string) []string {
	t.Helper()
	ticketFile := filepath.Join(work, fmt.Sprintf("ticket-%d", time.Now().UnixNano()))
	if err := os.WriteFile(ticketFile, []byte(ticket+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	askpass := filepath.Join(work, "askpass.sh")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\nexec cat \"$OB_TICKET_FILE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=:0", "OB_TICKET_FILE="+ticketFile, "HOME="+work)
}

func startOpenSSH(t *testing.T, sshBin, work, knownHosts, ticket string) *openSSHClient {
	t.Helper()
	cmd := exec.Command(sshBin, append([]string{"-tt"}, openSSHArgs(work, knownHosts)...)...)
	cmd.Env = openSSHEnv(t, work, ticket)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c := &openSSHClient{cmd: cmd, stdin: stdin, lines: make(chan string, 64), done: make(chan struct{})}
	cmd.Stderr = &lockedWriter{c: c}
	if err := cmd.Start(); err != nil {
		t.Fatalf("ssh: %v", err)
	}
	go func() {
		reader := bufio.NewReader(stdout)
		for {
			line, err := reader.ReadString('\n')
			if line != "" {
				c.mu.Lock()
				c.out.WriteString(line)
				c.mu.Unlock()
				select {
				case c.lines <- strings.TrimRight(line, "\r\n"):
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { _ = cmd.Wait(); close(c.done) }()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-c.done
		}
	})
	return c
}

type lockedWriter struct{ c *openSSHClient }

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	return w.c.out.Write(p)
}

func (c *openSSHClient) output() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

func (c *openSSHClient) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(c.stdin, line+"\r"); err != nil {
		t.Fatalf("typing into ssh: %v", err)
	}
}

func (c *openSSHClient) waitFor(t *testing.T, want string, limit time.Duration) {
	t.Helper()
	deadline := time.After(limit)
	for {
		select {
		case line := <-c.lines:
			if strings.Contains(line, want) {
				return
			}
		case <-c.done:
			t.Fatalf("ssh ended before %q; it wrote:\n%s", want, c.output())
		case <-deadline:
			t.Fatalf("no %q from ssh within %s; it wrote:\n%s", want, limit, c.output())
		}
	}
}

func (c *openSSHClient) waitExit(t *testing.T, limit time.Duration) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(limit):
		t.Fatalf("the operator's ssh was not cut within %s after the session ended", limit)
	}
}

// runOpenSSHOnce tries one ssh with ticket and a command, and returns everything ssh wrote: a
// refused ticket is OpenSSH's "Permission denied".
func runOpenSSHOnce(t *testing.T, sshBin, work, knownHosts, ticket string) string {
	t.Helper()
	cmd := exec.Command(sshBin, append(openSSHArgs(work, knownHosts), "echo", "let-in")...)
	cmd.Env = openSSHEnv(t, work, ticket)
	done := make(chan struct{})
	var out []byte
	go func() { out, _ = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	return string(out)
}

// -- a target with a masked prompt -----------------------------------------------------------

type maskedPromptTarget struct {
	addr  string
	typed chan string
}

// startMaskedPromptTarget is an SSH target (pinned under targetHostKey) whose shell says it is ready,
// echoes what it is sent, and answers "sudo -v" with a password prompt that does not echo — as a
// real terminal's sudo does. What is typed at that prompt goes to typed, never back to the client.
func startMaskedPromptTarget(t *testing.T, password string) *maskedPromptTarget {
	t.Helper()
	target := &maskedPromptTarget{typed: make(chan string, 4)}
	config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if string(p) != password {
			return nil, fmt.Errorf("wrong password")
		}
		return nil, nil
	}}
	config.AddHostKey(targetHostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	target.addr = ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, requests, err := newCh.Accept()
					if err != nil {
						return
					}
					go func() {
						for req := range requests {
							switch req.Type {
							case "shell", "pty-req", "exec", "env":
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
								if req.Type == "exec" {
									_, _ = fmt.Fprint(ch, "target-shell-ready\r\n")
									_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
									_ = ch.Close()
								}
							default:
								if req.WantReply {
									_ = req.Reply(false, nil)
								}
							}
						}
					}()
					go func(ch ssh.Channel) {
						defer ch.Close()
						_, _ = fmt.Fprint(ch, "target-shell-ready\r\n")
						scanner := bufio.NewScanner(ch)
						scanner.Split(scanSSHLine)
						masked := false
						for scanner.Scan() {
							line := strings.TrimSpace(scanner.Text())
							switch {
							case masked:
								masked = false
								target.typed <- line
								_, _ = fmt.Fprint(ch, "\r\nSUDO-ACCEPTED\r\n")
							case line == "sudo -v":
								masked = true
								_, _ = fmt.Fprint(ch, "PROMPT-MASKED\r\n[sudo] password for root: ")
							case line != "":
								_, _ = fmt.Fprintf(ch, "echo:%s\r\n", line)
							}
						}
					}(ch)
				}
			}()
		}
	}()
	return target
}
