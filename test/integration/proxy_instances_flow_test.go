package integration_test

// ADR-0046 on real processes: two instances of the SSH proxy behind one Broker. A ticket is
// issued by one instance, in turn, and the operator is sent to that instance; a ticket is good
// nowhere else; ending a session cuts it on every instance; with one instance unreachable, nothing
// is ended — and the same call works once it is back; a connect still finds the instance that is
// up. Before ADR-0046 the Broker knew one instance, and every instance said the same address.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestProxyInstances_ATicketIsIssuedByOne_AndEndingASessionCutsItOnAll(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-46")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-46")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-46")
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-46")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-46")
	proxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-46")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-46")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-46")

	t.Run("a list of instances the Broker could read wrong stops it", func(t *testing.T) {
		var urls []string
		for i := 1; i <= 17; i++ {
			urls = append(urls, fmt.Sprintf("http://127.0.0.1:%d", i))
		}
		seventeen := strings.Join(urls, ",")
		for _, c := range []struct{ env, want string }{
			{"SSH_PROXY_URLS=http://127.0.0.1:18936,http://127.0.0.1:18938", "both set"},
			{"SSH_PROXY_URLS=http://127.0.0.1:18936,http://127.0.0.1:18936", "twice"},
			{"SSH_PROXY_URLS=http://127.0.0.1:18936,,http://127.0.0.1:18938", "SSH_PROXY_URLS"},
			{"SSH_PROXY_URLS=127.0.0.1:18936", "SSH_PROXY_URLS"},
			{"SSH_PROXY_URLS=" + seventeen, "at most 16"},
		} {
			env := []string{"PORT=18949", c.env}
			if c.want == "both set" {
				env = append(env, "SSH_PROXY_URL=http://127.0.0.1:18936")
			}
			if out := runUntilExit(t, root, brokerBin, env...); !strings.Contains(out, c.want) {
				t.Fatalf("%s: the refusal does not say %q:\n%s", c.env, c.want, out)
			}
		}
		for _, bad := range []string{"nowhere", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:70000", ":2222"} {
			if out := runUntilExit(t, root, proxyBin, "PORT=18948", "SSH_PORT=18947", "SSH_PUBLIC_ENDPOINT="+bad); !strings.Contains(out, "SSH_PUBLIC_ENDPOINT") {
				t.Fatalf("SSH_PUBLIC_ENDPOINT=%q was not refused by name:\n%s", bad, out)
			}
		}
	})

	audit := startService(t, root, auditBin, "18931")
	authz := startService(t, root, authzBin, "18932")
	authn := startService(t, root, authnBin, "18933", "SKIP_DEMO_SEED=1")
	vault := startService(t, root, vaultBin, "18934", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authz.baseURL)
	recorder := startService(t, root, recorderBin, "18935", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	spy := startAuditSpy(t, audit.baseURL)
	proxyEnv := func(sshAddr string) []string {
		return []string{"VAULT_URL=" + vault.baseURL, "AUDIT_URL=" + spy.baseURL, "PROXY_SERVICE_ID=ssh-proxy",
			"RECORDER_URL=" + recorder.baseURL, "RECORDING_POLICY=required", "SSH_PUBLIC_ENDPOINT=" + sshAddr}
	}
	// Not the default (127.0.0.1:SSH_PORT): an instance that ignored SSH_PUBLIC_ENDPOINT would show.
	const ssh1, ssh2 = "localhost:18937", "localhost:18939"
	_ = startServiceWithExtraPort(t, root, proxyBin, "18936", "18937", proxyEnv(ssh1)...)
	proxy2 := startServiceWithExtraPort(t, root, proxyBin, "18938", "18939", proxyEnv(ssh2)...)
	broker := startService(t, root, brokerBin, "18940",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL, "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URLS=http://127.0.0.1:18936, http://127.0.0.1:18938")
	gw := startService(t, root, gatewayBin, "18941",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL="+recorder.baseURL, "SESSION_ACTION_BURST=100", "SESSION_ACTION_RATE_PER_MINUTE=600")
	parent := t

	const targetSecret = "instances-target-secret"
	targetAddr := startObservedInteractiveTargetSSHServer(t, targetSecret, func(string) {})
	const accountID = "acc_instances"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "instances-account", "root", targetAddr, targetSecret, []string{"vault-admin"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	operator, status := gatewayLogin(t, gw.baseURL, "operator", "op-password-123")
	if status != http.StatusOK {
		t.Fatalf("login: %d", status)
	}
	open := func(t *testing.T) string {
		t.Helper()
		sess, status := gatewayCreateSession(t, gw.baseURL, operator, "", nil, accountID)
		if status != http.StatusCreated || sess == nil || sess.Status != "active" {
			t.Fatalf("session: %d %+v", status, sess)
		}
		return sess.ID
	}
	connect := func(t *testing.T, id string) (endpoint, ticket string) {
		t.Helper()
		endpoint, ticket, status := gatewayConnect(t, gw.baseURL, operator, id)
		if status != http.StatusOK || ticket == "" {
			t.Fatalf("connect: %d", status)
		}
		return endpoint, ticket
	}
	end := func(id string) (int, string) {
		code, _, text := rawRequest(t, http.MethodDelete, gw.baseURL+"/sessions/"+id, operator, "")
		return code, text
	}
	statusOf := func(t *testing.T, id string) string {
		t.Helper()
		s, _ := gatewayGetSession(t, gw.baseURL, operator, id)["status"].(string)
		return s
	}

	sessA := open(t)
	e1, t1 := connect(t, sessA)
	e2, t2 := connect(t, sessA)

	t.Run("tickets are issued by each instance in turn, and the operator is sent to the one that holds it", func(t *testing.T) {
		if e1 == e2 || (e1 != ssh1 && e1 != ssh2) || (e2 != ssh1 && e2 != ssh2) {
			t.Fatalf("endpoints %q and %q, want %s and %s, one each", e1, e2, ssh1, ssh2)
		}
	})

	t.Run("a ticket is good on its instance and nowhere else", func(t *testing.T) {
		other := map[string]string{ssh1: ssh2, ssh2: ssh1}
		e3, spare := connect(t, sessA)
		if err := tryDial(other[e3], spare); err == nil {
			t.Fatal("a ticket opened a connection on an instance that did not issue it")
		}
		// The same ticket, on the instance that issued it: it was refused elsewhere, not spent.
		if err := tryDial(e3, spare); err != nil {
			t.Fatalf("the ticket did not open a connection on its own instance: %v", err)
		}
	})

	sh1, sh2 := openShell(t, e1, t1), openShell(t, e2, t2)
	sessB := open(t)
	eB, tB := connect(t, sessB)
	shB := openShell(t, eB, tB)
	alive := func(t *testing.T, sh *shell, word string) {
		t.Helper()
		sh.stdin.Write([]byte(word + "\r"))
		sh.waitFor("out:" + word)
	}
	alive(t, sh1, "one-before")
	alive(t, sh2, "two-before")

	t.Run("ending the session cuts it on both instances", func(t *testing.T) {
		if code, text := end(sessA); code != http.StatusOK || !strings.Contains(text, `"terminated"`) {
			t.Fatalf("end: %d %s, want 200 and terminated", code, text)
		}
		sh1.waitClosed()
		sh2.waitClosed()
		for name, sh := range map[string]*shell{e1: sh1, e2: sh2} {
			if !strings.Contains(sh.output(), "openbastion: session ended because it was terminated.") {
				t.Fatalf("the operator on %s was not told: %q", name, sh.output())
			}
		}
		alive(t, shB, "b-untouched")
	})

	t.Run("with one instance unreachable nothing is ended, a connect finds the other, and the same call works once it is back", func(t *testing.T) {
		sessD := open(t)
		stopService(t, proxy2)
		for i := 0; i < 2; i++ {
			if e, _ := connect(t, sessD); e != ssh1 {
				t.Fatalf("connect %d with the second instance down was sent to %s, want %s", i+1, e, ssh1)
			}
		}
		code, text := end(sessD)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("with an instance down: %d %s, want 503", code, text)
		}
		if strings.Contains(text, "127.0.0.1") || strings.Contains(text, "18938") {
			t.Fatalf("an instance's address reached the client: %q", text)
		}
		if got := statusOf(t, sessD); got != "active" {
			t.Fatalf("the session is %q after a termination one instance did not confirm, want active", got)
		}
		spy.waitFor(t, "session.terminate", sessD, false)

		proxy2 = startServiceWithExtraPort(parent, root, proxyBin, "18938", "18939", proxyEnv(ssh2)...)
		if code, text := end(sessD); code != http.StatusOK || !strings.Contains(text, `"terminated"`) {
			t.Fatalf("with the instance back: %d %s, want 200", code, text)
		}
		spy.waitFor(t, "session.terminate", sessD, true)
	})
}

// tryDial says whether a ticket opens an SSH connection at addr.
func tryDial(addr, ticket string) error {
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err == nil {
		_ = client.Close()
	}
	return err
}
