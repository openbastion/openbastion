// This file proves the complete public journey through the API Gateway —
// the single entry point a real CLI or Admin UI would use — across SEVEN
// real, independently running processes: Authentication, Authorization,
// Session Broker, Password Vault, Audit Service, ssh-proxy, and the API
// Gateway itself. Login and CreateSession go through the Gateway's
// identity injection (proven at the unit level in api-gateway's own
// tests); this test additionally proves it holds across a real network
// hop to a real Session Broker, not just against a fake one.
package integration_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func authCreateUser(t *testing.T, baseURL, username, displayName, password string, roles []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"username": username, "displayName": displayName, "password": password, "roles": roles,
	})
	resp, err := http.Post(baseURL+"/auth/v1/users", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create-user: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create-user: status %d", resp.StatusCode)
	}
}

func gatewayLogin(t *testing.T, baseURL, username, password string) (token string, status int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(baseURL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gateway login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return out.AccessToken, resp.StatusCode
}

func gatewayCreateSession(t *testing.T, baseURL, token string, claimedRequestedBy string, claimedRoles []string, accountID string) (*brokerSession, int) {
	t.Helper()
	// Deliberately claims a different identity than the token actually
	// belongs to — the Gateway's verified identity must win regardless.
	body, _ := json.Marshal(map[string]any{
		"requestedBy": claimedRequestedBy, "actorRoles": claimedRoles,
		"targetAccountId": accountID, "protocol": "ssh",
		"justification": "gateway integration test", "durationMinutes": 60,
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway create-session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, resp.StatusCode
	}
	var sess brokerSession
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	return &sess, resp.StatusCode
}

func gatewayConnect(t *testing.T, baseURL, token, sessionID string) (proxyEndpoint, ticket string, status int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions/"+sessionID+"/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", resp.StatusCode
	}
	var out struct {
		ProxyEndpoint string `json:"proxyEndpoint"`
		Ticket        string `json:"ticket"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode connect response: %v", err)
	}
	return out.ProxyEndpoint, out.Ticket, resp.StatusCode
}

func TestGatewayFlow_LoginThroughRealSSHConnection_AcrossSevenRealProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-4")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-4")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-3")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-3")
	sshProxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-2")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway")

	vault := startService(t, root, vaultBin, "18201", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18203")
	audit := startService(t, root, auditBin, "18202")
	authz := startService(t, root, authzBin, "18203")
	authn := startService(t, root, authnBin, "18207", "SKIP_DEMO_SEED=1")
	startServiceWithExtraPort(t, root, sshProxyBin, "18205", "18206",
		"VAULT_URL=http://127.0.0.1:18201",
		"AUDIT_URL=http://127.0.0.1:18202",
		"PROXY_SERVICE_ID=ssh-proxy",
		// This test is about authorization and the relay, not recording, and
		// runs no Command Recorder: opt out of the default (required) policy
		// explicitly — without RECORDER_URL the proxy refuses to start.
		"RECORDING_POLICY=best-effort",
	)
	broker := startService(t, root, brokerBin, "18204",
		"AUTHORIZATION_URL=http://127.0.0.1:18203",
		"VAULT_URL=http://127.0.0.1:18201",
		"AUDIT_URL=http://127.0.0.1:18202",
		"SSH_PROXY_URL=http://127.0.0.1:18205",
	)
	gateway := startService(t, root, gatewayBin, "18208",
		"AUTHENTICATION_URL=http://127.0.0.1:18207",
		"SESSION_BROKER_URL="+broker.baseURL,
	)

	const secretValue = "gateway-it-secret-77"
	targetAddr := startFakeTargetSSHServer(t, secretValue)

	const accountID = "acc_gateway_it"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "gateway-test-account", "root", targetAddr, secretValue, []string{"vault-admin"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authCreateUser(t, authn.baseURL, "real-operator", "Real Operator", "op-password-123", []string{"dba"})

	// -- login, through the Gateway --
	token, status := gatewayLogin(t, gateway.baseURL, "real-operator", "op-password-123")
	if status != http.StatusOK {
		t.Fatalf("gateway login: status %d", status)
	}
	if token == "" {
		t.Fatal("expected a non-empty access token")
	}

	t.Run("wrong password is rejected by the real Authentication Service through the Gateway", func(t *testing.T) {
		if _, status := gatewayLogin(t, gateway.baseURL, "real-operator", "wrong-password"); status != http.StatusUnauthorized {
			t.Fatalf("expected 401 for a wrong password, got %d", status)
		}
	})

	// -- create session, claiming a false identity — must be overridden --
	sess, status := gatewayCreateSession(t, gateway.baseURL, token, "attacker-controlled-id", []string{"admin"}, accountID)
	if status != http.StatusCreated {
		t.Fatalf("gateway create-session: status %d", status)
	}

	proxyEndpoint, ticket, status := gatewayConnect(t, gateway.baseURL, token, sess.ID)
	if status != http.StatusOK {
		t.Fatalf("gateway connect: status %d", status)
	}
	t.Logf("real ProxyControl.EstablishSession, via Gateway -> Broker, returned proxyEndpoint=%q", proxyEndpoint)

	// -- the operator: a real ssh.Client using the ticket obtained --
	// entirely through the Gateway's public API.
	clientConfig := &ssh.ClientConfig{
		User:            "operator",
		Auth:            []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", "127.0.0.1:18206", clientConfig)
	if err != nil {
		t.Fatalf("client dial to ssh-proxy: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		t.Fatalf("client pty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("client stdin: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("client stdout: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("client shell: %v", err)
	}
	if _, err := fmt.Fprintf(stdin, "hello-via-gateway\n"); err != nil {
		t.Fatalf("write command: %v", err)
	}

	reader := bufio.NewReader(stdout)
	deadline := time.Now().Add(5 * time.Second)
	var line string
	for time.Now().Before(deadline) {
		line, err = reader.ReadString('\n')
		if err == nil && strings.Contains(line, "echo:hello-via-gateway") {
			break
		}
	}
	if !strings.Contains(line, "echo:hello-via-gateway") {
		t.Fatalf("expected the command to reach the real target through the full Gateway -> Authentication/Broker -> Vault -> ssh-proxy stack, got %q (err=%v)", line, err)
	}
	client.Close()

	t.Run("audit chain is intact after the full seven-process flow", func(t *testing.T) {
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatalf("verify-chain: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: status %d", resp.StatusCode)
		}
	})

	t.Run("gateway rejects requests with no bearer token", func(t *testing.T) {
		resp, err := http.Post(gateway.baseURL+"/sessions", "application/json", bytes.NewReader([]byte(`{}`)))
		if err != nil {
			t.Fatalf("post without token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 without a token, got %d", resp.StatusCode)
		}
	})
}
