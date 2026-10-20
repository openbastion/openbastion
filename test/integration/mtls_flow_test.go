// This file proves ADR-0010 on real processes: the whole product, with every
// call between services mutually authenticated, and what each kind of attacker
// gets on that network.
//
// Eight services run under INTERNAL_TLS=required, each with a certificate
// minted for the test (helpers: mtls_helpers_test.go). The journey is the one
// the other flows prove over plain HTTP — a user logs in, asks for a session,
// connects over SSH, runs commands, an auditor reads the recording — and here
// the only door the test uses is the Gateway's public one, after the users have
// been created by an operator holding the admin-cli certificate.
//
// Then the same network is attacked, with identities of every kind: no
// certificate, a certificate from another authority, an expired one, one from
// another trust domain, and — the interesting case — a perfectly valid
// certificate of the *wrong service*. That last attacker is a compromised
// service, and the point of ADR-0010 is that what it can do is its caller
// rules, not "anything the network allows".
package integration_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestMTLS_TheWholeProductOverMutualTLS_AndItsAttackers_AcrossEightRealProcesses(t *testing.T) {
	root := repoRoot(t)
	p := newTestPKI(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-mtls")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-mtls")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-mtls")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-mtls")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-mtls")
	sshProxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-mtls")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-mtls")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-mtls")

	const (
		vaultURL    = "https://127.0.0.1:18801"
		auditURL    = "https://127.0.0.1:18802"
		authzURL    = "https://127.0.0.1:18803"
		brokerURL   = "https://127.0.0.1:18804"
		proxyURL    = "https://127.0.0.1:18805"
		authnURL    = "https://127.0.0.1:18807"
		recorderURL = "https://127.0.0.1:18809"
		gatewayURL  = "http://127.0.0.1:18808" // the public listener: users, bearer tokens, TLS ends at the edge
	)

	startMTLSService(t, root, vaultBin, "18801", p, mtls.PasswordVault, "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authzURL)
	startMTLSService(t, root, auditBin, "18802", p, mtls.AuditService)
	startMTLSService(t, root, authzBin, "18803", p, mtls.Authorization)
	startMTLSService(t, root, authnBin, "18807", p, mtls.Authentication, "SKIP_DEMO_SEED=1")
	startMTLSService(t, root, recorderBin, "18809", p, mtls.CommandRecorder, "AUTHORIZATION_URL="+authzURL)
	startMTLSService(t, root, sshProxyBin, "18805", p, mtls.SSHProxy,
		"SSH_PORT=18806",
		"VAULT_URL="+vaultURL, "AUDIT_URL="+auditURL, "RECORDER_URL="+recorderURL,
		"RECORDING_POLICY=required",
		// No PROXY_SERVICE_ID: under mutual TLS the proxy's identity is its certificate's.
	)
	startMTLSService(t, root, brokerBin, "18804", p, mtls.SessionBroker,
		"AUTHORIZATION_URL="+authzURL, "VAULT_URL="+vaultURL, "AUDIT_URL="+auditURL, "SSH_PROXY_URL="+proxyURL)
	startService(t, root, gatewayBin, "18808", p.env(mtls.APIGateway,
		"AUTHENTICATION_URL="+authnURL, "SESSION_BROKER_URL="+brokerURL, "VAULT_URL="+vaultURL,
		"AUTHORIZATION_URL="+authzURL, "COMMAND_RECORDER_URL="+recorderURL)...)

	const targetSecret = "mtls-it-target-secret"
	targetAddr := startInteractiveTargetSSHServer(t, targetSecret)

	// -- bootstrap: the operator tooling holds the admin-cli identity ----------
	admin := p.clientAs(t, mtls.AdminCLI)
	mtlsCreateUser(t, admin, authnURL, "root-admin", "root-pw-123456", []string{"platform-admin", "vault-admin"})
	mtlsCreateUser(t, admin, authnURL, "operator", "op-password-123", []string{"dba"})
	mtlsCreateUser(t, admin, authnURL, "auditor", "aud-password-123", []string{"session-auditor"})

	// -- from here on, only the Gateway's public API ---------------------------
	adminToken, status := gatewayLogin(t, gatewayURL, "root-admin", "root-pw-123456")
	if status != http.StatusOK {
		t.Fatalf("admin login through the Gateway: status %d", status)
	}
	const accountID = "acc_mtls_it"
	for _, pol := range []struct{ name, role, resource string }{
		{"vault-admins", "vault-admin", "vault:account-admin:*"},
		{"dba-on-target", "dba", "vault:account:" + accountID},
		{"auditors", "session-auditor", "recording:session:*"},
	} {
		if status := gatewayCreatePolicy(t, gatewayURL, adminToken, pol.name, pol.role, pol.resource, "allow", "ignored"); status != http.StatusCreated {
			t.Fatalf("policy %s through the Gateway: status %d", pol.name, status)
		}
	}
	if status := gatewayOnboardAccount(t, gatewayURL, adminToken, accountID, "mtls-account", "root", targetAddr, targetSecret); status != http.StatusCreated {
		t.Fatalf("onboarding through the Gateway: status %d", status)
	}

	operatorToken, status := gatewayLogin(t, gatewayURL, "operator", "op-password-123")
	if status != http.StatusOK {
		t.Fatalf("operator login: status %d", status)
	}
	auditorToken, status := gatewayLogin(t, gatewayURL, "auditor", "aud-password-123")
	if status != http.StatusOK {
		t.Fatalf("auditor login: status %d", status)
	}

	sess, status := gatewayCreateSession(t, gatewayURL, operatorToken, "someone-else", []string{"platform-admin"}, accountID)
	if status != http.StatusCreated {
		t.Fatalf("create session over mutual TLS: status %d", status)
	}
	_, ticket, status := gatewayConnect(t, gatewayURL, operatorToken, sess.ID)
	if status != http.StatusOK {
		t.Fatalf("connect over mutual TLS: status %d", status)
	}

	sh := openShell(t, "127.0.0.1:18806", ticket)
	fmt.Fprint(sh.stdin, "whoami\r")
	sh.waitFor("out:whoami")
	fmt.Fprint(sh.stdin, "id\r")
	sh.waitFor("out:id")

	// ---------------------------------------------------------------------
	// The journey worked, over mutual TLS, end to end.
	// ---------------------------------------------------------------------
	t.Run("an auditor reads, through the Gateway, what the operator typed", func(t *testing.T) {
		var page recordingPage
		waitUntil(t, 5*time.Second, "the recording to be readable", func() bool {
			status, _, pg := gatewayGetRecording(t, gatewayURL, auditorToken, sess.ID, "")
			page = pg
			return status == http.StatusOK && pg.TotalEntries >= 2
		})
		if got := page.commands(); len(got) != 2 || got[0] != "whoami" || got[1] != "id" {
			t.Fatalf("recorded commands: %q", got)
		}
	})

	t.Run("the audit chain is intact", func(t *testing.T) {
		status, raw := mustCall(t, admin, http.MethodGet, auditURL+"/audit/v1/verify-chain", nil)
		if status != http.StatusOK {
			t.Fatalf("verify-chain: status %d: %s", status, raw)
		}
	})

	// ---------------------------------------------------------------------
	// Attackers who cannot even complete a handshake.
	// ---------------------------------------------------------------------
	t.Run("a peer without a certificate is refused by every internal listener", func(t *testing.T) {
		for _, u := range []string{vaultURL, auditURL, authzURL, brokerURL, proxyURL, authnURL, recorderURL} {
			status, raw, err := call(newMTLSClient(p.roots(), nil), http.MethodGet, u+"/healthz", nil)
			if err == nil {
				t.Errorf("%s answered a peer with no certificate: %d %q", u, status, raw)
			}
		}
	})

	t.Run("plain HTTP to an internal port gets nothing", func(t *testing.T) {
		for _, u := range []string{vaultURL, authzURL, recorderURL} {
			status, raw, err := call(http.DefaultClient, http.MethodGet, strings.Replace(u, "https://", "http://", 1)+"/healthz", nil)
			if err == nil && status/100 == 2 {
				t.Errorf("%s answered plain HTTP: %d %q", u, status, raw)
			}
		}
	})

	forge := func(t *testing.T, ca *pki.CA, service string, opts pki.IssueOptions) *pki.Leaf {
		t.Helper()
		leaf, err := ca.Issue(service, opts)
		if err != nil {
			t.Fatalf("forging %s: %v", service, err)
		}
		return leaf
	}

	t.Run("a certificate from another authority is refused, even for the right name", func(t *testing.T) {
		otherCA, err := pki.NewCA(mtlsDomain, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// The attacker trusts our CA (to verify the server) but holds an api-gateway
		// certificate that its own authority signed.
		c := clientWith(t, p.roots(), forge(t, otherCA, mtls.APIGateway, pki.IssueOptions{}))
		if status, raw, err := call(c, http.MethodGet, vaultURL+"/vault/v1/accounts", nil); err == nil {
			t.Fatalf("answered: %d %q", status, raw)
		}
	})

	t.Run("a certificate from the right authority for another trust domain is refused", func(t *testing.T) {
		keyPEM, err := p.ca.KeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		elsewhere, err := pki.LoadCA(p.ca.CertPEM(), keyPEM, "elsewhere.test")
		if err != nil {
			t.Fatal(err)
		}
		c := clientWith(t, p.roots(), forge(t, elsewhere, mtls.APIGateway, pki.IssueOptions{}))
		if status, raw, err := call(c, http.MethodGet, vaultURL+"/vault/v1/accounts", nil); err == nil {
			t.Fatalf("answered: %d %q", status, raw)
		}
	})

	t.Run("an expired certificate is refused", func(t *testing.T) {
		expired := forge(t, p.ca, mtls.APIGateway, pki.IssueOptions{NotBefore: time.Now().Add(-3 * time.Hour), TTL: time.Hour})
		c := clientWith(t, p.roots(), expired)
		if status, raw, err := call(c, http.MethodGet, vaultURL+"/vault/v1/accounts", nil); err == nil {
			t.Fatalf("answered: %d %q", status, raw)
		}
	})

	// ---------------------------------------------------------------------
	// A compromised service: a valid certificate, the wrong service.
	// What it can do is its caller rules — nothing else, whatever it claims.
	// ---------------------------------------------------------------------
	type attack struct {
		name    string
		caller  string
		method  string
		url     string
		body    any
		changes string // what the request would have changed, had it got in
	}
	forgedEntry := map[string]any{"entries": []map[string]any{{"session_id": sess.ID, "ts": time.Now().UTC(), "command": "rm -rf / # forged"}}}
	attacks := []attack{
		// Who may say who a user is, and what roles they hold.
		{"the broker forges roles to create an authorization policy", mtls.SessionBroker, http.MethodPost, authzURL + "/authz/v1/policies",
			map[string]any{"name": "evil", "role": "attacker", "resourcePattern": "*", "effect": "allow", "createdBy": "root-admin", "actorRoles": []string{"platform-admin"}}, "a policy"},
		{"the operator tooling forges roles to create an authorization policy", mtls.AdminCLI, http.MethodPost, authzURL + "/authz/v1/policies",
			map[string]any{"name": "evil", "role": "attacker", "resourcePattern": "*", "effect": "allow", "actorRoles": []string{"platform-admin"}}, "a policy"},
		{"the SSH proxy asks what a role may do", mtls.SSHProxy, http.MethodPost, authzURL + "/authz/v1/check-access",
			map[string]any{"actor_roles": []string{"dba"}, "resource": "vault:account:" + accountID, "action": "read"}, "a probe of the policy set"},
		{"a compromised Gateway creates users", mtls.APIGateway, http.MethodPost, authnURL + "/auth/v1/users",
			map[string]any{"username": "backdoor", "displayName": "b", "password": "backdoor-pw-123", "roles": []string{"platform-admin"}}, "a user"},
		{"the broker checks a password", mtls.SessionBroker, http.MethodPost, authnURL + "/auth/v1/login",
			map[string]any{"username": "operator", "password": "op-password-123"}, "a login oracle"},

		// Who may obtain, and who may redeem, access to a secret.
		{"a compromised Gateway mints a scope for a secret", mtls.APIGateway, http.MethodPost, vaultURL + "/vault/v1/authorize-scope",
			map[string]any{"session_id": "s", "privileged_account_id": accountID, "proxy_service_id": "ssh-proxy", "ttl_seconds": 60}, "a scope token"},
		{"the SSH proxy mints its own scope", mtls.SSHProxy, http.MethodPost, vaultURL + "/vault/v1/authorize-scope",
			map[string]any{"session_id": "s", "privileged_account_id": accountID, "proxy_service_id": "ssh-proxy", "ttl_seconds": 60}, "a scope token"},
		{"the recorder lists the vault's accounts", mtls.CommandRecorder, http.MethodGet, vaultURL + "/vault/v1/accounts", nil, "an inventory of privileged accounts"},
		{"the broker onboards an account, forging admin roles", mtls.SessionBroker, http.MethodPost, vaultURL + "/vault/v1/onboard-account",
			map[string]any{"id": "evil", "name": "evil", "username": "root", "targetHost": "10.0.0.66:22", "protocol": "ssh", "initialSecret": []byte("x"), "actorRoles": []string{"vault-admin"}}, "an account"},
		{"the SSH proxy rotates a secret", mtls.SSHProxy, http.MethodPost, vaultURL + "/vault/v1/rotate",
			map[string]any{"accountId": accountID, "newSecret": []byte("rotated-by-an-attacker"), "actorRoles": []string{"vault-admin"}}, "a rotation"},
		{"the broker deletes an account", mtls.SessionBroker, http.MethodDelete, vaultURL + "/vault/v1/accounts/" + accountID, nil, "an account"},

		// Who may write to the audit trail and the recording.
		{"the Vault writes an audit event", mtls.PasswordVault, http.MethodPost, auditURL + "/audit/v1/emit-event",
			map[string]any{"actor_id": "root-admin", "action": "session.terminated", "resource_type": "session", "resource_id": sess.ID, "success": true}, "an audit entry"},
		{"a compromised Gateway verifies the audit chain", mtls.APIGateway, http.MethodGet, auditURL + "/audit/v1/verify-chain", nil, "an oracle on the audit store"},
		{"the broker forges commands into a recording", mtls.SessionBroker, http.MethodPost, recorderURL + "/recorder/v1/command-entries", forgedEntry, "a recorded command"},
		{"the operator tooling forges commands into a recording", mtls.AdminCLI, http.MethodPost, recorderURL + "/recorder/v1/command-entries", forgedEntry, "a recorded command"},
		{"the broker reads a recording, forging the auditor role", mtls.SessionBroker, http.MethodGet,
			recorderURL + "/recorder/v1/sessions/" + sess.ID + "/commands?actorRoles=session-auditor", nil, "the commands of a session"},

		// Who may open a session, or tell a proxy to.
		{"the Vault opens a session as someone else", mtls.PasswordVault, http.MethodPost, brokerURL + "/sessions",
			map[string]any{"requestedBy": "root-admin", "actorRoles": []string{"platform-admin"}, "targetAccountId": accountID, "protocol": "ssh", "justification": "x", "durationMinutes": 60}, "a session"},
		{"the operator tooling connects to a session", mtls.AdminCLI, http.MethodPost, brokerURL + "/sessions/" + sess.ID + "/connect", nil, "a connection ticket"},
		{"the Vault asks the proxy for a break-glass ticket", mtls.PasswordVault, http.MethodPost, proxyURL + "/internal/v1/establish-session",
			map[string]any{"session_id": "evil", "target_host": targetAddr, "target_user": "root", "vault_scope_token": "forged", "ttl_seconds": 60, "break_glass": true}, "an unrecorded session"},
		{"a compromised Gateway asks the proxy for a ticket", mtls.APIGateway, http.MethodPost, proxyURL + "/internal/v1/establish-session",
			map[string]any{"session_id": "evil", "target_host": targetAddr, "target_user": "root", "vault_scope_token": "forged", "ttl_seconds": 60, "break_glass": true}, "an unrecorded session"},
	}
	for _, a := range attacks {
		a := a
		t.Run("refused at the door: "+a.name, func(t *testing.T) {
			status, raw := mustCall(t, p.clientAs(t, a.caller), a.method, a.url, a.body)
			if status != http.StatusForbidden || raw != guardRefusal {
				t.Fatalf("%s as %s: got %d %q — it should have been refused by the caller rules, and must not have reached the handler (%s)",
					a.method+" "+a.url, a.caller, status, raw, a.changes)
			}
		})
	}

	t.Run("and none of it happened", func(t *testing.T) {
		// The forged policy was not created: the role it was for has no access.
		status, raw := mustCall(t, p.clientAs(t, mtls.CommandRecorder), http.MethodPost, authzURL+"/authz/v1/check-access",
			map[string]any{"actor_roles": []string{"attacker"}, "resource": "vault:account:" + accountID, "action": "read"})
		if status != http.StatusOK || !strings.Contains(raw, `"allowed":false`) {
			t.Fatalf("the forged policy took effect: %d %s", status, raw)
		}
		// The forged command is in no recording.
		_, rawRec, page := gatewayGetRecording(t, gatewayURL, auditorToken, sess.ID, "")
		if strings.Contains(string(rawRec), "forged") || page.TotalEntries != 2 {
			t.Fatalf("the recording was tampered with: %s", rawRec)
		}
		// The forged user does not exist.
		if _, status := gatewayLogin(t, gatewayURL, "backdoor", "backdoor-pw-123"); status == http.StatusOK {
			t.Fatal("the user a compromised Gateway tried to create can log in")
		}
	})

	t.Run("the same callers are let through where their rules allow it", func(t *testing.T) {
		// The refusals above would be worthless if everything were refused.
		for _, ok := range []struct {
			name, caller, url string
		}{
			{"operator tooling verifies the audit chain", mtls.AdminCLI, auditURL + "/audit/v1/verify-chain"},
			{"the Gateway lists accounts, on behalf of a vault admin", mtls.APIGateway, vaultURL + "/vault/v1/accounts?actorRoles=vault-admin"},
			{"any service answers health checks", mtls.SSHProxy, vaultURL + "/healthz"},
		} {
			if status, raw := mustCall(t, p.clientAs(t, ok.caller), http.MethodGet, ok.url, nil); status != http.StatusOK {
				t.Errorf("%s: got %d %q", ok.name, status, raw)
			}
		}
		status, raw := mustCall(t, p.clientAs(t, mtls.CommandRecorder), http.MethodPost, authzURL+"/authz/v1/check-access",
			map[string]any{"actor_roles": []string{"dba"}, "resource": "vault:account:" + accountID, "action": "read"})
		if status != http.StatusOK {
			t.Errorf("the recorder asks what a role may do: %d %q", status, raw)
		}
	})

	// ---------------------------------------------------------------------
	// A stolen scope token is worthless to anyone but the proxy it was minted for.
	// ---------------------------------------------------------------------
	t.Run("a scope token can be redeemed only by the SSH proxy's own identity", func(t *testing.T) {
		// The test plays the broker — it holds the real broker certificate — to obtain a token.
		broker := p.clientAs(t, mtls.SessionBroker)
		status, raw := mustCall(t, broker, http.MethodPost, vaultURL+"/vault/v1/authorize-scope",
			map[string]any{"session_id": "stolen-token-it", "privileged_account_id": accountID, "proxy_service_id": "ssh-proxy", "ttl_seconds": 60})
		if status != http.StatusOK || !strings.Contains(raw, "scope_token") {
			t.Fatalf("authorize-scope as the broker: %d %s", status, raw)
		}
		token := jsonField(t, raw, "scope_token")

		for _, thief := range []string{mtls.SessionBroker, mtls.CommandRecorder, mtls.APIGateway, mtls.AdminCLI} {
			// Each thief claims to be the proxy, in the body — the one thing a thief controls.
			status, raw := mustCall(t, p.clientAs(t, thief), http.MethodPost, vaultURL+"/vault/v1/fetch-credential",
				map[string]any{"scope_token": token, "calling_proxy_id": "ssh-proxy"})
			if status != http.StatusForbidden || raw != guardRefusal {
				t.Fatalf("%s redeeming a stolen token: %d %q", thief, status, raw)
			}
		}

		proxy := p.clientAs(t, mtls.SSHProxy)
		// The proxy's own certificate, but a body that names someone else: refused, and
		// the token is not burned by the attempt.
		status, raw = mustCall(t, proxy, http.MethodPost, vaultURL+"/vault/v1/fetch-credential",
			map[string]any{"scope_token": token, "calling_proxy_id": "some-other-proxy"})
		if status != http.StatusForbidden || raw == guardRefusal {
			t.Fatalf("a body claim that contradicts the certificate: %d %q (want the Vault's own 403)", status, raw)
		}
		// The proxy itself — the claim in the body is optional, the certificate is the proof.
		status, raw = mustCall(t, proxy, http.MethodPost, vaultURL+"/vault/v1/fetch-credential",
			map[string]any{"scope_token": token})
		if status != http.StatusOK || !strings.Contains(raw, "credential_material") {
			t.Fatalf("the proxy redeeming its token after all those attempts: %d %q — the token must have survived them", status, raw)
		}
		// And a token is single-use.
		if status, _ = mustCall(t, proxy, http.MethodPost, vaultURL+"/vault/v1/fetch-credential", map[string]any{"scope_token": token}); status == http.StatusOK {
			t.Fatal("a scope token was redeemed twice")
		}
	})

	// ---------------------------------------------------------------------
	// The client side: a service that is pointed at an impostor sends it nothing.
	// ---------------------------------------------------------------------
	t.Run("a broker whose vault address leads to an impostor sends it nothing", func(t *testing.T) {
		// The impostor holds a perfectly valid certificate — the recorder's — and
		// answers at the vault's place. Chain and address check out; the identity
		// does not, and the broker's client is pinned to "password-vault".
		leaf, err := tls.LoadX509KeyPair(pki.CertFile(p.dir, mtls.CommandRecorder), pki.KeyFile(p.dir, mtls.CommandRecorder))
		if err != nil {
			t.Fatal(err)
		}
		var hits atomic.Int64
		impostor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		impostor.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
		impostor.StartTLS()
		t.Cleanup(impostor.Close)

		victim := startMTLSService(t, root, brokerBin, "18810", p, mtls.SessionBroker,
			"AUTHORIZATION_URL="+authzURL, "VAULT_URL="+impostor.URL, "AUDIT_URL="+auditURL, "SSH_PROXY_URL="+proxyURL)

		// The test plays the Gateway, which is the broker's only caller. Creating the
		// session asks Authorization, not the Vault; it is connecting that asks the
		// Vault for a scope on the secret — the call that must never go astray.
		gw := p.clientAs(t, mtls.APIGateway)
		status, raw := mustCall(t, gw, http.MethodPost, victim.baseURL+"/sessions",
			map[string]any{"requestedBy": "u-operator", "actorRoles": []string{"dba"}, "targetAccountId": accountID,
				"protocol": "ssh", "justification": "it", "durationMinutes": 60})
		if status != http.StatusCreated {
			t.Fatalf("create session on the victim broker: %d %s", status, raw)
		}
		status, raw = mustCall(t, gw, http.MethodPost, victim.baseURL+"/sessions/"+jsonField(t, raw, "id")+"/connect", nil)
		if status == http.StatusOK || strings.Contains(raw, "ticket") {
			t.Fatalf("a connection ticket was issued although the vault could not be reached as itself: %d %s", status, raw)
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("the impostor received %d request(s): the broker sent a vault request to a service that is not the vault", n)
		}
		// The refusal is explained by the client's own identity check, not by a timeout
		// or a connection error that merely looks like one.
		if !strings.Contains(raw, `answered as "command-recorder", expected "password-vault"`) {
			t.Fatalf("the refusal should come from the identity pin; the broker said: %d %q", status, raw)
		}
	})
}
