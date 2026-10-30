package integration_test

// The target's host key is pinned at the Vault (ADR-0039), across real processes: a machine
// that takes the target's address presents another key and is sent no password; an
// administrator re-pins through the Gateway (audited, under the token's name); onboarding
// without a key, or with one that does not read, is refused.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// recordingTarget is an SSH target presenting signer, recording every password it is offered
// and accepting want; its shell says "target-shell-ready" and ends.
type recordingTarget struct {
	addr string
	mu   sync.Mutex
	seen []string
}

func (r *recordingTarget) passwords() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func startRecordingTarget(t *testing.T, signer ssh.Signer, want string) *recordingTarget {
	t.Helper()
	rt := &recordingTarget{}
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		rt.mu.Lock()
		rt.seen = append(rt.seen, string(p))
		rt.mu.Unlock()
		if string(p) == want {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, requests, err := nc.Accept()
					if err != nil {
						return
					}
					for req := range requests {
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						if req.Type == "shell" {
							fmt.Fprint(ch, "target-shell-ready\r\n")
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
							_ = ch.Close()
							break
						}
					}
				}
			}()
		}
	}()
	rt.addr = ln.Addr().String()
	return rt
}

func gatewayPinHostKey(t *testing.T, gatewayURL, token, accountID, hostKey string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"hostKey": hostKey})
	req, _ := http.NewRequest(http.MethodPut, gatewayURL+"/vault/accounts/"+accountID+"/host-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Fingerprint string `json:"hostKeyFingerprint"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Fingerprint
}

func TestHostKeyFlow_AnImpostorIsSentNoSecret_AnAdministratorRePins_AcrossRealProcesses(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not installed")
	}
	root := repoRoot(t)
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"vault": "./services/vault/password-vault/cmd/password-vault", "audit": "./services/recording-audit/audit-service/cmd/audit-service",
		"authz": "./services/access/authorization/cmd/authorization", "authn": "./services/access/authentication/cmd/authentication",
		"broker": "./services/access/session-broker/cmd/session-broker", "proxy": "./services/proxy/ssh-proxy/cmd/ssh-proxy",
		"recorder": "./services/recording-audit/command-recorder/cmd/command-recorder", "gateway": "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, name+"-39")
	}
	audit := startService(t, root, bins["audit"], "19702")
	spy := startAuditSpy(t, audit.baseURL)
	vault := startService(t, root, bins["vault"], "19701", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:19703", "AUDIT_URL="+spy.baseURL)
	authz := startService(t, root, bins["authz"], "19703")
	authn := startService(t, root, bins["authn"], "19707", "SKIP_DEMO_SEED=1")
	startService(t, root, bins["recorder"], "19709", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	startServiceWithExtraPort(t, root, bins["proxy"], "19705", "19706", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+spy.baseURL,
		"PROXY_SERVICE_ID=ssh-proxy", "RECORDER_URL=http://127.0.0.1:19709", "RECORDING_POLICY=required")
	broker := startService(t, root, bins["broker"], "19704", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL=http://127.0.0.1:19705")
	gateway := startService(t, root, bins["gateway"], "19708", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:19709", "VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL)

	const accountID, secret = "acc_pinned", "the-real-root-password"
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	impostorSigner, _ := ssh.NewSignerFromKey(priv)
	impostorKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(impostorSigner.PublicKey())))
	// The impostor holds the address the account names; the account is pinned to the real
	// target's key (targetHostKey), which the impostor does not have.
	impostor := startRecordingTarget(t, impostorSigner, secret)

	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authCreateUser(t, authn.baseURL, "admin", "Admin", "admin-password-123", []string{"vault-admin"})
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	adminToken, _ := gatewayLogin(t, gateway.baseURL, "admin", "admin-password-123")
	operatorToken, _ := gatewayLogin(t, gateway.baseURL, "operator", "op-password-123")

	onboard := func(id string, hostKey any) int {
		return gatewayOnboardAccountWith(t, gateway.baseURL, adminToken, map[string]any{
			"id": id, "name": id, "username": "root", "targetHost": impostor.addr,
			"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(secret), "hostKey": hostKey,
		})
	}

	t.Run("onboarding without a host key, or with one that does not read, is refused", func(t *testing.T) {
		for name, key := range map[string]any{"none": nil, "empty": "", "garbage": "ssh-ed25519 not-a-key", "a private key": "-----BEGIN OPENSSH PRIVATE KEY-----"} {
			if s := onboard("acc_unpinned_"+strings.ReplaceAll(name, " ", "_"), key); s != http.StatusBadRequest {
				t.Fatalf("%s: onboarding answered %d, want 400", name, s)
			}
		}
		if s := onboard(accountID, targetHostKey); s != http.StatusCreated {
			t.Fatalf("onboarding with a key answered %d", s)
		}
	})

	connect := func(t *testing.T) (string, string) {
		t.Helper()
		sess, status := gatewayCreateSession(t, gateway.baseURL, operatorToken, "", nil, accountID)
		if status != http.StatusCreated {
			t.Fatalf("create session: %d", status)
		}
		_, ticket, status := gatewayConnect(t, gateway.baseURL, operatorToken, sess.ID)
		if status != http.StatusOK {
			t.Fatalf("connect: %d", status)
		}
		out, _ := openssh(t, ticket, "ssh", "-p", "19706", "operator@127.0.0.1")
		return sess.ID, out
	}

	t.Run("attack: the impostor at the target's address is sent no password, and it is audited", func(t *testing.T) {
		sessionID, out := connect(t)
		if got := impostor.passwords(); len(got) != 0 {
			t.Fatalf("the impostor was sent %d password(s): %q", len(got), got)
		}
		if !strings.Contains(out, "pinned host key") || strings.Contains(out, "target-shell-ready") {
			t.Fatalf("the operator was not told, or reached a shell:\n%s", out)
		}
		spy.waitFor(t, "session.host_key_mismatch", sessionID, false)
	})

	t.Run("re-pinning needs the admin role; done by an admin, it is audited under the admin's name", func(t *testing.T) {
		if s, _ := gatewayPinHostKey(t, gateway.baseURL, operatorToken, accountID, impostorKey); s != http.StatusForbidden {
			t.Fatalf("an operator re-pinned: %d", s)
		}
		if s, _ := gatewayPinHostKey(t, gateway.baseURL, adminToken, accountID, "not a key"); s != http.StatusBadRequest {
			t.Fatalf("a key that does not read was pinned: %d", s)
		}
		s, fp := gatewayPinHostKey(t, gateway.baseURL, adminToken, accountID, impostorKey)
		if s != http.StatusOK || fp != ssh.FingerprintSHA256(impostorSigner.PublicKey()) {
			t.Fatalf("re-pin: %d %q", s, fp)
		}
		spy.mu.Lock()
		var pinnedBy string
		for _, e := range spy.events {
			if e.Action == "vault.host_key_set" && e.ResourceID == accountID && e.Success {
				pinnedBy = e.ActorID
			}
		}
		spy.mu.Unlock()
		if pinnedBy == "" || pinnedBy == "user_root" {
			t.Fatalf("the re-pin is not audited under the admin's name: %q", pinnedBy)
		}
		acc, _ := gatewayGetAccount(t, gateway.baseURL, adminToken, accountID)
		if acc["hostKeyFingerprint"] != fp {
			t.Fatalf("the account shows fingerprint %v, want %s", acc["hostKeyFingerprint"], fp)
		}
	})

	t.Run("counter-proof: the target now pinned is sent the secret and the session runs", func(t *testing.T) {
		_, out := connect(t)
		if got := impostor.passwords(); len(got) != 1 || got[0] != secret {
			t.Fatalf("the pinned target was sent %q", got)
		}
		if !strings.Contains(out, "target-shell-ready") {
			t.Fatalf("the session did not run:\n%s", out)
		}
	})
}
