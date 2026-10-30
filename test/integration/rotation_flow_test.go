package integration_test

// Rotation reaches the target (ADR-0037), across eight real processes and a real SSH target.
//
// Before ADR-0037 a rotation changed the secret in the Vault only: the target kept its old
// password, the Vault injected one the target refused, and the next session failed. This is
// that, written first and seen to fail.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// rotatableTarget is an SSH server whose passwords change: root may run chpasswd; every user
// gets a pretend shell answering "out:<line>".
type rotatableTarget struct {
	addr string
	mu   sync.Mutex
	pw   map[string]string
}

func startRotatableTarget(t *testing.T, passwords map[string]string) *rotatableTarget {
	t.Helper()
	tgt := &rotatableTarget{pw: passwords}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if tgt.password(m.User()) == string(p) && p != nil {
			return &ssh.Permissions{Extensions: map[string]string{"user": m.User()}}, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tgt.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go tgt.serve(c, cfg)
		}
	}()
	return tgt
}

func (tgt *rotatableTarget) password(user string) string {
	tgt.mu.Lock()
	defer tgt.mu.Unlock()
	return tgt.pw[user]
}

func (tgt *rotatableTarget) serve(c net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	user := conn.Permissions.Extensions["user"]
	for nc := range chans {
		ch, requests, err := nc.Accept()
		if err != nil {
			return
		}
		go func(ch ssh.Channel, requests <-chan *ssh.Request) {
			defer ch.Close()
			for r := range requests {
				switch r.Type {
				case "pty-req", "window-change":
					_ = r.Reply(true, nil)
				case "shell":
					_ = r.Reply(true, nil)
					go shellLoop(ch)
				case "exec":
					_ = r.Reply(true, nil)
					status := uint32(1)
					cmd, in := string(r.Payload[4:]), bufio.NewReader(ch)
					allowed := cmd == "chpasswd" && user == "root"
					if cmd == "sudo -S -p '' chpasswd" && user == "admin" { // admin may sudo, with its own password first
						first, _ := in.ReadString('\n')
						allowed = strings.TrimRight(first, "\n") == tgt.password(user)
					}
					if allowed {
						line, _ := in.ReadString('\n')
						if u, p, ok := strings.Cut(strings.TrimRight(line, "\n"), ":"); ok {
							tgt.mu.Lock()
							tgt.pw[u] = p
							tgt.mu.Unlock()
							status = 0
						}
					}
					_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
					return
				default:
					_ = r.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}

func shellLoop(ch ssh.Channel) {
	in := bufio.NewReader(ch)
	for {
		fmt.Fprint(ch, "$ ")
		var line []byte
		for {
			b, err := in.ReadByte()
			if err != nil {
				return
			}
			if b == '\r' || b == '\n' {
				break
			}
			line = append(line, b)
		}
		fmt.Fprintf(ch, "\r\nout:%s\r\n", line)
	}
}

func canLogIn(addr, user, password string) bool {
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func vaultOnboard(t *testing.T, vaultURL string, body map[string]any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(vaultURL+"/vault/v1/onboard-account", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func gatewayRotate(t *testing.T, gatewayURL, token, accountID string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, gatewayURL+"/vault/accounts/"+accountID+"/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestRotationFlow_ARotationChangesThePasswordOnTheTarget_AndTheNextSessionUsesIt(t *testing.T) {
	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-37")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-37")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-37")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-37")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-37")
	proxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-37")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-37")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-37")

	audit := startService(t, root, auditBin, "19502")
	spy := startAuditSpy(t, audit.baseURL)
	vault := startService(t, root, vaultBin, "19501", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:19503", "AUDIT_URL="+spy.baseURL)
	authz := startService(t, root, authzBin, "19503")
	authn := startService(t, root, authnBin, "19507", "SKIP_DEMO_SEED=1")
	startService(t, root, recorderBin, "19509", "AUTHORIZATION_URL=http://127.0.0.1:19503", "AUDIT_URL="+audit.baseURL)
	startServiceWithExtraPort(t, root, proxyBin, "19505", "19506", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+audit.baseURL,
		"PROXY_SERVICE_ID=ssh-proxy", "RECORDER_URL=http://127.0.0.1:19509", "RECORDING_POLICY=required")
	broker := startService(t, root, brokerBin, "19504", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL=http://127.0.0.1:19505")
	gateway := startService(t, root, gatewayBin, "19508", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:19509", "VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL)

	tgt := startRotatableTarget(t, map[string]string{"root": "root-pw", "app": "app-old-pw"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:acc_rot_app", "allow")
	if s := vaultOnboard(t, vault.baseURL, map[string]any{"id": "acc_rot_root", "name": "root", "username": "root", "targetHost": tgt.addr,
		"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte("root-pw"), "actorRoles": []string{"vault-admin"}}); s != http.StatusCreated {
		t.Fatalf("onboard the reconciliation account: %d", s)
	}
	if s := vaultOnboard(t, vault.baseURL, map[string]any{"id": "acc_rot_app", "name": "app", "username": "app", "targetHost": tgt.addr,
		"protocol": "ssh", "rotationPolicy": "post_use", "initialSecret": []byte("app-old-pw"), "actorRoles": []string{"vault-admin"},
		"reconciliationAccountId": "acc_rot_root"}); s != http.StatusCreated {
		t.Fatalf("onboard the account: %d", s)
	}
	authCreateUser(t, authn.baseURL, "admin", "Admin", "admin-pw-123", []string{"platform-admin", "vault-admin"})
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	adminToken, _ := gatewayLogin(t, gateway.baseURL, "admin", "admin-pw-123")
	operatorToken, _ := gatewayLogin(t, gateway.baseURL, "operator", "op-password-123")

	session := func(t *testing.T) string {
		t.Helper()
		sess, status := gatewayCreateSession(t, gateway.baseURL, operatorToken, "", nil, "acc_rot_app")
		if status != http.StatusCreated {
			t.Fatalf("create session: %d", status)
		}
		_, ticket, status := gatewayConnect(t, gateway.baseURL, operatorToken, sess.ID)
		if status != http.StatusOK {
			t.Fatalf("connect: %d", status)
		}
		sh := openShell(t, "127.0.0.1:19506", ticket)
		fmt.Fprint(sh.stdin, "whoami\r")
		sh.waitFor("out:whoami")
		return sess.ID
	}

	t.Run("a manual rotation changes the target's password, and the next session opens with the new one", func(t *testing.T) {
		if s := gatewayRotate(t, gateway.baseURL, adminToken, "acc_rot_app"); s != http.StatusAccepted {
			t.Fatalf("rotate: %d", s)
		}
		if canLogIn(tgt.addr, "app", "app-old-pw") {
			t.Fatal("the old password still opens the target: the rotation did not reach it")
		}
		if now := tgt.password("app"); now == "app-old-pw" || now == "" {
			t.Fatalf("the target's password is %q", now)
		}
		session(t) // the Vault injects what the target now takes
		spy.waitFor(t, "vault.rotate_requested", "acc_rot_app", true)
		spy.waitFor(t, "vault.rotate", "acc_rot_app", true)
		adminID := userIDOf(t, adminToken)
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			if strings.HasPrefix(e.Action, "vault.rotate") && e.ActorID != adminID {
				t.Fatalf("a manual rotation's event names %q, want the admin %q (the Gateway's verified identity)", e.ActorID, adminID)
			}
		}
	})

	t.Run("a session that ends rotates a post_use account, and the next session still opens", func(t *testing.T) {
		before := tgt.password("app")
		id := session(t)
		req, _ := http.NewRequest(http.MethodDelete, gateway.baseURL+"/sessions/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+operatorToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("terminate: %d", resp.StatusCode)
		}
		spy.mu.Lock()
		spy.events = nil
		spy.mu.Unlock()
		waitUntil(t, 15*time.Second, "the password to be rotated after use", func() bool { return tgt.password("app") != before })
		spy.waitFor(t, "vault.rotate", "acc_rot_app", true)
		spy.mu.Lock()
		for _, e := range spy.events {
			if strings.HasPrefix(e.Action, "vault.rotate") && e.ActorID != "" {
				t.Errorf("a rotation after use names %q: it is a system action", e.ActorID)
			}
		}
		spy.mu.Unlock()
		if canLogIn(tgt.addr, "app", before) {
			t.Fatal("the password used by the ended session still opens the target")
		}
		session(t)
	})

	t.Run("an account without a reconciliation account cannot be rotated, and nothing changes", func(t *testing.T) {
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:acc_rot_lonely", "allow")
		if s := vaultOnboard(t, vault.baseURL, map[string]any{"id": "acc_rot_lonely", "name": "l", "username": "root", "targetHost": tgt.addr,
			"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte("root-pw"), "actorRoles": []string{"vault-admin"}}); s != http.StatusCreated {
			t.Fatalf("onboard: %d", s)
		}
		if s := gatewayRotate(t, gateway.baseURL, adminToken, "acc_rot_lonely"); s != http.StatusConflict {
			t.Fatalf("rotate without reconciliation: %d, want 409", s)
		}
		if tgt.password("root") != "root-pw" {
			t.Fatal("root's password changed")
		}
	})

	t.Run("the audit down, nothing is rotated", func(t *testing.T) {
		before := tgt.password("app")
		spy.setDown(true)
		defer spy.setDown(false)
		if s := gatewayRotate(t, gateway.baseURL, adminToken, "acc_rot_app"); s != http.StatusServiceUnavailable {
			t.Fatalf("rotate with the audit down: %d, want 503", s)
		}
		if tgt.password("app") != before {
			t.Fatal("the target was changed with the audit down")
		}
	})
}
