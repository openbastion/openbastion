package integration_test

// ADR-0048 across real processes and the real OpenSSH client: an account that recognises its
// target by a certificate authority, for one host name, opens a session on a target certified by
// that authority for that name — and sends no password to a target that presents a plain key, a
// certificate of another authority, for another name, expired, or without an end. An authority
// line that names a pattern is refused at onboarding; the account shows the authority's
// fingerprint.

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// certifiedSigner is a fresh host key certified by ca for names, from after to before.
func certifiedSigner(t *testing.T, ca ssh.Signer, names []string, after, before uint64) ssh.Signer {
	t.Helper()
	host := newHostSigner(t)
	cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: names, ValidAfter: after, ValidBefore: before}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHostCertFlow_AnAccountRecognisesItsTargetByAuthority_AndNoImpostorIsSentASecret(t *testing.T) {
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
		bins[name] = buildBinary(t, root, pkg, name+"-48")
	}
	audit := startService(t, root, bins["audit"], "19722")
	spy := startAuditSpy(t, audit.baseURL)
	vault := startService(t, root, bins["vault"], "19721", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:19723", "AUDIT_URL="+spy.baseURL)
	authz := startService(t, root, bins["authz"], "19723")
	authn := startService(t, root, bins["authn"], "19727", "SKIP_DEMO_SEED=1")
	startService(t, root, bins["recorder"], "19729", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	startServiceWithExtraPort(t, root, bins["proxy"], "19725", "19726", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+spy.baseURL,
		"PROXY_SERVICE_ID=ssh-proxy", "RECORDER_URL=http://127.0.0.1:19729", "RECORDING_POLICY=required")
	broker := startService(t, root, bins["broker"], "19724", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL=http://127.0.0.1:19725")
	gateway := startService(t, root, bins["gateway"], "19728", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:19729", "VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL)

	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	authCreateUser(t, authn.baseURL, "admin", "Admin", "admin-password-123", []string{"vault-admin"})
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	adminToken, _ := gatewayLogin(t, gateway.baseURL, "admin", "admin-password-123")
	operatorToken, _ := gatewayLogin(t, gateway.baseURL, "operator", "op-password-123")

	const secret = "the-root-password-by-authority"
	ca, rogue := newHostSigner(t), newHostSigner(t)
	authority := "@cert-authority target.example " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	hour := func(d int) uint64 { return uint64(time.Now().Add(time.Duration(d) * time.Hour).Unix()) }

	onboard := func(id, addr, hostKey string) int {
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+id, "allow")
		return gatewayOnboardAccountWith(t, gateway.baseURL, adminToken, map[string]any{
			"id": id, "name": id, "username": "root", "targetHost": addr,
			"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(secret), "hostKey": hostKey,
		})
	}
	session := func(t *testing.T, id string) (string, string) {
		t.Helper()
		sess, status := gatewayCreateSession(t, gateway.baseURL, operatorToken, "", nil, id)
		if status != http.StatusCreated {
			t.Fatalf("create session on %s: %d", id, status)
		}
		_, ticket, status := gatewayConnect(t, gateway.baseURL, operatorToken, sess.ID)
		if status != http.StatusOK {
			t.Fatalf("connect on %s: %d", id, status)
		}
		out, _ := openssh(t, ticket, "ssh", "-p", "19726", "operator@127.0.0.1")
		return sess.ID, out
	}

	t.Run("an authority line with a pattern, a list or a port is refused at onboarding", func(t *testing.T) {
		caKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
		for i, bad := range []string{"@cert-authority *.example " + caKey, "@cert-authority a.example,b.example " + caKey, "@cert-authority [target.example]:22 " + caKey} {
			if s := onboard("acc_badauth_"+string(rune('a'+i)), "127.0.0.1:1", bad); s != http.StatusBadRequest {
				t.Fatalf("%q: onboarding answered %d, want 400", bad, s)
			}
		}
	})

	good := startRecordingTarget(t, certifiedSigner(t, ca, []string{"target.example"}, hour(-1), hour(1)), secret)
	t.Run("the target certified by the account's authority for its name opens the session", func(t *testing.T) {
		if s := onboard("acc_by_authority", good.addr, authority); s != http.StatusCreated {
			t.Fatalf("onboarding by authority answered %d", s)
		}
		acc, _ := gatewayGetAccount(t, gateway.baseURL, adminToken, "acc_by_authority")
		if acc["hostKeyFingerprint"] != ssh.FingerprintSHA256(ca.PublicKey()) {
			t.Fatalf("the account shows %v, want the authority's fingerprint", acc["hostKeyFingerprint"])
		}
		_, out := session(t, "acc_by_authority")
		if got := good.passwords(); len(got) != 1 || got[0] != secret {
			t.Fatalf("the certified target was sent %q", got)
		}
		if !strings.Contains(out, "target-shell-ready") {
			t.Fatalf("the session did not run:\n%s", out)
		}
	})

	for name, signer := range map[string]ssh.Signer{
		"a plain key":                           newHostSigner(t),
		"a certificate of another authority":    certifiedSigner(t, rogue, []string{"target.example"}, hour(-1), hour(1)),
		"a certificate for another name":        certifiedSigner(t, ca, []string{"other.example"}, hour(-1), hour(1)),
		"a certificate for the dialled address": certifiedSigner(t, ca, []string{"127.0.0.1"}, hour(-1), hour(1)),
		"an expired certificate":                certifiedSigner(t, ca, []string{"target.example"}, hour(-2), hour(-1)),
		"a certificate without an end":          certifiedSigner(t, ca, []string{"target.example"}, hour(-1), ssh.CertTimeInfinity),
	} {
		t.Run("attack: "+name+" is sent no password, and it is audited", func(t *testing.T) {
			impostor := startRecordingTarget(t, signer, secret)
			id := "acc_imp_" + strings.ReplaceAll(name, " ", "_")
			if s := onboard(id, impostor.addr, authority); s != http.StatusCreated {
				t.Fatalf("onboarding answered %d", s)
			}
			sessionID, out := session(t, id)
			if got := impostor.passwords(); len(got) != 0 {
				t.Fatalf("the impostor was sent %d password(s): %q", len(got), got)
			}
			if strings.Contains(out, "target-shell-ready") {
				t.Fatalf("the operator reached a shell:\n%s", out)
			}
			spy.waitFor(t, "session.host_key_mismatch", sessionID, false)
		})
	}
}
