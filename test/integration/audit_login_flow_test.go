package integration_test

// ADR-0064 across real processes and a real Audit Service: every token is written to the chain
// before it is issued, and none is issued when the audit is down; the second factor's
// administrative gestures are written before they are made, and refused without the audit;
// refusals are written; no password, code or secret is ever in the chain.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuditLogin_ATokenIsWrittenBeforeItIsIssued_AndTheAuditDownNobodyLogsIn(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-64")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-64")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-64")
	audit := startService(t, root, auditBin, "19651")
	spy := startAuditSpy(t, audit.baseURL)
	mfaKey := testKMSKeyHex(t)
	authn := startService(t, root, authnBin, "19652", "SKIP_DEMO_SEED=1", "AUDIT_URL="+spy.baseURL,
		"MFA_REQUIRED_ROLES=platform-admin", "MFA_SECRET_KEY_HEX="+mfaKey)
	gateway := startService(t, root, gatewayBin, "19653", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	run := fmt.Sprint(time.Now().UnixNano())
	admin, dba := "root-"+run, "dba-"+run
	for user, role := range map[string]string{admin: "platform-admin", dba: "dba"} {
		if s, out := postJSONTo(t, authn.baseURL+"/auth/v1/users", map[string]any{"username": user, "displayName": user, "password": "pw-" + user, "roles": []string{role}}); s != http.StatusCreated {
			t.Fatalf("create %s: %d %v", user, s, out)
		}
	}
	login := func(user, password string) (int, map[string]any) {
		return postJSONTo(t, gateway.baseURL+"/auth/login", map[string]string{"username": user, "password": password})
	}
	var secrets []string

	t.Run("a login is in the chain, then a refused one", func(t *testing.T) {
		if s, out := login(dba, "pw-"+dba); s != http.StatusOK || out["accessToken"] == nil {
			t.Fatalf("login: %d %v", s, out)
		}
		spy.waitFor(t, "auth.login", dba, true)
		if s, _ := login(dba, "not-the-password"); s != http.StatusUnauthorized {
			t.Fatalf("a wrong password: %d", s)
		}
		spy.waitFor(t, "auth.login_refused", dba, false)
		// Who vouches for the account, in the chain (ADR-0076, point 10): a local one says so.
		for _, action := range []string{"auth.login", "auth.login_refused"} {
			if d := spy.detailsOf(action, dba); d["identity_source"] != "local" || d["identity_provider"] != "" {
				t.Fatalf("%s of a local account: details %v, want identity_source local and no provider", action, d)
			}
		}
	})

	t.Run("the second factor's code, enrollment and login are in the chain, in their order", func(t *testing.T) {
		loginStatus, out := login(admin, "pw-"+admin)
		if loginStatus != http.StatusUnauthorized || out["mfa"] != "enrollment_required" {
			t.Fatalf("MFA enrollment challenge: %d %v, want 401 enrollment_required", loginStatus, out)
		}
		ch, ok := out["challenge"].(string)
		if !ok || ch == "" {
			t.Fatalf("MFA login did not return a challenge: %v", out)
		}
		s, issued := postJSONTo(t, authn.baseURL+"/auth/v1/mfa/enrollment-codes", map[string]string{"source": "local", "loginName": admin})
		if s != http.StatusOK {
			t.Fatalf("issue a code: %d %v", s, issued)
		}
		spy.waitFor(t, "auth.mfa_enrollment_code_issued", "local:"+admin, true)
		ec := issued["enrollmentCode"].(string)
		enrollStatus, e := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll", map[string]string{"challenge": ch, "enrollmentCode": ec})
		if enrollStatus != http.StatusOK {
			t.Fatalf("enroll MFA: %d %v", enrollStatus, e)
		}
		secret, ok := e["secret"].(string)
		if !ok || secret == "" {
			t.Fatalf("MFA enrollment did not return a secret: %v", e)
		}
		secrets = append(secrets, ch, ec, secret)
		if s, done := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll/confirm", map[string]string{"challenge": ch, "code": totpCode(t, secret, time.Now())}); s != http.StatusOK || done["accessToken"] == nil {
			t.Fatalf("confirm: %d %v", s, done)
		}
		spy.waitFor(t, "auth.mfa_enrolled", admin, true)
		spy.waitFor(t, "auth.login_mfa", admin, true)
		if spy.has("auth.login", admin, true) {
			t.Fatal("a second-factor login written as auth.login")
		}
	})

	t.Run("the chain verifies, and holds no password, code, challenge or secret", func(t *testing.T) {
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: %d", resp.StatusCode)
		}
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			for _, v := range append(secrets, "pw-"+admin, "pw-"+dba, "not-the-password", mfaKey) {
				if strings.Contains(fmt.Sprintf("%+v", e), v) {
					t.Fatalf("the chain holds a value it must not: %+v", e)
				}
			}
		}
	})

	t.Run("the audit down: a right password gets no token (503), and no code or reset is made", func(t *testing.T) {
		spy.setDown(true)
		defer spy.setDown(false)
		if s, out := login(dba, "pw-"+dba); s != http.StatusServiceUnavailable || out["accessToken"] != nil {
			t.Fatalf("login with the audit down: %d %v", s, out)
		}
		if s, out := postJSONTo(t, authn.baseURL+"/auth/v1/mfa/enrollment-codes", map[string]string{"source": "local", "loginName": admin}); s != http.StatusServiceUnavailable || out["enrollmentCode"] != nil {
			t.Fatalf("a code with the audit down: %d %v", s, out)
		}
		resp, err := http.Post(authn.baseURL+"/auth/v1/mfa/reset", "application/json", strings.NewReader(fmt.Sprintf(`{"username": %q}`, admin)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("a reset with the audit down: %d", resp.StatusCode)
		}
		// A wrong password is still a refusal, not a 503.
		if s, _ := login(dba, "not-the-password"); s != http.StatusUnauthorized {
			t.Fatalf("a wrong password with the audit down: %d", s)
		}
		spy.setDown(false)
		// Not reset: the enrolled factor is still required.
		if _, out := login(admin, "pw-"+admin); out["mfa"] != "required" {
			t.Fatalf("after a refused reset: %v, want required because the enrolled factor remains active", out)
		}
	})

	t.Run("no password is in the service's log", func(t *testing.T) {
		for _, v := range append(secrets, "pw-"+admin, "pw-"+dba, "not-the-password") {
			if strings.Contains(authn.out.String(), v) || strings.Contains(gateway.out.String(), v) {
				t.Fatal("a log holds a value it must not")
			}
		}
		if !strings.Contains(authn.out.String(), "logins are written to the audit at "+spy.baseURL+" before a token is issued") {
			t.Fatalf("the start does not say logins are audited:\n%s", authn.out.String())
		}
	})
}
