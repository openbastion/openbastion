package integration_test

// ADR-0074 against a real Teams channel, when NOTIFY_INTEROP_TEAMS_URL is given: a real Audit Service,
// under mutual TLS, pushes the alert the Vault writes, signed, in the teams format. The URL is a
// secret: it reaches the process by its environment only, and the log must never hold it.
//
// What this proves is the delivery seen from OpenBastion: no refusal, no retry. That the card shows
// in the channel is for a person to look at — a Workflows flow answers 202 before it posts.

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
)

func TestRealChannel_TheAuditServicePushesTheVaultsAlertToTeams_Signed(t *testing.T) {
	raw := os.Getenv("NOTIFY_INTEROP_TEAMS_URL")
	if raw == "" {
		t.Skip("NOTIFY_INTEROP_TEAMS_URL not set")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		t.Fatal("NOTIFY_INTEROP_TEAMS_URL is not a URL") // never the value: it is a secret
	}
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-74-real")
	p := newTestPKI(t)
	audit := startMTLSService(t, root, auditBin, "18860", p, mtls.AuditService,
		"ALERT_NOTIFY_URL="+raw, "ALERT_NOTIFY_SECRET="+alertPushSecret, "ALERT_NOTIFY_FORMAT=teams", "ALERT_NOTIFY_RETRY_SECONDS=1")

	// The identity is the certificate's (ADR-0045): only the Vault's alert is pushed.
	status, body := mustCall(t, p.clientAs(t, mtls.PasswordVault), http.MethodPost, audit.baseURL+"/audit/v1/emit-event",
		map[string]any{"action": "vault.rotation_overdue", "resource_type": "account", "resource_id": "acc_interop_adr0074", "success": false})
	if status != http.StatusOK {
		t.Fatalf("emit: %d %s", status, body)
	}

	// A refusal is logged at once and a retry after 1 s: room for both, and for Microsoft to answer.
	time.Sleep(8 * time.Second)
	out := audit.out.String()
	for _, secret := range []string{raw, parsed.RawQuery, parsed.Path, alertPushSecret} {
		if secret != "" && strings.Contains(out, secret) {
			t.Fatal("the log holds the URL or the secret") // the log is not printed: it would be the leak
		}
	}
	if !strings.Contains(out, "alerts use the teams format") || !strings.Contains(out, "signed (") {
		t.Fatal("the Audit Service does not say it pushes signed alerts in the teams format")
	}
	for _, failed := range []string{"not delivered", "given up", "not pushed"} {
		if strings.Contains(out, failed) {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, failed) {
					t.Fatalf("the alert was not delivered: %s", line) // these lines name the host only
				}
			}
		}
	}
}

// The approval of an emergency access, against the same real channel: a real Gateway, Broker,
// Authentication, Authorization and Audit Service. One person asks, with a justification; a second
// one approves. The Broker tells the channel twice, signed, in the teams format, and never the
// justification: that is for a person to read in the channel. The Vault is played: no account is
// read for a notification, and nothing connects.
func TestRealChannel_TheBrokerTellsTeamsOfABreakGlassRequest_AndOfItsApproval(t *testing.T) {
	raw := os.Getenv("NOTIFY_INTEROP_TEAMS_URL")
	if raw == "" {
		t.Skip("NOTIFY_INTEROP_TEAMS_URL not set")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		t.Fatal("NOTIFY_INTEROP_TEAMS_URL is not a URL")
	}
	root := repoRoot(t)
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"audit": "./services/recording-audit/audit-service/cmd/audit-service", "authz": "./services/access/authorization/cmd/authorization",
		"authn": "./services/access/authentication/cmd/authentication", "broker": "./services/access/session-broker/cmd/session-broker",
		"gateway": "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, name+"-74-real")
	}
	audit := startService(t, root, bins["audit"], "18862")
	authz := startService(t, root, bins["authz"], "18863")
	authn := startService(t, root, bins["authn"], "18867", "SKIP_DEMO_SEED=1")
	playVaultAccounts(t, "18861")
	broker := startService(t, root, bins["broker"], "18864",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:18861", "AUDIT_URL="+audit.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18865", "BREAKGLASS_MAX_MINUTES=30",
		"BREAKGLASS_NOTIFY_URL="+raw, "BREAKGLASS_NOTIFY_SECRET="+alertPushSecret, "BREAKGLASS_NOTIFY_FORMAT=teams")
	gateway := startService(t, root, bins["gateway"], "18868", "AUTHENTICATION_URL="+authn.baseURL,
		"SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:18869")

	const acc = "acc_interop_bg_adr0074"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead", "breakglass-approve:account:"+acc, "allow")
	authCreateUser(t, authn.baseURL, "sre-oncall", "On-call SRE", "oncall-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "lead-bob", "Lead", "bob-password-123", []string{"lead"})
	oncall, status := gatewayLogin(t, gateway.baseURL, "sre-oncall", "oncall-password-1")
	if status != http.StatusOK {
		t.Fatalf("login: %d", status)
	}
	bob, status := gatewayLogin(t, gateway.baseURL, "lead-bob", "bob-password-123")
	if status != http.StatusOK {
		t.Fatalf("login: %d", status)
	}

	const reason = "INTEROP-JUSTIFICATION that must not reach the channel"
	st, body, sess := gatewayCreateWith(t, gateway.baseURL, oncall, acc, true, reason, 10)
	if st != http.StatusCreated || sess.Status != "pending_approval" {
		t.Fatalf("request: %d %s", st, body)
	}
	time.Sleep(3 * time.Second) // the two cards in their order, in the channel
	if st, body := gatewayDecide(t, gateway.baseURL, bob, sess.ID, "approve", `{}`); st != http.StatusOK {
		t.Fatalf("approve: %d %s", st, body)
	}

	// The Broker tries once, within 5 s, and says it when it fails.
	time.Sleep(7 * time.Second)
	out := broker.out.String()
	for _, secret := range []string{raw, parsed.RawQuery, parsed.Path, alertPushSecret} {
		if secret != "" && strings.Contains(out, secret) {
			t.Fatal("the Broker's log holds the URL or the secret")
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "not delivered") {
			t.Fatalf("a notification was not delivered: %s", line)
		}
	}
	t.Logf("in the channel, two cards for request %s on %s: asked, then APPROVED; no justification", sess.ID, acc)
}
