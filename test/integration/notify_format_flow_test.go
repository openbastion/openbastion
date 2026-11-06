package integration_test

// ADR-0074, on real processes: what a chat format receives, what is refused at startup, and that a
// dead channel still delays nothing. A real Slack and a real Teams are pkg/webhook's
// TestRealChannel, with URLs that are never written here.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

const notifyFormatURL = "https://hooks.example.com/services/s3cr3t-path"

func TestNotifyFormat_AValueThatIsNotAFormatStopsTheService_WithoutRepeatingTheURL(t *testing.T) {
	root := repoRoot(t)
	broker := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "broker-74")
	audit := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-74")
	for _, c := range []struct {
		name, bin, variable string
		env                 []string
	}{
		{"Broker, unknown", broker, "BREAKGLASS_NOTIFY_FORMAT", []string{"BREAKGLASS_NOTIFY_URL=" + notifyFormatURL, "BREAKGLASS_NOTIFY_FORMAT=mattermost"}},
		{"Broker, no channel", broker, "BREAKGLASS_NOTIFY_FORMAT", []string{"BREAKGLASS_NOTIFY_FORMAT=slack"}},
		{"Audit, unknown", audit, "ALERT_NOTIFY_FORMAT", []string{"ALERT_NOTIFY_URL=" + notifyFormatURL, "ALERT_NOTIFY_SECRET=" + alertPushSecret, "ALERT_NOTIFY_FORMAT=Teams"}},
		{"Audit, no channel", audit, "ALERT_NOTIFY_FORMAT", []string{"ALERT_NOTIFY_FORMAT=teams"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := runUntilExit(t, root, c.bin, append([]string{"PORT=18774"}, c.env...)...)
			if !strings.Contains(out, c.variable) {
				t.Fatalf("the refusal does not name %s:\n%s", c.variable, out)
			}
			if strings.Contains(out, "s3cr3t-path") || strings.Contains(out, alertPushSecret) {
				t.Fatalf("the refusal repeats a secret:\n%s", out)
			}
		})
	}
}

func TestNotifyFormat_AnAlertReachesTeamsAsACard_AcrossARealProcess(t *testing.T) {
	root := repoRoot(t)
	hook := newHookSpy(t)
	audit := startService(t, root, buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-74b"), "18775",
		"ALERT_NOTIFY_URL="+hook.srv.URL+"/hooks/s3cr3t-path", "ALERT_NOTIFY_SECRET="+alertPushSecret, "ALERT_NOTIFY_FORMAT=teams")
	if err := (&httpAuditEmitter{baseURL: audit.baseURL}).EmitEvent(context.Background(), "vault.rotation_overdue", "account", "<!channel>[x](http://evil.example)", false); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "the alert to be delivered", func() bool { return len(hook.deliveries("", "")) > 0 })
	d := hook.deliveries("", "")[0]
	if d.Body["type"] != "message" || !strings.Contains(d.Raw, "application/vnd.microsoft.card.adaptive") || !strings.Contains(d.Raw, "OpenBastion alert") {
		t.Fatalf("not a card: %s", d.Raw)
	}
	for _, forbidden := range []string{"<!", "](", "http://", "resourceId", "eventId"} {
		if strings.Contains(d.Raw, forbidden) {
			t.Fatalf("%q is in the message: %s", forbidden, d.Raw)
		}
	}
	if d.Signature == "" {
		t.Fatal("the channel of alerts stays signed")
	}
	if strings.Contains(audit.out.String(), "s3cr3t-path") {
		t.Fatal("the URL is in the log")
	}
}

func TestNotifyFormat_ARequestReachesSlackAsAPhrase_AndADeadChannelDelaysNothing(t *testing.T) {
	root := repoRoot(t)
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"vault": "./services/vault/password-vault/cmd/password-vault", "audit": "./services/recording-audit/audit-service/cmd/audit-service",
		"authz": "./services/access/authorization/cmd/authorization", "authn": "./services/access/authentication/cmd/authentication",
		"broker": "./services/access/session-broker/cmd/session-broker", "proxy": "./services/proxy/ssh-proxy/cmd/ssh-proxy",
		"recorder": "./services/recording-audit/command-recorder/cmd/command-recorder", "gateway": "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, name+"-74")
	}
	hook := newHookSpy(t)
	audit := startService(t, root, bins["audit"], "18782")
	vault := startService(t, root, bins["vault"], "18781", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18783", "AUDIT_URL="+audit.baseURL)
	authz := startService(t, root, bins["authz"], "18783")
	authn := startService(t, root, bins["authn"], "18787", "SKIP_DEMO_SEED=1")
	startService(t, root, bins["recorder"], "18789", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	startServiceWithExtraPort(t, root, bins["proxy"], "18785", "18786", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+audit.baseURL,
		"PROXY_SERVICE_ID=ssh-proxy", "RECORDER_URL=http://127.0.0.1:18789", "RECORDING_POLICY=required")
	broker := startService(t, root, bins["broker"], "18784", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL=http://127.0.0.1:18785",
		"BREAKGLASS_NOTIFY_URL="+hook.srv.URL+"/hook", "BREAKGLASS_NOTIFY_FORMAT=slack")
	gateway := startService(t, root, bins["gateway"], "18788", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:18789", "VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL, "CLIENT_LOGIN_BURST=100")

	const accountID = "acc_notify"
	targetAddr := startObservedInteractiveTargetSSHServer(t, "notify-target-secret", func(string) {})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "notify-account", "root", targetAddr, "notify-target-secret", []string{"vault-admin"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authCreateUser(t, authn.baseURL, "admin", "Admin", "admin-password-123", []string{"vault-admin"})
	authCreateUser(t, authn.baseURL, "dba-alice", "Alice", "alice-password-1", []string{"dba"})
	admin, status := gatewayLogin(t, gateway.baseURL, "admin", "admin-password-123")
	if status != http.StatusOK {
		t.Fatalf("login: %d", status)
	}
	alice, status := gatewayLogin(t, gateway.baseURL, "dba-alice", "alice-password-1")
	if status != http.StatusOK {
		t.Fatalf("login: %d", status)
	}
	if st, body := gatewaySetApproval(t, gateway.baseURL, admin, accountID, `{"approvalRequired":true}`); st != http.StatusOK {
		t.Fatalf("set approval: %d %s", st, body)
	}

	st, out, raw := gatewayAsk(t, gateway.baseURL, alice, accountID, "CHG0001234")
	if st != http.StatusCreated || out["status"] != "pending_approval" {
		t.Fatalf("request: %d %s", st, raw)
	}
	waitUntil(t, 5*time.Second, "the request to be told", func() bool { return len(hook.deliveries("", "")) > 0 })
	d := hook.deliveries("", "")[0]
	text, _ := d.Body["text"].(string)
	if len(d.Body) != 1 || !strings.Contains(text, "OpenBastion access request") || !strings.Contains(text, accountID) || !strings.Contains(text, "CHG0001234") {
		t.Fatalf("not the phrase alone: %s", d.Raw)
	}
	if strings.Contains(d.Raw, "apply the change") {
		t.Fatalf("the justification left: %s", d.Raw)
	}

	// The channel stops answering: the delivery has 5 s, and a request does not wait for it.
	hook.mode.Store(hookHangs)
	start := time.Now()
	st, out, raw = gatewayAsk(t, gateway.baseURL, alice, accountID, "CHG0001235")
	if st != http.StatusCreated || out["status"] != "pending_approval" {
		t.Fatalf("a dead channel refused a request: %d %s", st, raw)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("a dead channel delayed a request by %s", took)
	}
}
