package integration_test

// ADR-0074 against real channels, for each URL given: NOTIFY_INTEROP_TEAMS_URL (teams format) and
// NOTIFY_INTEROP_SLACK_URL (slack format). Real services push to them, signed. A URL is a secret: it
// reaches a process by its environment only, and no log may hold it.
//
// What this proves is the delivery seen from OpenBastion: no refusal, no retry. That the messages
// show in the channel is for a person to look at — a Workflows flow answers 202 before it posts.

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
)

type realChannel struct {
	env, format string
	url         *url.URL
	raw         string
}

// realChannels returns the channels whose URL is set, and skips the test when none is.
func realChannels(t *testing.T) []realChannel {
	t.Helper()
	var out []realChannel
	for _, c := range []realChannel{{env: "NOTIFY_INTEROP_TEAMS_URL", format: "teams"}, {env: "NOTIFY_INTEROP_SLACK_URL", format: "slack"}} {
		raw := os.Getenv(c.env)
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			t.Fatalf("%s is not a URL", c.env) // never the value: it is a secret
		}
		c.raw, c.url = raw, parsed
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Skip("neither NOTIFY_INTEROP_TEAMS_URL nor NOTIFY_INTEROP_SLACK_URL is set")
	}
	return out
}

// mustHaveDelivered fails when the log holds the URL or the secret, or says a delivery failed.
// The log itself is never printed: it would be the leak.
func mustHaveDelivered(t *testing.T, c realChannel, out string, failures ...string) {
	t.Helper()
	for _, secret := range []string{c.raw, c.url.RawQuery, c.url.Path, alertPushSecret} {
		if secret != "" && secret != "/" && strings.Contains(out, secret) {
			t.Fatal("the log holds the URL or the secret")
		}
	}
	for _, line := range strings.Split(out, "\n") {
		for _, failed := range failures {
			if strings.Contains(line, failed) {
				t.Fatalf("not delivered: %s", line) // these lines name the host only
			}
		}
	}
}

func TestRealChannel_TheAuditServicePushesTheVaultsAlert_Signed(t *testing.T) {
	channels := realChannels(t)
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-74-real")
	for i, c := range channels {
		t.Run(c.format, func(t *testing.T) {
			p := newTestPKI(t)
			port := []string{"18860", "18859"}[i]
			audit := startMTLSService(t, root, auditBin, port, p, mtls.AuditService,
				"ALERT_NOTIFY_URL="+c.raw, "ALERT_NOTIFY_SECRET="+alertPushSecret, "ALERT_NOTIFY_FORMAT="+c.format, "ALERT_NOTIFY_RETRY_SECONDS=1")
			// The identity is the certificate's (ADR-0045): only the Vault's alert is pushed.
			status, body := mustCall(t, p.clientAs(t, mtls.PasswordVault), http.MethodPost, audit.baseURL+"/audit/v1/emit-event",
				map[string]any{"action": "vault.rotation_overdue", "resource_type": "account", "resource_id": "acc_interop_adr0074", "success": false})
			if status != http.StatusOK {
				t.Fatalf("emit: %d %s", status, body)
			}
			// A refusal is logged at once and a retry after 1 s: room for both, and for the channel to answer.
			time.Sleep(8 * time.Second)
			out := audit.out.String()
			if !strings.Contains(out, "alerts use the "+c.format+" format") || !strings.Contains(out, "signed (") {
				t.Fatalf("the Audit Service does not say it pushes signed alerts in the %s format", c.format)
			}
			mustHaveDelivered(t, c, out, "not delivered", "given up", "not pushed")
		})
	}
}

// The Broker against the same real channels: a real Gateway, Broker, Vault, Authentication,
// Authorization and Audit Service; nothing connects to a target. Four messages, in this order:
// an emergency access asked with a justification, then approved by a second person; an ordinary
// access asked with a ticket (ADR-0067), then approved by another person. The ticket is in the
// messages, by design; the justification is in none — that is for a person to read in the channel.
func TestRealChannel_TheBrokerTellsOfABreakGlassAndOfAnAccessWithATicket_AndOfTheirApproval(t *testing.T) {
	channels := realChannels(t)
	root := repoRoot(t)
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"vault": "./services/vault/password-vault/cmd/password-vault", "audit": "./services/recording-audit/audit-service/cmd/audit-service",
		"authz": "./services/access/authorization/cmd/authorization", "authn": "./services/access/authentication/cmd/authentication",
		"broker": "./services/access/session-broker/cmd/session-broker", "gateway": "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, name+"-74-real")
	}
	for i, c := range channels {
		t.Run(c.format, func(t *testing.T) {
			port := func(n int) string { return []string{"1887", "1888"}[i] + string(rune('0'+n)) }
			audit := startService(t, root, bins["audit"], port(2))
			authz := startService(t, root, bins["authz"], port(3))
			vault := startService(t, root, bins["vault"], port(1), "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
			authn := startService(t, root, bins["authn"], port(7), "SKIP_DEMO_SEED=1")
			broker := startService(t, root, bins["broker"], port(4),
				"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL, "AUDIT_URL="+audit.baseURL,
				"SSH_PROXY_URL=http://127.0.0.1:"+port(5), "BREAKGLASS_MAX_MINUTES=30", "APPROVAL_TICKET_PATTERN=(INC|CHG)[0-9]{7}",
				"BREAKGLASS_NOTIFY_URL="+c.raw, "BREAKGLASS_NOTIFY_SECRET="+alertPushSecret, "BREAKGLASS_NOTIFY_FORMAT="+c.format)
			gateway := startService(t, root, bins["gateway"], port(8), "AUTHENTICATION_URL="+authn.baseURL,
				"SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:"+port(9),
				"VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL, "CLIENT_LOGIN_BURST=100")

			const bg, gated = "acc_interop_bg_adr0074", "acc_interop_ticket_adr0074"
			authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
			for _, acc := range []string{bg, gated} {
				onboardAccountFull(t, vault.baseURL, acc, acc, "root", "10.0.0.9:22", "interop-target-secret", []string{"vault-admin"})
				authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
			}
			authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+bg, "allow")
			authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead", "breakglass-approve:account:"+bg, "allow")
			authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead", "session-approve:account:"+gated, "allow")
			authCreateUser(t, authn.baseURL, "admin", "Admin", "admin-password-123", []string{"vault-admin"})
			authCreateUser(t, authn.baseURL, "sre-oncall", "On-call SRE", "oncall-password-1", []string{"sre"})
			authCreateUser(t, authn.baseURL, "lead-bob", "Lead", "bob-password-123", []string{"lead"})
			login := func(user, pw string) string {
				tok, status := gatewayLogin(t, gateway.baseURL, user, pw)
				if status != http.StatusOK {
					t.Fatalf("login %s: %d", user, status)
				}
				return tok
			}
			admin, oncall, bob := login("admin", "admin-password-123"), login("sre-oncall", "oncall-password-1"), login("lead-bob", "bob-password-123")
			if st, body := gatewaySetApproval(t, gateway.baseURL, admin, gated, `{"approvalRequired":true}`); st != http.StatusOK {
				t.Fatalf("set approval: %d %s", st, body)
			}
			approve := func(id string) {
				t.Helper()
				if st, body := gatewayDecide(t, gateway.baseURL, bob, id, "approve", `{}`); st != http.StatusOK {
					t.Fatalf("approve %s: %d %s", id, st, body)
				}
			}
			const pause = 3 * time.Second // the messages in their order, in the channel

			st, body, emergency := gatewayCreateWith(t, gateway.baseURL, oncall, bg, true, "INTEROP-JUSTIFICATION that must not reach the channel", 10)
			if st != http.StatusCreated || emergency.Status != "pending_approval" {
				t.Fatalf("break-glass request: %d %s", st, body)
			}
			time.Sleep(pause)
			approve(emergency.ID)
			time.Sleep(pause)
			st, asked, raw := gatewayAsk(t, gateway.baseURL, oncall, gated, "CHG0074001")
			if st != http.StatusCreated || asked["status"] != "pending_approval" {
				t.Fatalf("access request: %d %s", st, raw)
			}
			access, _ := asked["id"].(string)
			time.Sleep(pause)
			approve(access)

			time.Sleep(7 * time.Second) // the Broker tries once, within 5 s, and says it when it fails
			mustHaveDelivered(t, c, broker.out.String(), "not delivered")
			t.Logf("%s: four messages — break-glass %s asked then APPROVED; access %s with ticket CHG0074001 asked then APPROVED; no justification",
				c.format, emergency.ID, access)
		})
	}
}
