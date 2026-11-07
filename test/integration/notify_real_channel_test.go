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
	audit := startMTLSService(t, root, auditBin, "18793", p, mtls.AuditService,
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
