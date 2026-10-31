package integration_test

// ADR-0045 across a real Audit Service under mutual TLS: an alert written by the Vault is pushed,
// signed, to the declared URL, retried when the receiver fails, and never holds up the write; the
// same alert written by another service is in the chain and is not pushed; and a channel that is
// not configured whole stops the service, without its URL or its secret in the message.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
)

const alertPushSecret = "integration-alert-secret-0123456789abcdef"

type alertDelivery struct {
	at        time.Time
	timestamp string
	signature string
	body      []byte
}

func TestAlertPush_TheVaultsAlertIsPushedSigned_AndRetried_AnotherServicesIsNot(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-45")

	t.Run("a channel that is not configured whole stops the service, repeating neither its URL nor its secret", func(t *testing.T) {
		short := "short-s3cr3t-value"
		for _, c := range []struct {
			env  []string
			name string
		}{
			{[]string{"ALERT_NOTIFY_URL=https://alerts.example/hooks/s3cr3t-path"}, "ALERT_NOTIFY_SECRET"},
			{[]string{"ALERT_NOTIFY_SECRET=" + alertPushSecret}, "ALERT_NOTIFY_URL"},
			{[]string{"ALERT_NOTIFY_RETRY_SECONDS=5"}, "ALERT_NOTIFY_URL"},
			{[]string{"ALERT_NOTIFY_URL=http://alerts.example/hooks/s3cr3t-path", "ALERT_NOTIFY_SECRET=" + alertPushSecret}, "ALERT_NOTIFY_URL"},
			{[]string{"ALERT_NOTIFY_URL=https://alerts.example/hooks/s3cr3t-path", "ALERT_NOTIFY_SECRET=" + short}, "ALERT_NOTIFY_SECRET"},
			{[]string{"ALERT_NOTIFY_URL=https://alerts.example/hooks/s3cr3t-path", "ALERT_NOTIFY_SECRET=" + alertPushSecret, "ALERT_NOTIFY_RETRY_SECONDS=0"}, "ALERT_NOTIFY_RETRY_SECONDS"},
			{[]string{"ALERT_NOTIFY_URL=https://alerts.example/hooks/s3cr3t-path", "ALERT_NOTIFY_SECRET=" + alertPushSecret, "ALERT_NOTIFY_RETRY_SECONDS=601"}, "ALERT_NOTIFY_RETRY_SECONDS"},
		} {
			out := runUntilExit(t, root, auditBin, append([]string{"PORT=18491", "INTERNAL_TLS=disabled"}, c.env...)...)
			if !strings.Contains(out, c.name) {
				t.Fatalf("%v: the refusal does not name %s:\n%s", c.env, c.name, out)
			}
			if strings.Contains(out, "s3cr3t") || strings.Contains(out, alertPushSecret) {
				t.Fatalf("%v: the refusal repeats the URL or the secret:\n%s", c.env, out)
			}
		}
	})

	// The receiver: the first delivery is answered late, and with a 503; every later one, 200.
	var mu sync.Mutex
	var got []alertDelivery
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		n := len(got)
		got = append(got, alertDelivery{at: time.Now(), timestamp: r.Header.Get("X-OpenBastion-Timestamp"), signature: r.Header.Get("X-OpenBastion-Signature"), body: body})
		mu.Unlock()
		if r.URL.Path != "/hooks/s3cr3t-path" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if n == 0 {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer recv.Close()

	p := newTestPKI(t)
	audit := startMTLSService(t, root, auditBin, "18492", p, mtls.AuditService,
		"ALERT_NOTIFY_URL="+recv.URL+"/hooks/s3cr3t-path", "ALERT_NOTIFY_SECRET="+alertPushSecret, "ALERT_NOTIFY_RETRY_SECONDS=1")
	emit := func(as, action, resourceID string, success bool) string {
		t.Helper()
		start := time.Now()
		status, raw := mustCall(t, p.clientAs(t, as), http.MethodPost, audit.baseURL+"/audit/v1/emit-event",
			map[string]any{"action": action, "resource_type": "account", "resource_id": resourceID, "success": success})
		if status != http.StatusOK {
			t.Fatalf("emit %s as %s: %d %s", action, as, status, raw)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("emit %s as %s took %s: the write waited for the channel", action, as, d)
		}
		var r struct {
			EventID string `json:"event_id"`
		}
		_ = json.Unmarshal([]byte(raw), &r)
		return r.EventID
	}

	forged := emit(mtls.SessionBroker, "vault.rotation_overdue", "acc_forged", false)
	_ = emit(mtls.PasswordVault, "vault.rotate", "acc_fine", true)
	overdueID := emit(mtls.PasswordVault, "vault.rotation_overdue", "acc_real", false)
	// A second write right behind the first: it does not wait for the slow receiver either.
	_ = emit(mtls.PasswordVault, "vault.rotate", "acc_fine", true)

	t.Run("the Vault's alert is pushed, signed, and retried after a 503 until it is delivered", func(t *testing.T) {
		waitUntil(t, 15*time.Second, "a second delivery", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(got) >= 2
		})
		time.Sleep(1500 * time.Millisecond) // room for anything else that would be pushed
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 2 {
			t.Fatalf("%d deliveries, want 2 (one 503, one 200) for the one alert", len(got))
		}
		for i, d := range got {
			mac := hmac.New(sha256.New, []byte(alertPushSecret))
			mac.Write([]byte(d.timestamp + "."))
			mac.Write(d.body)
			if want := "v1=" + hex.EncodeToString(mac.Sum(nil)); d.signature != want {
				t.Fatalf("delivery %d: signature %q, want %q", i+1, d.signature, want)
			}
			var m map[string]any
			if err := json.Unmarshal(d.body, &m); err != nil {
				t.Fatal(err)
			}
			if m["eventId"] != overdueID || m["event"] != "vault.rotation_overdue" || m["emitter"] != mtls.PasswordVault || m["resourceId"] != "acc_real" {
				t.Fatalf("delivery %d is not the Vault's alert %s: %v", i+1, overdueID, m)
			}
		}
		if gap := got[1].at.Sub(got[0].at); gap < time.Second {
			t.Fatalf("the retry came %s after the failure, want at least ALERT_NOTIFY_RETRY_SECONDS=1", gap)
		}
	})

	t.Run("the same alert written by the Broker is in the chain, and is not pushed", func(t *testing.T) {
		mu.Lock()
		for _, d := range got {
			if strings.Contains(string(d.body), forged) || strings.Contains(string(d.body), "acc_forged") {
				mu.Unlock()
				t.Fatalf("the Broker's vault.rotation_overdue was pushed: %s", d.body)
			}
		}
		mu.Unlock()
		status, raw := mustCall(t, p.clientAs(t, mtls.AdminCLI), http.MethodGet, audit.baseURL+"/audit/v1/verify-chain", nil)
		if status != http.StatusOK {
			t.Fatalf("verify-chain: %d %s", status, raw)
		}
	})

	t.Run("the log says where, never the URL nor the secret", func(t *testing.T) {
		out := audit.out.String()
		if strings.Contains(out, "s3cr3t-path") || strings.Contains(out, alertPushSecret) {
			t.Fatalf("the log holds the URL or the secret:\n%s", out)
		}
		if !strings.Contains(out, "vault.rotation_overdue from password-vault") || !strings.Contains(out, "attempt 2 of 5") {
			t.Fatalf("the log does not say what is pushed and what was retried:\n%s", out)
		}
	})
}

func TestAlertPush_WithoutInternalTLSNoEmitterIsNamed_AndTheAlertIsPushed_AndTheServiceSaysSo(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-45")
	var mu sync.Mutex
	var bodies []string
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer recv.Close()
	audit := startService(t, root, auditBin, "18493", "INTERNAL_TLS=disabled",
		"ALERT_NOTIFY_URL="+recv.URL+"/hook", "ALERT_NOTIFY_SECRET="+alertPushSecret)
	if s := postJSON(t, audit.baseURL+"/audit/v1/emit-event", map[string]any{"action": "vault.rotation_overdue", "resource_type": "account", "resource_id": "acc_dev"}); s != http.StatusOK {
		t.Fatalf("emit: %d", s)
	}
	waitUntil(t, 10*time.Second, "the delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(bodies) == 1 && strings.Contains(bodies[0], `"resourceId":"acc_dev"`) && strings.Contains(bodies[0], `"emitter":""`)
	})
	if !strings.Contains(audit.out.String(), "no emitter is named") {
		t.Fatalf("the service does not say that any writer's alert is pushed:\n%s", audit.out.String())
	}
}
