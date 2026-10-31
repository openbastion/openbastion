package integration_test

// ADR-0057 across real processes and a real PostgreSQL: an alert that waits for a retry when the
// Audit Service is killed is delivered by the next Audit Service, once, signed.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPostgresFlow_AnAlertWaitingForARetryIsDeliveredAfterTheAuditServiceRestarts(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("TRUNCATE audit_events RESTART IDENTITY"); err != nil { // the same reason as the chain restart test
		t.Fatal(err)
	}

	// The receiver is down (503) until up is set.
	var mu sync.Mutex
	var up bool
	var got []alertDelivery
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		got = append(got, alertDelivery{at: time.Now(), timestamp: r.Header.Get("X-OpenBastion-Timestamp"), signature: r.Header.Get("X-OpenBastion-Signature"), body: body})
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer recv.Close()
	deliveries := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }

	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-57")
	env := []string{"DATABASE_URL=" + dsn, "AUDIT_CHAIN_KEY_HEX=" + testKMSKeyHex(t), "AUDIT_ANCHOR_FILE=" + t.TempDir() + "/anchors.jsonl",
		"ALERT_NOTIFY_URL=" + recv.URL + "/hooks/s3cr3t-path", "ALERT_NOTIFY_SECRET=" + alertPushSecret, "ALERT_NOTIFY_RETRY_SECONDS=3"}

	audit1 := startService(t, root, auditBin, "18571", env...)
	// The queue is emptied once the first process has made sure it exists (its migrations).
	if _, err := db.Exec("DELETE FROM alert_outbox"); err != nil {
		t.Fatal(err)
	}
	if err := (&httpAuditEmitter{baseURL: audit1.baseURL}).EmitEvent(context.Background(), "vault.rotation_overdue", "account", "acc_restart", false); err != nil {
		t.Fatal(err)
	}
	// The first attempt fails; the retry is due in 3 s — and the Audit Service is killed before it.
	waitUntil(t, 10*time.Second, "the first attempt answered 503", func() bool { return strings.Contains(audit1.out.String(), "attempt 2 of 5 in 3s") })
	stopService(t, audit1)
	n := deliveries()
	mu.Lock()
	up = true
	firstBody := string(got[0].body)
	mu.Unlock()

	audit2 := startService(t, root, auditBin, "18572", env...)
	t.Run("the next Audit Service delivers it, signed, once", func(t *testing.T) {
		waitUntil(t, 15*time.Second, "the alert delivered after the restart", func() bool { return deliveries() > n })
		time.Sleep(4 * time.Second) // room for a second delivery, which must not come
		mu.Lock()
		defer mu.Unlock()
		if len(got) != n+1 {
			t.Fatalf("%d deliveries after the restart, want 1", len(got)-n)
		}
		d := got[n]
		if string(d.body) != firstBody {
			t.Fatalf("delivered after the restart %s, want the alert that waited %s", d.body, firstBody)
		}
		var m map[string]any
		if err := json.Unmarshal(d.body, &m); err != nil || m["event"] != "vault.rotation_overdue" || m["resourceId"] != "acc_restart" {
			t.Fatalf("not the alert that waited: %s (%v)", d.body, err)
		}
		mac := hmac.New(sha256.New, []byte(alertPushSecret))
		mac.Write([]byte(d.timestamp + "."))
		mac.Write(d.body)
		if want := "v1=" + hex.EncodeToString(mac.Sum(nil)); d.signature != want {
			t.Fatalf("signature %q, want %q", d.signature, want)
		}
	})

	t.Run("the queue is empty once it is delivered, and the log says where the alerts wait, never the URL", func(t *testing.T) {
		var left int
		if err := db.QueryRow("SELECT count(*) FROM alert_outbox").Scan(&left); err != nil || left != 0 {
			t.Fatalf("alert_outbox holds %d rows (%v), want 0", left, err)
		}
		out := audit2.out.String()
		if !strings.Contains(out, "kept in alert_outbox: a restart delivers them") {
			t.Fatalf("the log does not say where the alerts wait:\n%s", out)
		}
		if strings.Contains(out, "s3cr3t-path") || strings.Contains(out, alertPushSecret) {
			t.Fatalf("the log holds the URL or the secret:\n%s", out)
		}
	})
}
