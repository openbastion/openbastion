package integration_test

// ADR-0116 §3 across two real processes: a Session Broker on PostgreSQL that changes a session's row
// moves its head in the Audit Service, and the head's digest is the SHA-256 of the row's canonical
// form as this package computes it on its own (session_metadata_sign_test.go).

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestPostgresFlow_AChangeOfASessionMovesItsHeadInTheAuditService(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	root := repoRoot(t)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-0116")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-0116")
	unreachable := "http://127.0.0.1:1"
	audit := startService(t, root, auditBin, "19951")
	// Started once to migrate the table, then the row is written signed, past its end.
	broker := startService(t, root, brokerBin, "19952", "DATABASE_URL="+dsn, "AUTHORIZATION_URL="+unreachable,
		"AUDIT_URL="+audit.baseURL, "VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable, "SESSION_EXPIRY_SWEEP_SECONDS=1")
	stopService(t, broker)
	end := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	row := signedSessionRow{ID: fmt.Sprintf("session_head_%d", time.Now().UnixNano()), Status: "active", Protocol: "ssh",
		RequestedBy: "user_a", Account: "acc_1", Justification: "ADR-0116 head", CreatedAt: end.Add(-time.Hour), ExpiresAt: end}
	insertSignedSession(t, db, row)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM sessions WHERE id = $1`, row.ID) })
	startService(t, root, brokerBin, "19952", "DATABASE_URL="+dsn, "AUTHORIZATION_URL="+unreachable,
		"AUDIT_URL="+audit.baseURL, "VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable, "SESSION_EXPIRY_SWEEP_SECONDS=1")

	// The sweep expires it: revision 2, an active session that ended owing the Vault its end.
	expired := row
	expired.Status, expired.AfterUseOwed = "expired", true
	want := sha256.Sum256(sessionMetadataCanonical(expired))
	var head struct {
		Revision       uint64 `json:"revision"`
		MetadataSHA256 string `json:"metadata_sha256"`
		KeyID          string `json:"key_id"`
	}
	waitUntil(t, 15*time.Second, "the head at the expiry's revision", func() bool {
		resp, err := http.Get(audit.baseURL + "/audit/v1/session-metadata/head?session_id=" + row.ID)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&head) == nil && head.Revision == 2
	})
	if head.MetadataSHA256 != hex.EncodeToString(want[:]) || head.KeyID != "k1" {
		t.Fatalf("the head %+v, want digest %x under k1", head, want)
	}
	var revision int64
	_ = db.QueryRow(`SELECT metadata_revision FROM sessions WHERE id = $1`, row.ID).Scan(&revision)
	if revision != 2 {
		t.Fatalf("the row at revision %d, want 2", revision)
	}
}
