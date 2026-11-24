package infrastructure_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func TestPostgresSessionAlertReadsUseBoundedKeysetAndOneSummarySnapshot(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	var sourceID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&sourceID); err != nil {
		t.Skipf("no retained source event available for projection read test: %v", err)
	}
	before, err := store.SessionAlertCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uniqueID("session-alert-read")
	ids := make([]string, 3)
	at := time.Now().UTC().Truncate(time.Microsecond)
	for i := range ids {
		ids[i] = fmt.Sprintf("alert_%032x", time.Now().UnixNano()+int64(i))
		_, err := db.ExecContext(ctx, `INSERT INTO session_alerts (id, rule_id, rule_version, source_event_id, session_id, severity, status, summary, detected_at, created_at, revision) VALUES ($1,$2,'v1',$3,$4,'high','unacknowledged','test alert',$5,$5,1)`, ids[i], uniqueID("rule"), sourceID, sessionID, at.Add(time.Duration(i)*time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	defer db.ExecContext(ctx, `DELETE FROM session_alerts WHERE session_id = $1`, sessionID)

	page, err := store.ListSessionAlerts(ctx, domain.SessionAlertFilter{SessionID: sessionID, Status: domain.AlertStatusUnacknowledged, Severity: "high", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 3 || page[0].DetectedAt.Before(page[1].DetectedAt) || page[1].DetectedAt.Before(page[2].DetectedAt) {
		t.Fatalf("unexpected keyset order: %+v", page)
	}
	got, err := store.GetSessionAlert(ctx, ids[0])
	if err != nil || got == nil || got.ID != ids[0] {
		t.Fatalf("GetSessionAlert = %+v, %v", got, err)
	}

	after, err := store.SessionAlertCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.UnacknowledgedCount != before.UnacknowledgedCount+3 || after.BySeverity[domain.AlertHigh] != before.BySeverity[domain.AlertHigh]+3 {
		t.Fatalf("summary delta = %+v, before %+v; want +3 unacknowledged high", after, before)
	}
	if !store.SessionAlertsDurable() {
		t.Fatal("PostgreSQL projection must report durable=true")
	}
}
