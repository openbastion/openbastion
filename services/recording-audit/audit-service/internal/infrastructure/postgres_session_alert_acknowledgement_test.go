package infrastructure_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func insertPostgresSessionAlert(t *testing.T, db *sql.DB, svc *application.AuditService, sessionID string) string {
	t.Helper()
	ctx := context.Background()
	source, err := svc.EmitEventAs(ctx, "session-broker", "requester-ack-test", "session.connect", "session", sessionID, true)
	if err != nil {
		t.Fatalf("append source audit event: %v", err)
	}
	alertID := fmt.Sprintf("alert_%032x", time.Now().UnixNano())
	_, err = db.ExecContext(ctx, `INSERT INTO session_alerts (id, rule_id, rule_version, source_event_id, session_id, severity, status, summary, detected_at, created_at, revision) VALUES ($1,$2,'v1',$3,$4,'high','unacknowledged','acknowledgement integration test',$5,$5,1)`, alertID, uniqueID("rule-ack"), source.ID, sessionID, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatalf("insert session alert fixture: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM session_alerts WHERE id = $1`, alertID) })
	return alertID
}

func TestPostgresSessionAlertAcknowledgementCommitsProjectionAndChainTogether(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db)
	svc := application.NewAuditService(store)
	sessionID := uniqueID("session-alert-ack-pg")
	alertID := insertPostgresSessionAlert(t, db, svc, sessionID)

	before, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeCount := int64(0)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&beforeCount); err != nil {
		t.Fatal(err)
	}
	ack, already, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-pg", alertID, 1)
	if err != nil || already {
		t.Fatalf("acknowledge = %+v already=%v err=%v", ack, already, err)
	}
	if ack.Status != domain.AlertStatusAcknowledged || ack.Revision != 2 || ack.AcknowledgedBy != "auditor-pg" || ack.AcknowledgementEventID == "" {
		t.Fatalf("acknowledged row = %+v", ack)
	}
	var eventAction, eventActor, eventResource string
	if err := db.QueryRowContext(ctx, `SELECT action, actor_id, resource_id FROM audit_events WHERE id = $1`, ack.AcknowledgementEventID).Scan(&eventAction, &eventActor, &eventResource); err != nil {
		t.Fatal(err)
	}
	if eventAction != "session.alert.acknowledged" || eventActor != "auditor-pg" || eventResource != alertID {
		t.Fatalf("event = action %q actor %q resource %q", eventAction, eventActor, eventResource)
	}
	var afterCount int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&afterCount); err != nil {
		t.Fatal(err)
	}
	if afterCount != beforeCount+1 {
		t.Fatalf("audit event count %d -> %d, want exactly one", beforeCount, afterCount)
	}
	last, err := store.Last(ctx)
	if err != nil || last == nil || last.ID != ack.AcknowledgementEventID || string(last.PrevHash) != string(before.Hash) {
		t.Fatalf("chain tail = %+v, previous=%+v, err=%v", last, before, err)
	}

	retry, already, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-pg", alertID, 1)
	if err != nil || !already || retry.AcknowledgementEventID != ack.AcknowledgementEventID {
		t.Fatalf("retry = %+v already=%v err=%v", retry, already, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&afterCount); err != nil {
		t.Fatal(err)
	}
	if afterCount != beforeCount+1 {
		t.Fatalf("idempotent retry appended an event; count=%d", afterCount)
	}
}

func TestPostgresSessionAlertAcknowledgement_RollsBackChainWhenProjectionUpdateFails(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db)
	svc := application.NewAuditService(store)
	sessionID := uniqueID("session-alert-ack-rollback")
	alertID := insertPostgresSessionAlert(t, db, svc, sessionID)

	functionName := fmt.Sprintf("fail_ack_%d", time.Now().UnixNano())
	triggerName := fmt.Sprintf("fail_ack_trigger_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`CREATE FUNCTION public.%s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced acknowledgement update failure'; END; $$`, functionName)); err != nil {
		t.Fatalf("create isolated rollback trigger function: %v", err)
	}
	defer db.ExecContext(ctx, fmt.Sprintf(`DROP FUNCTION IF EXISTS public.%s()`, functionName))
	defer db.ExecContext(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON session_alerts`, triggerName))
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE UPDATE ON session_alerts FOR EACH ROW WHEN (OLD.id = '%s') EXECUTE FUNCTION public.%s()`, triggerName, alertID, functionName)); err != nil {
		t.Fatal(err)
	}

	var before int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-rollback", alertID, 1); err == nil {
		t.Fatal("acknowledgement succeeded despite forced projection failure")
	}
	var after int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("audit event append escaped rollback: %d -> %d", before, after)
	}
	var status string
	var revision int64
	if err := db.QueryRowContext(ctx, `SELECT status, revision FROM session_alerts WHERE id = $1`, alertID).Scan(&status, &revision); err != nil {
		t.Fatal(err)
	}
	if status != domain.AlertStatusUnacknowledged || revision != 1 {
		t.Fatalf("projection after rollback = %s revision %d", status, revision)
	}
}

func TestPostgresSessionAlertAcknowledgement_ConcurrentProcessesAppendOneEvent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db)
	keys := application.RandomChainKeys()
	services := []*application.AuditService{application.NewAuditService(store).WithChainKeys(keys), application.NewAuditService(store).WithChainKeys(keys)}
	sessionID := uniqueID("session-alert-ack-concurrent")
	alertID := insertPostgresSessionAlert(t, db, services[0], sessionID)
	var before int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, len(services))
	for _, svc := range services {
		wg.Add(1)
		go func(svc *application.AuditService) {
			defer wg.Done()
			<-start
			_, _, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-concurrent", alertID, 1)
			errs <- err
		}(svc)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent process acknowledgement: %v", err)
		}
	}
	var after int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("concurrent services appended %d events, want exactly one", after-before)
	}
	var revision int64
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status, revision FROM session_alerts WHERE id = $1`, alertID).Scan(&status, &revision); err != nil {
		t.Fatal(err)
	}
	if status != domain.AlertStatusAcknowledged || revision != 2 {
		t.Fatalf("concurrent result = %s revision %d", status, revision)
	}
}
