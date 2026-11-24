package integration_test

import (
	"database/sql"
	"testing"
)

// truncateAuditEvents clears the signed chain and any alert-detection tables already
// installed. Some integration tests intentionally run against a fresh database before
// the Audit Service has applied all migrations.
func truncateAuditEvents(t *testing.T, db *sql.DB) {
	t.Helper()
	var auditEventsExists, detectionOutboxExists, sessionAlertsExists bool
	if err := db.QueryRow(`SELECT to_regclass('public.audit_events') IS NOT NULL, to_regclass('public.session_alert_detection_outbox') IS NOT NULL, to_regclass('public.session_alerts') IS NOT NULL`).Scan(&auditEventsExists, &detectionOutboxExists, &sessionAlertsExists); err != nil {
		t.Fatalf("checking audit schema: %v", err)
	}
	if !auditEventsExists {
		return // a fresh database has nothing to reset; the test's service installs the schema
	}
	query := `TRUNCATE audit_events RESTART IDENTITY`
	switch {
	case detectionOutboxExists && sessionAlertsExists:
		query = `TRUNCATE session_alerts, session_alert_detection_outbox, audit_events RESTART IDENTITY`
	case detectionOutboxExists:
		query = `TRUNCATE session_alert_detection_outbox, audit_events RESTART IDENTITY`
	case sessionAlertsExists:
		query = `TRUNCATE session_alerts, audit_events RESTART IDENTITY`
	}
	if _, err := db.Exec(query); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}
