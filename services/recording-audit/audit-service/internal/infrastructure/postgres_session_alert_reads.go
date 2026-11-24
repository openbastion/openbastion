package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

func (s *PostgresStore) ListSessionAlerts(ctx context.Context, filter domain.SessionAlertFilter) ([]domain.SessionAlert, error) {
	query := `SELECT id, rule_id, rule_version, source_event_id, session_id, severity, status, summary, detected_at, created_at, revision, acknowledged_at, acknowledged_by, acknowledgement_event_id FROM session_alerts WHERE 1=1`
	args := make([]any, 0, 8)
	add := func(clause string, value any) {
		args = append(args, value)
		query += " AND " + strings.ReplaceAll(clause, "?", "$"+strconv.Itoa(len(args)))
	}
	if filter.Status != "" {
		add("status = ?", filter.Status)
	}
	if filter.Severity != "" {
		add("severity = ?", filter.Severity)
	}
	if filter.SessionID != "" {
		add("session_id = ?", filter.SessionID)
	}
	if filter.Since != nil {
		add("detected_at >= ?", *filter.Since)
	}
	if filter.Until != nil {
		add("detected_at <= ?", *filter.Until)
	}
	if filter.BeforeDetectedAt != nil {
		args = append(args, *filter.BeforeDetectedAt, filter.BeforeID)
		query += " AND (detected_at < $" + strconv.Itoa(len(args)-1) + " OR (detected_at = $" + strconv.Itoa(len(args)-1) + " AND id < $" + strconv.Itoa(len(args)) + "))"
	}
	args = append(args, filter.Limit)
	query += " ORDER BY detected_at DESC, id DESC LIMIT $" + strconv.Itoa(len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	alerts := make([]domain.SessionAlert, 0)
	for rows.Next() {
		alert, err := scanSessionAlert(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

func (s *PostgresStore) GetSessionAlert(ctx context.Context, id string) (*domain.SessionAlert, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, rule_id, rule_version, source_event_id, session_id, severity, status, summary, detected_at, created_at, revision, acknowledged_at, acknowledged_by, acknowledgement_event_id FROM session_alerts WHERE id = $1`, id)
	alert, err := scanSessionAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &alert, nil
}

func (s *PostgresStore) SessionAlertCounts(ctx context.Context) (domain.SessionAlertCounts, error) {
	var counts domain.SessionAlertCounts
	var info, low, medium, high, critical int64
	err := s.db.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE severity='info'), count(*) FILTER (WHERE severity='low'), count(*) FILTER (WHERE severity='medium'), count(*) FILTER (WHERE severity='high'), count(*) FILTER (WHERE severity='critical'), CURRENT_TIMESTAMP FROM session_alerts WHERE status='unacknowledged'`).Scan(&counts.UnacknowledgedCount, &info, &low, &medium, &high, &critical, &counts.AsOf)
	if err != nil {
		return domain.SessionAlertCounts{}, err
	}
	counts.BySeverity = map[domain.AlertSeverity]int64{domain.AlertInfo: info, domain.AlertLow: low, domain.AlertMedium: medium, domain.AlertHigh: high, domain.AlertCritical: critical}
	counts.AsOf = counts.AsOf.UTC()
	return counts, nil
}

func (s *PostgresStore) SessionAlertsDurable() bool { return true }

type sessionAlertScanner interface{ Scan(...any) error }

func scanSessionAlert(row sessionAlertScanner) (domain.SessionAlert, error) {
	var alert domain.SessionAlert
	var acknowledgedAt sql.NullTime
	var acknowledgedBy, acknowledgementEventID sql.NullString
	err := row.Scan(&alert.ID, &alert.RuleID, &alert.RuleVersion, &alert.SourceEventID, &alert.SessionID, &alert.Severity, &alert.Status, &alert.Summary, &alert.DetectedAt, &alert.CreatedAt, &alert.Revision, &acknowledgedAt, &acknowledgedBy, &acknowledgementEventID)
	if err != nil {
		return domain.SessionAlert{}, err
	}
	alert.DetectedAt, alert.CreatedAt = alert.DetectedAt.UTC(), alert.CreatedAt.UTC()
	if acknowledgedAt.Valid {
		at := acknowledgedAt.Time.UTC()
		alert.AcknowledgedAt = &at
	}
	if acknowledgedBy.Valid {
		alert.AcknowledgedBy = acknowledgedBy.String
	}
	if acknowledgementEventID.Valid {
		alert.AcknowledgementEventID = acknowledgementEventID.String
	}
	return alert, nil
}

// AcknowledgeSessionAlert commits the chain event and projection transition in one transaction.
func (s *PostgresStore) AcknowledgeSessionAlert(ctx context.Context, id string, expectedRevision int64, actorID string, event *domain.Event) (domain.SessionAlert, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.SessionAlert{}, false, err
	}
	defer tx.Rollback()
	if err := lockAuditChain(ctx, tx); err != nil {
		return domain.SessionAlert{}, false, err
	}

	row := tx.QueryRowContext(ctx, `SELECT id, rule_id, rule_version, source_event_id, session_id, severity, status, summary, detected_at, created_at, revision, acknowledged_at, acknowledged_by, acknowledgement_event_id FROM session_alerts WHERE id = $1 FOR UPDATE`, id)
	alert, err := scanSessionAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SessionAlert{}, false, domain.ErrSessionAlertNotFound
	}
	if err != nil {
		return domain.SessionAlert{}, false, err
	}
	if alert.Status == domain.AlertStatusAcknowledged {
		return alert, false, nil
	}
	if alert.Status != domain.AlertStatusUnacknowledged || alert.Revision != expectedRevision || alert.Revision >= domain.MaxSessionAlertRevision {
		return domain.SessionAlert{}, false, domain.ErrSessionAlertRevisionConflict
	}
	if event == nil || event.ActorID != actorID || event.ResourceID != id || event.Action != "session.alert.acknowledged" {
		return domain.SessionAlert{}, false, fmt.Errorf("invalid session alert acknowledgement event")
	}
	if err := checkAuditChainHead(ctx, tx, event); err != nil {
		return domain.SessionAlert{}, false, err
	}
	if err := appendEvent(ctx, tx, event); err != nil {
		return domain.SessionAlert{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE session_alerts SET status = 'acknowledged', acknowledged_at = $3, acknowledged_by = $4, acknowledgement_event_id = $5, revision = revision + 1 WHERE id = $1 AND status = 'unacknowledged' AND revision = $2`, id, expectedRevision, event.Timestamp, actorID, event.ID)
	if err != nil {
		return domain.SessionAlert{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return domain.SessionAlert{}, false, err
	}
	if rows != 1 {
		return domain.SessionAlert{}, false, domain.ErrSessionAlertRevisionConflict
	}
	if err := tx.Commit(); err != nil {
		return domain.SessionAlert{}, false, err
	}
	at := event.Timestamp.UTC()
	alert.Status = domain.AlertStatusAcknowledged
	alert.AcknowledgedAt = &at
	alert.AcknowledgedBy = actorID
	alert.AcknowledgementEventID = event.ID
	alert.Revision++
	return alert, true, nil
}
