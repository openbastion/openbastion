package infrastructure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/dbpool"
	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
	"github.com/openbastion/openbastion/services/access/workflow-service/migrations"
)

func OpenPostgres(ctx context.Context, dsn string, config dbpool.Config) (*sql.DB, error) {
	db, err := openPool(dsn, config)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	result, err := migrate.Apply(ctx, db, "workflow-service", migrations.Files)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	result.Log("workflow-service", log.Printf)
	return db, nil
}

type PostgresStore struct{ db *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

func (s *PostgresStore) HierarchyRevision(ctx context.Context) (uint64, error) {
	var revision int64
	err := s.db.QueryRowContext(ctx, `SELECT revision FROM approval_hierarchy_state WHERE singleton = TRUE`).Scan(&revision)
	if err != nil {
		return 0, err
	}
	return uint64(revision), nil
}

func (s *PostgresStore) GetManager(ctx context.Context, subordinate string) (*domain.ManagerRelation, uint64, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM approval_hierarchy_state WHERE singleton = TRUE`).Scan(&revision); err != nil {
		return nil, 0, err
	}
	relation, err := scanRelation(tx.QueryRowContext(ctx, `
		SELECT subordinate_user_id, manager_user_id, revision, created_by, updated_by, created_at, updated_at
		FROM approver_hierarchy WHERE subordinate_user_id = $1`, subordinate))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, uint64(revision), domain.ErrNotFound
		}
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return relation, uint64(revision), nil
}

func (s *PostgresStore) ListHierarchy(ctx context.Context, manager string, page, pageSize int) (domain.HierarchyPage, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return domain.HierarchyPage{}, err
	}
	defer tx.Rollback()
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM approval_hierarchy_state WHERE singleton = TRUE`).Scan(&revision); err != nil {
		return domain.HierarchyPage{}, err
	}
	var total int
	if manager == "" {
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM approver_hierarchy`).Scan(&total)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM approver_hierarchy WHERE manager_user_id = $1`, manager).Scan(&total)
	}
	if err != nil {
		return domain.HierarchyPage{}, err
	}
	var rows *sql.Rows
	if manager == "" {
		rows, err = tx.QueryContext(ctx, `
			SELECT subordinate_user_id, manager_user_id, revision, created_by, updated_by, created_at, updated_at
			FROM approver_hierarchy ORDER BY subordinate_user_id LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	} else {
		rows, err = tx.QueryContext(ctx, `
			SELECT subordinate_user_id, manager_user_id, revision, created_by, updated_by, created_at, updated_at
			FROM approver_hierarchy WHERE manager_user_id = $1 ORDER BY subordinate_user_id LIMIT $2 OFFSET $3`, manager, pageSize, (page-1)*pageSize)
	}
	if err != nil {
		return domain.HierarchyPage{}, err
	}
	defer rows.Close()
	items := make([]domain.ManagerRelation, 0, pageSize)
	for rows.Next() {
		var item domain.ManagerRelation
		var relationRevision int64
		if err := rows.Scan(&item.SubordinateUserID, &item.ManagerUserID, &relationRevision, &item.CreatedBy, &item.UpdatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return domain.HierarchyPage{}, err
		}
		item.Revision = uint64(relationRevision)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return domain.HierarchyPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.HierarchyPage{}, err
	}
	return domain.HierarchyPage{Items: items, Page: page, PageSize: pageSize, TotalItems: total, Revision: uint64(revision)}, nil
}

func (s *PostgresStore) SetManager(ctx context.Context, subordinate, manager string, expected uint64, now time.Time, event domain.AuditOutboxEvent) (*domain.ManagerRelation, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM approval_hierarchy_state WHERE singleton = TRUE FOR UPDATE`).Scan(&currentRevision); err != nil {
		return nil, false, err
	}
	if uint64(currentRevision) != expected {
		return nil, false, domain.ErrConflict
	}
	current, err := scanRelation(tx.QueryRowContext(ctx, `
		SELECT subordinate_user_id, manager_user_id, revision, created_by, updated_by, created_at, updated_at
		FROM approver_hierarchy WHERE subordinate_user_id = $1`, subordinate))
	if err == nil && current.ManagerUserID == manager {
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return current, false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	var cycle bool
	if err := tx.QueryRowContext(ctx, `
		WITH RECURSIVE manager_chain(user_id) AS (
			SELECT $1::text
			UNION
			SELECT h.manager_user_id FROM approver_hierarchy h JOIN manager_chain c ON h.subordinate_user_id = c.user_id
		)
		SELECT EXISTS (SELECT 1 FROM manager_chain WHERE user_id = $2)`, manager, subordinate).Scan(&cycle); err != nil {
		return nil, false, err
	}
	if cycle {
		return nil, false, domain.ErrCycle
	}
	newRevision := currentRevision + 1
	if event.Details == nil {
		event.Details = make(map[string]string)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO approver_hierarchy (subordinate_user_id, manager_user_id, revision, created_by, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $4, $5, $5)
		ON CONFLICT (subordinate_user_id) DO UPDATE SET manager_user_id = EXCLUDED.manager_user_id,
			revision = EXCLUDED.revision, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		subordinate, manager, newRevision, event.ActorID, now); err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE approval_hierarchy_state SET revision = $1, updated_at = $2 WHERE singleton = TRUE`, newRevision, now); err != nil {
		return nil, false, err
	}
	event.Details["revision"] = fmt.Sprint(newRevision)
	if err := insertAuditOutbox(ctx, tx, event, now); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	relation := &domain.ManagerRelation{SubordinateUserID: subordinate, ManagerUserID: manager, Revision: uint64(newRevision), UpdatedBy: event.ActorID, UpdatedAt: now, CreatedAt: now, CreatedBy: event.ActorID}
	if current != nil {
		relation.CreatedAt, relation.CreatedBy = current.CreatedAt, current.CreatedBy
	}
	return relation, true, nil
}

func (s *PostgresStore) DeleteManager(ctx context.Context, subordinate string, expected uint64, now time.Time, event domain.AuditOutboxEvent) (uint64, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM approval_hierarchy_state WHERE singleton = TRUE FOR UPDATE`).Scan(&currentRevision); err != nil {
		return 0, false, err
	}
	if uint64(currentRevision) != expected {
		return uint64(currentRevision), false, domain.ErrConflict
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM approver_hierarchy WHERE subordinate_user_id = $1`, subordinate)
	if err != nil {
		return 0, false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	if count != 1 {
		return uint64(currentRevision), false, domain.ErrNotFound
	}
	newRevision := currentRevision + 1
	if event.Details == nil {
		event.Details = make(map[string]string)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE approval_hierarchy_state SET revision = $1, updated_at = $2 WHERE singleton = TRUE`, newRevision, now); err != nil {
		return 0, false, err
	}
	event.Details["revision"] = fmt.Sprint(newRevision)
	if err := insertAuditOutbox(ctx, tx, event, now); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return uint64(newRevision), true, nil
}

func scanRelation(row *sql.Row) (*domain.ManagerRelation, error) {
	var item domain.ManagerRelation
	var revision int64
	if err := row.Scan(&item.SubordinateUserID, &item.ManagerUserID, &revision, &item.CreatedBy, &item.UpdatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return nil, err
	}
	item.Revision = uint64(revision)
	return &item, nil
}

func insertAuditOutbox(ctx context.Context, tx *sql.Tx, event domain.AuditOutboxEvent, now time.Time) error {
	details, err := json.Marshal(event.Details)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO workflow_audit_outbox (event_id, actor_id, action, resource_type, resource_id, details, success, due_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, event.ID, event.ActorID, event.Action, event.ResourceType, event.ResourceID, details, event.Success, now)
	return err
}

func (s *PostgresStore) ClaimAuditEvents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]domain.AuditOutboxEvent, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT event_id, actor_id, action, resource_type, resource_id, details, success, attempts
		FROM workflow_audit_outbox
		WHERE due_at <= $1 AND (lease_until IS NULL OR lease_until <= $1)
		ORDER BY due_at, event_id
		LIMIT $2 FOR UPDATE SKIP LOCKED`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditOutboxEvent
	for rows.Next() {
		var event domain.AuditOutboxEvent
		var details []byte
		if err := rows.Scan(&event.ID, &event.ActorID, &event.Action, &event.ResourceType, &event.ResourceID, &details, &event.Success, &event.Attempts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(details, &event.Details); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		token, err := domain.NewID("lease")
		if err != nil {
			return nil, err
		}
		until := now.Add(lease)
		if _, err := tx.ExecContext(ctx, `UPDATE workflow_audit_outbox SET lease_until = $1, lease_token = $2, attempts = attempts + 1 WHERE event_id = $3`, until, token, out[i].ID); err != nil {
			return nil, err
		}
		out[i].LeaseUntil, out[i].LeaseToken, out[i].Attempts = &until, token, out[i].Attempts+1
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) CompleteAuditEvent(ctx context.Context, eventID, leaseToken string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM workflow_audit_outbox WHERE event_id = $1 AND lease_token = $2`, eventID, leaseToken)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return domain.ErrConflict
	}
	return nil
}

func (s *PostgresStore) RetryAuditEvent(ctx context.Context, eventID, leaseToken string, dueAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE workflow_audit_outbox SET due_at = $1, lease_until = NULL, lease_token = NULL WHERE event_id = $2 AND lease_token = $3`, dueAt, eventID, leaseToken)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return domain.ErrConflict
	}
	return nil
}

func openPool(dsn string, config dbpool.Config) (*sql.DB, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	cfg, err := pq.NewConfig(dsn)
	if err != nil {
		return nil, err
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	connector, err := pq.NewConnectorConfig(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	if err := dbpool.Configure(db, config); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure postgres pool: %w", err)
	}
	return db, nil
}
