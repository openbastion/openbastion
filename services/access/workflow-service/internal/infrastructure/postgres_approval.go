package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

type rowScanner interface{ Scan(dest ...any) error }

const approvalSelect = `
SELECT r.id, r.resource_type, r.resource_id, r.requester_user_id, r.account_id,
       r.ticket_reference, a.approver_user_id, r.hierarchy_revision, r.status,
       r.idempotency_key, r.request_hash, r.decision_expires_at, r.created_at,
       r.decided_at, r.decided_by, r.decision_reason, r.revision
FROM workflow_requests r
JOIN workflow_approvals a ON a.workflow_request_id = r.id`

func (s *PostgresStore) FindApprovalByIdempotencyKey(ctx context.Context, key string) (*domain.ApprovalRequest, error) {
	request, err := scanApprovalRequest(s.db.QueryRowContext(ctx, approvalSelect+` WHERE r.idempotency_key = $1`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return request, err
}

func (s *PostgresStore) GetApprovalRequest(ctx context.Context, requestID string) (*domain.ApprovalRequest, error) {
	request, err := scanApprovalRequest(s.db.QueryRowContext(ctx, approvalSelect+` WHERE r.id = $1`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return request, err
}

func (s *PostgresStore) CreateApprovalRequest(ctx context.Context, input domain.CreateApprovalInput, approver string, hierarchyRevision uint64, requestHash [32]byte, now time.Time, event domain.AuditOutboxEvent) (*domain.ApprovalRequest, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	// Check the stable key before resolving hierarchy again: a timeout after commit
	// must replay the original approver snapshot even if the hierarchy has changed.
	existing, err := scanApprovalRequest(tx.QueryRowContext(ctx, approvalSelect+` WHERE r.idempotency_key = $1 OR r.id = $2 FOR UPDATE OF r, a`, input.IdempotencyKey, input.RequestID))
	if err == nil {
		if existing.RequestHash != requestHash {
			return nil, false, domain.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}

	// A shared lock on the global revision is held through the insert. Hierarchy
	// mutations take FOR UPDATE on this row, so the snapshot cannot race a change.
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM approval_hierarchy_state WHERE singleton = TRUE FOR SHARE`).Scan(&currentRevision); err != nil {
		return nil, false, err
	}
	if uint64(currentRevision) != hierarchyRevision {
		return nil, false, domain.ErrConflict
	}
	var currentApprover string
	if err := tx.QueryRowContext(ctx, `SELECT manager_user_id FROM approver_hierarchy WHERE subordinate_user_id = $1`, input.RequesterUserID).Scan(&currentApprover); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, domain.ErrForbidden
		}
		return nil, false, err
	}
	if currentApprover != approver {
		return nil, false, domain.ErrConflict
	}

	inserted, err := tx.ExecContext(ctx, `
		INSERT INTO workflow_requests (id, resource_type, resource_id, requester_user_id, account_id,
			ticket_reference, status, hierarchy_revision, idempotency_key, request_hash, decision_expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10,$11)
		ON CONFLICT DO NOTHING`,
		input.RequestID, input.ResourceType, input.ResourceID, input.RequesterUserID, input.AccountID,
		input.TicketReference, hierarchyRevision, input.IdempotencyKey, requestHash[:], input.DecisionExpiresAt, now)
	if err != nil {
		return nil, false, err
	}
	insertedCount, err := inserted.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if insertedCount == 0 {
		existing, lookupErr := scanApprovalRequest(tx.QueryRowContext(ctx, approvalSelect+` WHERE r.idempotency_key = $1 OR r.id = $2`, input.IdempotencyKey, input.RequestID))
		if lookupErr != nil || existing.RequestHash != requestHash {
			return nil, false, domain.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO workflow_approvals (workflow_request_id, approver_user_id, hierarchy_revision, status, created_at)
		VALUES ($1,$2,$3,'pending',$4)`, input.RequestID, approver, hierarchyRevision, now); err != nil {
		return nil, false, err
	}
	if event.Details == nil {
		event.Details = make(map[string]string)
	}
	event.Details["approver_user_id"] = approver
	event.Details["hierarchy_revision"] = fmt.Sprint(hierarchyRevision)
	if err := insertAuditOutbox(ctx, tx, event, now); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	request := &domain.ApprovalRequest{
		ID: input.RequestID, ResourceType: input.ResourceType, ResourceID: input.ResourceID,
		RequesterUserID: input.RequesterUserID, AccountID: input.AccountID, TicketReference: input.TicketReference,
		ApproverUserID: approver, HierarchyRevision: hierarchyRevision, Status: domain.ApprovalPending,
		IdempotencyKey: input.IdempotencyKey, RequestHash: requestHash, DecisionExpiresAt: input.DecisionExpiresAt,
		CreatedAt: now, Revision: 1,
	}
	return request, true, nil
}

func (s *PostgresStore) ListPendingApprovals(ctx context.Context, approver string, page, pageSize int, now time.Time) (domain.ApprovalPage, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM workflow_requests r JOIN workflow_approvals a ON a.workflow_request_id = r.id
		WHERE a.approver_user_id = $1 AND r.status = 'pending' AND a.status = 'pending' AND r.decision_expires_at > $2`, approver, now).Scan(&total); err != nil {
		return domain.ApprovalPage{}, err
	}
	rows, err := s.db.QueryContext(ctx, approvalSelect+`
		WHERE a.approver_user_id = $1 AND r.status = 'pending' AND a.status = 'pending' AND r.decision_expires_at > $2
		ORDER BY r.created_at, r.id LIMIT $3 OFFSET $4`, approver, now, pageSize, (page-1)*pageSize)
	if err != nil {
		return domain.ApprovalPage{}, err
	}
	defer rows.Close()
	items := make([]domain.ApprovalRequest, 0, pageSize)
	for rows.Next() {
		item, err := scanApprovalRequest(rows)
		if err != nil {
			return domain.ApprovalPage{}, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return domain.ApprovalPage{}, err
	}
	return domain.ApprovalPage{Items: items, Page: page, PageSize: pageSize, TotalItems: total}, nil
}

func (s *PostgresStore) DecideApprovalRequest(ctx context.Context, requestID string, expected uint64, decision domain.ApprovalStatus, actor, reason string, now time.Time, event domain.AuditOutboxEvent) (*domain.ApprovalRequest, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	current, err := scanApprovalRequest(tx.QueryRowContext(ctx, approvalSelect+` WHERE r.id = $1 FOR UPDATE OF r, a`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, domain.ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if current.Status == decision && current.DecidedBy == actor && current.DecisionReason == reason {
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return current, false, nil
	}
	if current.Status != domain.ApprovalPending {
		return nil, false, domain.ErrConflict
	}
	if !current.DecisionExpiresAt.After(now) {
		return nil, false, domain.ErrExpired
	}
	if current.Revision != expected {
		return nil, false, domain.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_requests SET status=$1, decided_at=$2, decided_by=$3, decision_reason=$4, revision=revision+1 WHERE id=$5 AND revision=$6 AND status='pending'`, string(decision), now, actor, reason, requestID, expected); err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_approvals SET status=$1, decided_at=$2, decided_by=$3, decision_reason=$4, revision=revision+1 WHERE workflow_request_id=$5 AND revision=$6 AND status='pending'`, string(decision), now, actor, reason, requestID, expected); err != nil {
		return nil, false, err
	}
	if event.Details == nil {
		event.Details = make(map[string]string)
	}
	event.Details["revision"] = fmt.Sprint(expected + 1)
	if err := insertAuditOutbox(ctx, tx, event, now); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	current.Status, current.DecidedBy, current.DecisionReason, current.Revision = decision, actor, reason, expected+1
	decidedAt := now
	current.DecidedAt = &decidedAt
	return current, true, nil
}

func (s *PostgresStore) CancelApprovalRequest(ctx context.Context, requestID string, expected uint64, reason string, now time.Time, event domain.AuditOutboxEvent) (*domain.ApprovalRequest, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	current, err := scanApprovalRequest(tx.QueryRowContext(ctx, approvalSelect+` WHERE r.id = $1 FOR UPDATE OF r, a`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, domain.ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if current.Status == domain.ApprovalCancelled && current.DecisionReason == reason {
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return current, false, nil
	}
	if current.Status != domain.ApprovalPending {
		return nil, false, domain.ErrConflict
	}
	if current.Revision != expected {
		return nil, false, domain.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_requests SET status='cancelled', decision_reason=$1, revision=revision+1 WHERE id=$2 AND revision=$3 AND status='pending'`, reason, requestID, expected); err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_approvals SET status='cancelled', decision_reason=$1, revision=revision+1 WHERE workflow_request_id=$2 AND revision=$3 AND status='pending'`, reason, requestID, expected); err != nil {
		return nil, false, err
	}
	if event.Details == nil {
		event.Details = make(map[string]string)
	}
	event.Details["revision"] = fmt.Sprint(expected + 1)
	if err := insertAuditOutbox(ctx, tx, event, now); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	current.Status, current.DecisionReason, current.Revision = domain.ApprovalCancelled, reason, expected+1
	return current, true, nil
}

func (s *PostgresStore) ExpirePendingApprovals(ctx context.Context, now time.Time, limit int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT r.id, r.resource_type, r.resource_id, a.approver_user_id
		FROM workflow_requests r JOIN workflow_approvals a ON a.workflow_request_id = r.id
		WHERE r.status='pending' AND a.status='pending' AND r.decision_expires_at <= $1
		ORDER BY r.decision_expires_at, r.id LIMIT $2 FOR UPDATE OF r, a SKIP LOCKED`, now, limit)
	if err != nil {
		return 0, err
	}
	type expired struct{ id, resourceType, resourceID, approver string }
	var candidates []expired
	for rows.Next() {
		var item expired
		if err := rows.Scan(&item.id, &item.resourceType, &item.resourceID, &item.approver); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, item := range candidates {
		if _, err := tx.ExecContext(ctx, `UPDATE workflow_requests SET status='expired', revision=revision+1 WHERE id=$1 AND status='pending'`, item.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE workflow_approvals SET status='expired', revision=revision+1 WHERE workflow_request_id=$1 AND status='pending'`, item.id); err != nil {
			return 0, err
		}
		eventID, err := domain.NewID("workflow_audit")
		if err != nil {
			return 0, err
		}
		event := domain.AuditOutboxEvent{ID: eventID, Action: "workflow.approval_request_expired", ResourceType: item.resourceType, ResourceID: item.resourceID, Details: map[string]string{"request_id": item.id, "approver_user_id": item.approver}, Success: true}
		if err := insertAuditOutbox(ctx, tx, event, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(candidates), nil
}

func scanApprovalRequest(row rowScanner) (*domain.ApprovalRequest, error) {
	var request domain.ApprovalRequest
	var hierarchyRevision, revision int64
	var hash []byte
	var status string
	var decidedAt sql.NullTime
	var decidedBy sql.NullString
	if err := row.Scan(&request.ID, &request.ResourceType, &request.ResourceID, &request.RequesterUserID,
		&request.AccountID, &request.TicketReference, &request.ApproverUserID, &hierarchyRevision, &status,
		&request.IdempotencyKey, &hash, &request.DecisionExpiresAt, &request.CreatedAt, &decidedAt,
		&decidedBy, &request.DecisionReason, &revision); err != nil {
		return nil, err
	}
	if len(hash) != len(request.RequestHash) {
		return nil, fmt.Errorf("invalid request hash length %d", len(hash))
	}
	copy(request.RequestHash[:], hash)
	request.HierarchyRevision, request.Status, request.Revision = uint64(hierarchyRevision), domain.ApprovalStatus(status), uint64(revision)
	if decidedAt.Valid {
		value := decidedAt.Time
		request.DecidedAt = &value
	}
	if decidedBy.Valid {
		request.DecidedBy = decidedBy.String
	}
	return &request, nil
}
