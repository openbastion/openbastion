package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

const (
	HierarchyReadAction   = "approval-hierarchy:read"
	HierarchyManageAction = "approval-hierarchy:manage"
	HierarchyAllResource  = "approval-hierarchy:all"
)

type HierarchyService struct {
	repository domain.HierarchyRepository
	users      domain.UserDirectory
	authorizer domain.AuthorizationClient
	audit      domain.AuditEmitter
	now        func() time.Time
}

func NewHierarchyService(repository domain.HierarchyRepository, users domain.UserDirectory, authorizer domain.AuthorizationClient, audit domain.AuditEmitter) *HierarchyService {
	return &HierarchyService{repository: repository, users: users, authorizer: authorizer, audit: audit, now: time.Now}
}

func (s *HierarchyService) WithClock(now func() time.Time) *HierarchyService {
	if now != nil {
		s.now = now
	}
	return s
}

func (s *HierarchyService) clock() time.Time { return s.now().UTC() }

func (s *HierarchyService) GetManager(ctx context.Context, actorID string, roles []string, subordinateID string) (*domain.ManagerRelation, uint64, error) {
	if !validUserID(actorID) || !validUserID(subordinateID) {
		return nil, 0, domain.ErrInvalid
	}
	if err := s.requireAccess(ctx, actorID, roles, "approval-hierarchy:user:"+subordinateID, HierarchyReadAction, HierarchyAllResource); err != nil {
		return nil, 0, err
	}
	relation, revision, err := s.repository.GetManager(ctx, subordinateID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, revision, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("read manager relation: %w", err)
	}
	return relation, revision, nil
}

func (s *HierarchyService) ListHierarchy(ctx context.Context, actorID string, roles []string, managerID string, page, pageSize int) (domain.HierarchyPage, error) {
	if !validUserID(actorID) || (managerID != "" && !validUserID(managerID)) {
		return domain.HierarchyPage{}, domain.ErrInvalid
	}
	if page < 1 || page > 1_000_000 || pageSize < 1 || pageSize > 100 {
		return domain.HierarchyPage{}, domain.ErrInvalid
	}
	resource := HierarchyAllResource
	if managerID != "" {
		resource = "approval-hierarchy:reports:" + managerID
	}
	if err := s.requireAccess(ctx, actorID, roles, resource, HierarchyReadAction); err != nil {
		return domain.HierarchyPage{}, err
	}
	pageResult, err := s.repository.ListHierarchy(ctx, managerID, page, pageSize)
	if err != nil {
		return domain.HierarchyPage{}, fmt.Errorf("list hierarchy: %w", err)
	}
	return pageResult, nil
}

func (s *HierarchyService) SetManager(ctx context.Context, actorID string, roles []string, subordinateID, managerID string, expectedRevision uint64) (*domain.ManagerRelation, uint64, error) {
	if !validUserID(actorID) || !validUserID(subordinateID) || !validUserID(managerID) {
		return nil, 0, domain.ErrInvalid
	}
	if subordinateID == managerID {
		return nil, 0, domain.ErrCycle
	}
	if err := s.requireAccess(ctx, actorID, roles, "approval-hierarchy:user:"+subordinateID, HierarchyManageAction, HierarchyAllResource); err != nil {
		if errors.Is(err, domain.ErrForbidden) {
			if auditErr := s.recordDenied(ctx, actorID, subordinateID, "not_authorized"); auditErr != nil {
				return nil, 0, auditErr
			}
		}
		return nil, 0, err
	}
	for _, id := range []string{subordinateID, managerID} {
		identity, err := s.users.GetAuthorizationContext(ctx, id)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: validating hierarchy identity", domain.ErrUnavailable)
		}
		if !identity.Exists || !identity.Active {
			if auditErr := s.recordDenied(ctx, actorID, subordinateID, "identity_inactive_or_missing"); auditErr != nil {
				return nil, 0, auditErr
			}
			return nil, 0, domain.ErrInvalid
		}
	}
	now := s.clock()
	details := map[string]string{"subordinate_user_id": subordinateID, "manager_user_id": managerID, "expected_revision": fmt.Sprint(expectedRevision), "operation": "set"}
	if err := s.audit.EmitEvent(ctx, actorID, "approval_hierarchy.change_authorized", "approval_hierarchy", subordinateID, details, true); err != nil {
		return nil, 0, fmt.Errorf("%w: hierarchy audit unavailable", domain.ErrUnavailable)
	}
	eventID, err := domain.NewID("workflow_audit")
	if err != nil {
		return nil, 0, fmt.Errorf("%w: audit event identifier unavailable", domain.ErrUnavailable)
	}
	event := domain.AuditOutboxEvent{ID: eventID, ActorID: actorID, Action: "approval_hierarchy.relation_changed", ResourceType: "approval_hierarchy", ResourceID: subordinateID, Details: map[string]string{"subordinate_user_id": subordinateID, "manager_user_id": managerID}, Success: true}
	relation, changed, err := s.repository.SetManager(ctx, subordinateID, managerID, expectedRevision, now, event)
	if err != nil {
		if errors.Is(err, domain.ErrCycle) || errors.Is(err, domain.ErrConflict) {
			if auditErr := s.recordDenied(ctx, actorID, subordinateID, "cycle_or_stale_revision"); auditErr != nil {
				return nil, 0, auditErr
			}
			return nil, 0, err
		}
		return nil, 0, fmt.Errorf("%w: hierarchy mutation failed", domain.ErrUnavailable)
	}
	revision, err := s.repository.HierarchyRevision(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: hierarchy revision unavailable", domain.ErrUnavailable)
	}
	if !changed {
		return relation, revision, nil
	}
	return relation, revision, nil
}

func (s *HierarchyService) DeleteManager(ctx context.Context, actorID string, roles []string, subordinateID string, expectedRevision uint64) (uint64, error) {
	if !validUserID(actorID) || !validUserID(subordinateID) {
		return 0, domain.ErrInvalid
	}
	if err := s.requireAccess(ctx, actorID, roles, "approval-hierarchy:user:"+subordinateID, HierarchyManageAction, HierarchyAllResource); err != nil {
		if errors.Is(err, domain.ErrForbidden) {
			if auditErr := s.recordDenied(ctx, actorID, subordinateID, "not_authorized"); auditErr != nil {
				return 0, auditErr
			}
		}
		return 0, err
	}
	identity, err := s.users.GetAuthorizationContext(ctx, subordinateID)
	if err != nil {
		return 0, fmt.Errorf("%w: validating hierarchy identity", domain.ErrUnavailable)
	}
	if !identity.Exists || !identity.Active {
		if auditErr := s.recordDenied(ctx, actorID, subordinateID, "identity_inactive_or_missing"); auditErr != nil {
			return 0, auditErr
		}
		return 0, domain.ErrInvalid
	}
	now := s.clock()
	details := map[string]string{"subordinate_user_id": subordinateID, "expected_revision": fmt.Sprint(expectedRevision), "operation": "delete"}
	if err := s.audit.EmitEvent(ctx, actorID, "approval_hierarchy.change_authorized", "approval_hierarchy", subordinateID, details, true); err != nil {
		return 0, fmt.Errorf("%w: hierarchy audit unavailable", domain.ErrUnavailable)
	}
	eventID, err := domain.NewID("workflow_audit")
	if err != nil {
		return 0, fmt.Errorf("%w: audit event identifier unavailable", domain.ErrUnavailable)
	}
	event := domain.AuditOutboxEvent{ID: eventID, ActorID: actorID, Action: "approval_hierarchy.relation_changed", ResourceType: "approval_hierarchy", ResourceID: subordinateID, Details: map[string]string{"subordinate_user_id": subordinateID, "operation": "delete"}, Success: true}
	revision, _, err := s.repository.DeleteManager(ctx, subordinateID, expectedRevision, now, event)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrConflict) {
			if auditErr := s.recordDenied(ctx, actorID, subordinateID, "relation_missing_or_stale_revision"); auditErr != nil {
				return 0, auditErr
			}
			return 0, err
		}
		return 0, fmt.Errorf("%w: hierarchy mutation failed", domain.ErrUnavailable)
	}
	return revision, nil
}

func (s *HierarchyService) requireAccess(ctx context.Context, actorID string, _ []string, resource, action string, fallback ...string) error {
	identity, err := s.users.GetAuthorizationContext(ctx, actorID)
	if err != nil {
		return fmt.Errorf("%w: actor identity unavailable", domain.ErrUnavailable)
	}
	if !identity.Exists || !identity.Active {
		return domain.ErrForbidden
	}
	roles := identity.Roles
	allowed, _, err := s.authorizer.CheckAccess(ctx, actorID, roles, resource, action)
	if err != nil {
		return fmt.Errorf("%w: authorization unavailable", domain.ErrUnavailable)
	}
	if allowed {
		return nil
	}
	for _, candidate := range fallback {
		allowed, _, err = s.authorizer.CheckAccess(ctx, actorID, roles, candidate, action)
		if err != nil {
			return fmt.Errorf("%w: authorization unavailable", domain.ErrUnavailable)
		}
		if allowed {
			return nil
		}
	}
	return domain.ErrForbidden
}

func (s *HierarchyService) recordDenied(ctx context.Context, actorID, subordinateID, reason string) error {
	details := map[string]string{"subordinate_user_id": subordinateID, "reason_code": reason}
	if err := s.audit.EmitEvent(ctx, actorID, "approval_hierarchy.change_denied", "approval_hierarchy", subordinateID, details, false); err != nil {
		return fmt.Errorf("%w: refusal audit unavailable", domain.ErrUnavailable)
	}
	return nil
}

func validUserID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
