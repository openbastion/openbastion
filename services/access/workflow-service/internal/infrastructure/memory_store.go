package infrastructure

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

type MemoryStore struct {
	mu          sync.Mutex
	revision    uint64
	relations   map[string]domain.ManagerRelation
	outbox      map[string]domain.AuditOutboxEvent
	requests    map[string]domain.ApprovalRequest
	idempotency map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{relations: make(map[string]domain.ManagerRelation), outbox: make(map[string]domain.AuditOutboxEvent), requests: make(map[string]domain.ApprovalRequest), idempotency: make(map[string]string)}
}

func (s *MemoryStore) HierarchyRevision(context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision, nil
}

func (s *MemoryStore) GetManager(_ context.Context, subordinate string) (*domain.ManagerRelation, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	relation, ok := s.relations[subordinate]
	if !ok {
		return nil, s.revision, domain.ErrNotFound
	}
	copy := relation
	return &copy, s.revision, nil
}

func (s *MemoryStore) ListHierarchy(_ context.Context, manager string, page, pageSize int) (domain.HierarchyPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]domain.ManagerRelation, 0, len(s.relations))
	for _, relation := range s.relations {
		if manager == "" || relation.ManagerUserID == manager {
			all = append(all, relation)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].SubordinateUserID < all[j].SubordinateUserID })
	total := len(all)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	items := append([]domain.ManagerRelation(nil), all[start:end]...)
	return domain.HierarchyPage{Items: items, Page: page, PageSize: pageSize, TotalItems: total, Revision: s.revision}, nil
}

func (s *MemoryStore) SetManager(_ context.Context, subordinate, manager string, expected uint64, now time.Time, event domain.AuditOutboxEvent) (*domain.ManagerRelation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.revision {
		return nil, false, domain.ErrConflict
	}
	if subordinate == manager {
		return nil, false, domain.ErrCycle
	}
	seen := make(map[string]struct{})
	for cursor := manager; cursor != ""; {
		if cursor == subordinate {
			return nil, false, domain.ErrCycle
		}
		if _, ok := seen[cursor]; ok {
			return nil, false, domain.ErrCycle
		}
		seen[cursor] = struct{}{}
		relation, ok := s.relations[cursor]
		if !ok {
			break
		}
		cursor = relation.ManagerUserID
	}
	if current, ok := s.relations[subordinate]; ok && current.ManagerUserID == manager {
		copy := current
		return &copy, false, nil
	}
	s.revision++
	relation, exists := s.relations[subordinate]
	if !exists {
		relation = domain.ManagerRelation{SubordinateUserID: subordinate, ManagerUserID: manager, CreatedBy: event.ActorID, CreatedAt: now}
	}
	relation.ManagerUserID, relation.UpdatedBy, relation.UpdatedAt, relation.Revision = manager, event.ActorID, now, s.revision
	s.relations[subordinate] = relation
	event.DueAt = now
	s.outbox[event.ID] = event
	copy := relation
	return &copy, true, nil
}

func (s *MemoryStore) DeleteManager(_ context.Context, subordinate string, expected uint64, now time.Time, event domain.AuditOutboxEvent) (uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.revision {
		return s.revision, false, domain.ErrConflict
	}
	if _, ok := s.relations[subordinate]; !ok {
		return s.revision, false, domain.ErrNotFound
	}
	delete(s.relations, subordinate)
	s.revision++
	event.DueAt = now
	s.outbox[event.ID] = event
	return s.revision, true, nil
}

func (s *MemoryStore) ClaimAuditEvents(_ context.Context, now time.Time, lease time.Duration, limit int) ([]domain.AuditOutboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.outbox))
	for id, event := range s.outbox {
		if !event.DueAt.After(now) && (event.LeaseUntil == nil || !event.LeaseUntil.After(now)) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]domain.AuditOutboxEvent, 0, len(ids))
	for _, id := range ids {
		event := s.outbox[id]
		token := fmt.Sprintf("lease-%d-%s", now.UnixNano(), id)
		until := now.Add(lease)
		event.LeaseToken, event.LeaseUntil = token, &until
		event.Attempts++
		s.outbox[id] = event
		out = append(out, event)
	}
	return out, nil
}

func (s *MemoryStore) CompleteAuditEvent(_ context.Context, id, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.outbox[id]
	if !ok || event.LeaseToken != token {
		return domain.ErrConflict
	}
	delete(s.outbox, id)
	return nil
}

func (s *MemoryStore) RetryAuditEvent(_ context.Context, id, token string, due time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.outbox[id]
	if !ok || event.LeaseToken != token {
		return domain.ErrConflict
	}
	event.DueAt, event.LeaseUntil, event.LeaseToken = due, nil, ""
	s.outbox[id] = event
	return nil
}
