package infrastructure

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type InMemoryStore struct {
	mu       sync.Mutex
	sessions map[string]*domain.Session
	// expiredAt holds, for each session the sweep expired, when; toAudit those whose
	// expiry is not yet in the trail (ADR-0034).
	expiredAt map[string]time.Time
	toAudit   map[string]bool
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{sessions: map[string]*domain.Session{}, expiredAt: map[string]time.Time{}, toAudit: map[string]bool{}}
}

// ExpireDue is domain.SessionRepository.ExpireDue, under the store's lock.
func (s *InMemoryStore) ExpireDue(ctx context.Context, now time.Time, limit int) ([]*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var due []*domain.Session
	for _, sess := range s.sessions {
		if (sess.Status == domain.StatusActive || sess.Status == domain.StatusPendingApproval) && sess.ExpiresAt.Before(now) {
			due = append(due, sess)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].ExpiresAt.Equal(due[j].ExpiresAt) {
			return due[i].ExpiresAt.Before(due[j].ExpiresAt)
		}
		return due[i].ID < due[j].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]*domain.Session, 0, len(due))
	for _, sess := range due {
		sess.AfterUseOwed = sess.Status == domain.StatusActive // ADR-0044
		sess.Status = domain.StatusExpired
		s.expiredAt[sess.ID] = now
		s.toAudit[sess.ID] = true
		cp := *sess
		out = append(out, &cp)
	}
	return out, nil
}

// ExpiriesToAudit is domain.SessionRepository.ExpiriesToAudit.
func (s *InMemoryStore) ExpiriesToAudit(ctx context.Context, before time.Time, limit int) ([]*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.Session
	for id := range s.toAudit {
		if s.expiredAt[id].Before(before) {
			cp := *s.sessions[id]
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := s.expiredAt[out[i].ID], s.expiredAt[out[j].ID]; !a.Equal(b) {
			return a.Before(b)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// MarkExpiryAudited is domain.SessionRepository.MarkExpiryAudited.
func (s *InMemoryStore) MarkExpiryAudited(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.toAudit, id)
	return nil
}

func (s *InMemoryStore) Save(ctx context.Context, sess *domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.sessions[sess.ID] = &cp
	return nil
}

func (s *InMemoryStore) Get(ctx context.Context, id string) (*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *sess
	return &cp, nil
}

// SaveIfStatus is the compare-and-swap of domain.SessionRepository, under the
// store's lock.
func (s *InMemoryStore) SaveIfStatus(ctx context.Context, sess *domain.Session, expected domain.SessionStatus) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[sess.ID]
	if !ok || current.Status != expected {
		return false, nil
	}
	cp := *sess
	s.sessions[sess.ID] = &cp
	return true, nil
}

// pendingOf counts the requests of requestedBy waiting at now. The caller holds the lock.
func (s *InMemoryStore) pendingOf(requestedBy string, now time.Time) int {
	n := 0
	for _, sess := range s.sessions {
		if sess.Status == domain.StatusPendingApproval && sess.RequestedBy == requestedBy && !sess.ExpiresAt.Before(now) {
			n++
		}
	}
	return n
}

// CountPending is domain.SessionRepository.CountPending over the map.
func (s *InMemoryStore) CountPending(ctx context.Context, requestedBy string, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingOf(requestedBy, now), nil
}

// SaveIfUnderPendingLimit counts and stores under one hold of the store's lock: that
// is what makes the limit exact under concurrency.
func (s *InMemoryStore) SaveIfUnderPendingLimit(ctx context.Context, sess *domain.Session, limit int, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingOf(sess.RequestedBy, now) >= limit {
		return false, nil
	}
	cp := *sess
	s.sessions[sess.ID] = &cp
	return true, nil
}

// ListPending is domain.SessionRepository.ListPending over the map.
func (s *InMemoryStore) ListPending(ctx context.Context, now time.Time, limit int) ([]*domain.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending []*domain.Session
	for _, sess := range s.sessions {
		if sess.Status == domain.StatusPendingApproval && !sess.ExpiresAt.Before(now) {
			cp := *sess
			pending = append(pending, &cp)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if !pending[i].ExpiresAt.Equal(pending[j].ExpiresAt) {
			return pending[i].ExpiresAt.Before(pending[j].ExpiresAt)
		}
		return pending[i].ID < pending[j].ID
	})
	if limit >= 0 && len(pending) > limit {
		return pending[:limit], true, nil
	}
	return pending, false, nil
}

// AfterUseOwed is domain.SessionRepository.AfterUseOwed.
func (s *InMemoryStore) AfterUseOwed(ctx context.Context, endedBefore time.Time, limit int) ([]domain.AfterUseNotice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.AfterUseNotice
	for _, sess := range s.sessions {
		if !sess.AfterUseOwed {
			continue
		}
		ended := sess.ExpiresAt
		if at, ok := s.expiredAt[sess.ID]; ok {
			ended = at
		}
		if sess.TerminatedAt != nil {
			ended = *sess.TerminatedAt
		}
		if ended.Before(endedBefore) {
			out = append(out, domain.AfterUseNotice{SessionID: sess.ID, AccountID: sess.PrivilegedAccountID, EndedAt: ended})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].EndedAt.Equal(out[j].EndedAt) {
			return out[i].EndedAt.Before(out[j].EndedAt)
		}
		return out[i].SessionID < out[j].SessionID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// MarkAfterUseDelivered is domain.SessionRepository.MarkAfterUseDelivered.
func (s *InMemoryStore) MarkAfterUseDelivered(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.AfterUseOwed = false
	}
	return nil
}

// SearchSessions is domain.SessionRepository.SearchSessions.
func (s *InMemoryStore) SearchSessions(ctx context.Context, q domain.SessionSearch, limit int) ([]*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	text := strings.ToLower(q.Text)
	var out []*domain.Session
	for _, sess := range s.sessions {
		if sess.CreatedAt.Before(q.From) || !sess.CreatedAt.Before(q.To) {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(sess.RequestedBy), text) && !strings.Contains(strings.ToLower(sess.PrivilegedAccountID), text) &&
			!strings.Contains(strings.ToLower(sess.Justification), text) && !strings.Contains(strings.ToLower(sess.Ticket), text) {
			continue
		}
		if q.Protocol != "" && sess.Protocol != q.Protocol || q.RequestedBy != "" && sess.RequestedBy != q.RequestedBy ||
			q.PrivilegedAccountID != "" && sess.PrivilegedAccountID != q.PrivilegedAccountID || q.BreakGlass != nil && sess.BreakGlass != *q.BreakGlass {
			continue
		}
		if q.After != nil && !(sess.CreatedAt.Before(q.After.CreatedAt) || sess.CreatedAt.Equal(q.After.CreatedAt) && sess.ID < q.After.ID) {
			continue
		}
		cp := *sess
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
