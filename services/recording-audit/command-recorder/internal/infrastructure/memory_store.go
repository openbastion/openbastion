package infrastructure

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
)

// InMemoryStore is the dev/test implementation of domain.CommandRepository.
type InMemoryStore struct {
	mu      sync.Mutex
	entries []domain.CommandEntry
	nextID  int64
	started map[string]time.Time // when each session's recording started (its first entry)
	// opened counts the sessions EachCommand decrypted (ADR-0080): what a test may assert was not.
	opened map[string]int
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{nextID: 1, started: map[string]time.Time{}, opened: map[string]int{}}
}

func (s *InMemoryStore) AppendBatch(ctx context.Context, entries []domain.CommandEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		e.ID = s.nextID
		s.nextID++
		// Same precision as PostgreSQL's TIMESTAMPTZ, so both stores satisfy
		// one contract.
		e.Timestamp = e.Timestamp.UTC().Truncate(time.Microsecond)
		if _, ok := s.started[e.SessionID]; !ok {
			s.started[e.SessionID] = time.Now().UTC()
		}
		s.entries = append(s.entries, e)
	}
	return nil
}

func (s *InMemoryStore) ListBySession(ctx context.Context, sessionID string, page, pageSize int) ([]domain.CommandEntry, int, error) {
	s.mu.Lock()
	var matching []domain.CommandEntry
	for _, e := range s.entries {
		if e.SessionID == sessionID {
			matching = append(matching, e)
		}
	}
	s.mu.Unlock()

	sort.SliceStable(matching, func(i, j int) bool {
		if !matching[i].Timestamp.Equal(matching[j].Timestamp) {
			return matching[i].Timestamp.Before(matching[j].Timestamp)
		}
		return matching[i].ID < matching[j].ID
	})

	total := len(matching)
	start := (page - 1) * pageSize
	if start >= total {
		return []domain.CommandEntry{}, total, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return matching[start:end], total, nil
}

// RecordingsStartedBetween is domain.CommandRepository.RecordingsStartedBetween.
func (s *InMemoryStore) RecordingsStartedBetween(ctx context.Context, from, to time.Time, limit int) ([]domain.SearchCandidate, error) {
	s.mu.Lock()
	var out []domain.SearchCandidate
	for id, at := range s.started {
		if !at.Before(from) && at.Before(to) {
			out = append(out, domain.SearchCandidate{SessionID: id, StartedAt: at})
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.After(out[j].StartedAt)
		}
		return out[i].SessionID < out[j].SessionID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// EachCommand is domain.CommandRepository.EachCommand.
func (s *InMemoryStore) EachCommand(ctx context.Context, sessionID string, fn func(domain.CommandEntry) bool) error {
	entries, _, err := s.ListBySession(ctx, sessionID, 1, int(^uint(0)>>1))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.opened[sessionID]++
	s.mu.Unlock()
	for _, e := range entries {
		if !fn(e) {
			return nil
		}
	}
	return nil
}

// SetStarted sets when a session's recording started; for tests.
func (s *InMemoryStore) SetStarted(sessionID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started[sessionID] = at.UTC()
}

// Opened says how many times EachCommand decrypted a session; for tests.
func (s *InMemoryStore) Opened(sessionID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opened[sessionID]
}
