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
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{nextID: 1}
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
