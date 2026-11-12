package infrastructure

import (
	"context"
	"sort"
	"sync"

	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

type memoryRecording struct {
	keyID      string
	wrappedDEK []byte
	status     string
	last       int64
	segments   map[int64]domain.SegmentMetadata
}

type MemoryStore struct {
	mu         sync.Mutex
	recordings map[string]*memoryRecording
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{recordings: make(map[string]*memoryRecording)}
}

func (s *MemoryStore) BeginRecording(_ context.Context, sessionID, keyID string, wrappedDEK []byte) error {
	if sessionID == "" || keyID == "" || len(wrappedDEK) == 0 {
		return domain.ErrInvalidSegment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.recordings[sessionID]; exists {
		return domain.ErrAlreadyExists
	}
	s.recordings[sessionID] = &memoryRecording{
		keyID: keyID, wrappedDEK: append([]byte(nil), wrappedDEK...),
		status: "incomplete", segments: make(map[int64]domain.SegmentMetadata),
	}
	return nil
}

func (s *MemoryStore) AppendSegment(_ context.Context, segment domain.SegmentMetadata) error {
	if segment.SessionID == "" || segment.FirstSequence < 1 || segment.LastSequence < segment.FirstSequence ||
		segment.ObjectKey == "" || len(segment.SHA256) != 32 {
		return domain.ErrInvalidSegment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recording := s.recordings[segment.SessionID]
	if recording == nil {
		return domain.ErrNotFound
	}
	if recording.status != "incomplete" || segment.FirstSequence != recording.last+1 ||
		segment.LastSequence < segment.FirstSequence {
		return domain.ErrConflict
	}
	if _, exists := recording.segments[segment.FirstSequence]; exists {
		return domain.ErrConflict
	}
	segment.SHA256 = append([]byte(nil), segment.SHA256...)
	recording.segments[segment.FirstSequence] = segment
	recording.last = segment.LastSequence
	return nil
}

func (s *MemoryStore) CompleteRecording(_ context.Context, sessionID string, throughSequence int64) error {
	if sessionID == "" || throughSequence < 0 {
		return domain.ErrInvalidSegment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recording := s.recordings[sessionID]
	if recording == nil {
		return domain.ErrNotFound
	}
	if recording.status != "incomplete" || recording.last != throughSequence {
		return domain.ErrConflict
	}
	recording.status = "complete"
	return nil
}

func (s *MemoryStore) GetSegment(_ context.Context, sessionID string, firstSequence int64) (domain.StoredSegment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recording := s.recordings[sessionID]
	if recording == nil {
		return domain.StoredSegment{}, domain.ErrNotFound
	}
	segment, exists := recording.segments[firstSequence]
	if !exists {
		return domain.StoredSegment{}, domain.ErrNotFound
	}
	segment.SHA256 = append([]byte(nil), segment.SHA256...)
	return domain.StoredSegment{
		SegmentMetadata: segment, KeyID: recording.keyID,
		WrappedDEK: append([]byte(nil), recording.wrappedDEK...), Complete: recording.status == "complete",
	}, nil
}

func (s *MemoryStore) GetSegmentsFrom(_ context.Context, sessionID string, firstSequence int64, limit int) ([]domain.StoredSegment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recording := s.recordings[sessionID]
	if recording == nil || limit < 1 {
		return nil, nil
	}
	firsts := make([]int64, 0, len(recording.segments))
	for first := range recording.segments {
		if first >= firstSequence {
			firsts = append(firsts, first)
		}
	}
	sort.Slice(firsts, func(i, j int) bool { return firsts[i] < firsts[j] })
	if len(firsts) > limit {
		firsts = firsts[:limit]
	}
	out := make([]domain.StoredSegment, 0, len(firsts))
	for _, first := range firsts {
		segment := recording.segments[first]
		segment.SHA256 = append([]byte(nil), segment.SHA256...)
		out = append(out, domain.StoredSegment{
			SegmentMetadata: segment, KeyID: recording.keyID,
			WrappedDEK: append([]byte(nil), recording.wrappedDEK...), Complete: recording.status == "complete",
		})
	}
	return out, nil
}

func (s *MemoryStore) Ready(context.Context) error { return nil }

var _ domain.Repository = (*MemoryStore)(nil)
