package application

// Archiving the chain out of the database without making it unverifiable (ADR-0032).

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// Archiver writes archives somewhere the database does not control.
type Archiver interface {
	// Write writes the events, in order, as the archive `name`, and returns the SHA-256 of
	// the archive as read back. An archive of that name that already holds exactly these
	// events is not an error; one that holds anything else is.
	Write(ctx context.Context, name string, events []*domain.Event) ([]byte, error)
	// Sum returns the SHA-256 of the archive `name` as it is now.
	Sum(ctx context.Context, name string) ([]byte, error)
}

// archiving holds what WithArchive set.
type archiving struct {
	to     Archiver
	months int // months of events kept in the database
	mu     sync.Mutex
}

// selfEmitter is the Audit Service's own identity (pkg/mtls.AuditService): the emitter of
// the events it writes about its own chain.
const selfEmitter = "audit-service"

// WithArchive makes the service archive, out of the database, the whole calendar months older
// than `months` (ADR-0032). It needs anchors: the checkpoints are kept with them.
func (s *AuditService) WithArchive(to Archiver, months int) *AuditService {
	s.archive = &archiving{to: to, months: months}
	return s
}

// ArchiveDue archives every month that is due, oldest first, one at a time, and returns the
// names of the archives it wrote (or finished). It stops at the first refusal: nothing it has
// not verified, written and read back leaves the database.
func (s *AuditService) ArchiveDue(ctx context.Context) ([]string, error) {
	if s.archive == nil || s.anchors == nil {
		return nil, nil
	}
	s.archive.mu.Lock()
	defer s.archive.mu.Unlock()
	var done []string
	for {
		name, err := s.archiveOne(ctx)
		if err != nil {
			return done, err
		}
		if name == "" {
			return done, nil
		}
		done = append(done, name)
	}
}

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{domain.ErrArchiveRefused}, args...)...)
}

// archiveOne archives the oldest due month, or finishes an archive a failure interrupted; it
// returns the archive's name, or "" when nothing is due.
func (s *AuditService) archiveOne(ctx context.Context) (string, error) {
	if err := s.VerifyChain(ctx); err != nil {
		return "", refused("the chain does not verify, nothing is archived: %v", err)
	}
	events, err := s.store.All(ctx)
	if err != nil {
		return "", err
	}
	checkpoints, err := s.anchors.Checkpoints(ctx)
	if err != nil {
		return "", err
	}

	// A checkpoint whose events are still here: archived, not yet deleted (a failure between
	// the two). Finish it — if its archive is still the one it names.
	if n := len(checkpoints); n > 0 {
		last := checkpoints[n-1]
		if at := indexOf(events, last.LastID); at >= 0 {
			sum, err := s.archive.to.Sum(ctx, last.Archive)
			if err != nil {
				return "", refused("archive %s of the last checkpoint cannot be read: %v", last.Archive, err)
			}
			if !hmac.Equal(sum, last.SHA256) {
				return "", refused("archive %s is not the one its checkpoint names", last.Archive)
			}
			if !archivedEventAfter(events[at+1:], last.Archive) {
				if _, err := s.EmitEventAs(ctx, selfEmitter, "", "audit.archived", "audit", last.Archive, true); err != nil {
					return "", err
				}
			}
			if err := s.store.DeleteThrough(ctx, last.LastID, at+1); err != nil {
				return "", err
			}
			return last.Archive, nil
		}
	}

	if len(events) == 0 {
		return "", nil
	}
	month := monthOf(events[0].Timestamp)
	cutoff := monthOf(s.now()).AddDate(0, -s.archive.months, 0)
	if !month.Before(cutoff) {
		return "", nil
	}
	next := month.AddDate(0, 1, 0)
	k := 0
	for k < len(events) && events[k].Timestamp.Before(next) {
		k++
	}
	segment := events[:k]
	name := fmt.Sprintf("audit-%04d-%02d.jsonl", month.Year(), int(month.Month()))
	sum, err := s.archive.to.Write(ctx, name, segment)
	if err != nil {
		return "", refused("writing %s: %v", name, err)
	}

	start, err := s.startOfChain(events, checkpoints)
	if err != nil {
		return "", err
	}
	anchors, err := s.anchors.All(ctx)
	if err != nil {
		return "", err
	}
	inSegment := make(map[string]bool, k)
	for _, e := range segment {
		inSegment[e.ID] = true
	}
	covered := start.AnchorsCovered
	for covered < len(anchors) && inSegment[anchors[covered].EventID] {
		covered++
	}
	last := segment[k-1]
	c := domain.Checkpoint{
		Archive: name, SHA256: sum, Count: k,
		FirstID: segment[0].ID, PrevHash: segment[0].PrevHash,
		LastID: last.ID, LastHash: last.Hash, LastVersion: last.HashVersion,
		AnchorsCovered: covered, At: s.now().UTC().Truncate(time.Microsecond), KeyID: s.keys.current,
	}
	c.MAC = checkpointMAC(s.keys.keys[s.keys.current], c)
	if err := s.anchors.AppendCheckpoint(ctx, c); err != nil {
		return "", refused("the checkpoint of %s cannot be written: %v", name, err)
	}
	// The archiving itself is in the chain, before anything leaves it.
	if _, err := s.EmitEventAs(ctx, selfEmitter, "", "audit.archived", "audit", name, true); err != nil {
		return "", err
	}
	if err := s.store.DeleteThrough(ctx, last.ID, k); err != nil {
		return "", err
	}
	return name, nil
}

// monthOf is the first instant of t's calendar month, in UTC.
func monthOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// archivedEventAfter says whether the archiving of `name` is already in these events.
func archivedEventAfter(events []*domain.Event, name string) bool {
	for _, e := range events {
		if e.Action == "audit.archived" && e.ResourceID == name {
			return true
		}
	}
	return false
}

func indexOf(events []*domain.Event, id string) int {
	for i, e := range events {
		if e.ID == id {
			return i
		}
	}
	return -1
}

// checkpointTag starts every checkpoint MAC: it can never be taken for an event's or an anchor's.
const checkpointTag = "openbastion.audit.checkpoint.v1\x00"

func checkpointMAC(key []byte, c domain.Checkpoint) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(checkpointTag))
	var n [4]byte
	for _, field := range [][]byte{[]byte(c.Archive), c.SHA256, []byte(c.FirstID), c.PrevHash, []byte(c.LastID), c.LastHash, []byte(c.KeyID)} {
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		m.Write(n[:])
		m.Write(field)
	}
	var num [8]byte
	for _, v := range []uint64{uint64(c.Count), uint64(c.LastVersion), uint64(c.AnchorsCovered), uint64(c.At.UnixNano())} {
		binary.BigEndian.PutUint64(num[:], v)
		m.Write(num[:])
	}
	return m.Sum(nil)
}

// startOfChain checks the checkpoints — each genuine, under a key held, each following the one
// before — and says where the chain in the database starts: from nothing when its first event
// has no prev_hash, otherwise from the checkpoint whose last hash it follows. A first event
// that follows an event no checkpoint vouches for means the start of the chain was cut.
func (s *AuditService) startOfChain(events []*domain.Event, checkpoints []domain.Checkpoint) (domain.Checkpoint, error) {
	var prev domain.Checkpoint
	for i, c := range checkpoints {
		key, held := s.keys.keys[c.KeyID]
		if !held {
			return domain.Checkpoint{}, fmt.Errorf("checkpoint %d (%s): signed with chain key %q, which this service does not hold — it cannot vouch for it", i, c.Archive, c.KeyID)
		}
		if !hmac.Equal(checkpointMAC(key, c), c.MAC) {
			return domain.Checkpoint{}, fmt.Errorf("checkpoint %d (%s): its MAC does not match — the checkpoint was tampered with", i, c.Archive)
		}
		if string(c.PrevHash) != string(prev.LastHash) {
			return domain.Checkpoint{}, fmt.Errorf("checkpoint %d (%s) does not follow the checkpoint before it — a checkpoint is missing or out of order", i, c.Archive)
		}
		prev = c
	}
	if len(events) == 0 || len(events[0].PrevHash) == 0 {
		return domain.Checkpoint{}, nil
	}
	for _, c := range checkpoints {
		if hmac.Equal(c.LastHash, events[0].PrevHash) {
			return c, nil
		}
	}
	return domain.Checkpoint{}, fmt.Errorf("the chain starts at event %s, which follows an event no checkpoint vouches for — the start of the chain was cut", events[0].ID)
}

// checkpointsAgree: an archived event that is still in the database (not yet deleted) is the
// one its checkpoint names.
func (s *AuditService) checkpointsAgree(events []*domain.Event, checkpoints []domain.Checkpoint) error {
	for i, c := range checkpoints {
		if at := indexOf(events, c.LastID); at >= 0 && !hmac.Equal(events[at].Hash, c.LastHash) {
			return fmt.Errorf("checkpoint %d (%s): event %s does not have the hash it was archived with — the chain was rewritten", i, c.Archive, c.LastID)
		}
	}
	return nil
}
