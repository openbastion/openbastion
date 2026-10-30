package application

// Archiving the chain out of the database without making it unverifiable (ADR-0032).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

// memoryArchiver keeps archives as bytes, as the file archiver would.
type memoryArchiver struct {
	files map[string][]byte
	err   error
}

func (m *memoryArchiver) Write(_ context.Context, name string, events []*domain.Event) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	var b bytes.Buffer
	for _, e := range events {
		fmt.Fprintf(&b, "%s %x\n", e.ID, e.Hash)
	}
	if old, ok := m.files[name]; ok && !bytes.Equal(old, b.Bytes()) {
		return nil, errors.New("exists and differs")
	}
	m.files[name] = b.Bytes()
	sum := sha256.Sum256(b.Bytes())
	return sum[:], nil
}

func (m *memoryArchiver) Sum(_ context.Context, name string) ([]byte, error) {
	b, ok := m.files[name]
	if !ok {
		return nil, errors.New("no such archive")
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// flakyStore fails its next deletions.
type flakyStore struct {
	*infrastructure.InMemoryStore
	failDeletes int
}

func (f *flakyStore) DeleteThrough(ctx context.Context, lastID string, expected int) error {
	if f.failDeletes > 0 {
		f.failDeletes--
		return errors.New("the database went away")
	}
	return f.InMemoryStore.DeleteThrough(ctx, lastID, expected)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 10, 0, 0, 0, time.UTC) }

// archivingService: three events in January 2025, two in February, two in March, the head
// anchored at the end of each month; the clock then at 20 April, retention one month.
func archivingService(t *testing.T) (*AuditService, *flakyStore, *memoryAnchors, *memoryArchiver, *clock) {
	return archivingServiceAnchored(t, true)
}

// archivingServiceAnchored, with anchored false, writes no anchor: what a deployment has when
// archiving runs at start, before the first anchor.
func archivingServiceAnchored(t *testing.T, anchored bool) (*AuditService, *flakyStore, *memoryAnchors, *memoryArchiver, *clock) {
	t.Helper()
	store := &flakyStore{InMemoryStore: infrastructure.NewInMemoryStore()}
	sink := &memoryAnchors{}
	arch := &memoryArchiver{files: map[string][]byte{}}
	c := &clock{}
	svc := NewAuditService(store).WithChainKeys(mustKeys(t, keyA, "")).WithAnchors(sink).WithArchive(arch, 1)
	svc.now = c.now
	for _, month := range []struct {
		m time.Month
		n int
	}{{time.January, 3}, {time.February, 2}, {time.March, 2}} {
		for i := 0; i < month.n; i++ {
			c.t = day(2025, month.m, 1+i)
			emitN(t, svc, 1)
		}
		if !anchored {
			continue
		}
		if _, err := svc.Anchor(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	c.t = day(2025, time.April, 20)
	return svc, store, sink, arch, c
}

func actions(t *testing.T, s Store) []string {
	t.Helper()
	all, _ := s.All(context.Background())
	var out []string
	for _, e := range all {
		out = append(out, e.Action+"@"+e.Timestamp.Format("01-02"))
	}
	return out
}

func TestArchive_IsOffUnlessAsked(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := NewAuditService(store).WithAnchors(&memoryAnchors{})
	svc.now = (&clock{day(2020, time.January, 1)}).now
	emitN(t, svc, 2)
	svc.now = (&clock{day(2030, time.January, 1)}).now
	if names, err := svc.ArchiveDue(context.Background()); err != nil || len(names) != 0 {
		t.Fatalf("no archive configured: archived %v, %v", names, err)
	}
	if all, _ := store.All(context.Background()); len(all) != 2 {
		t.Fatalf("%d events left, want 2: nothing leaves without retention", len(all))
	}
}

func TestArchive_TheMonthsOlderThanTheRetentionLeave_AndTheChainStillVerifies(t *testing.T) {
	svc, store, sink, arch, _ := archivingService(t)
	ctx := context.Background()
	names, err := svc.ArchiveDue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(names) != "[audit-2025-01.jsonl audit-2025-02.jsonl]" {
		t.Fatalf("archived %v, want January and February — March is within the retention", names)
	}
	want := "[session.read@03-01 session.read@03-02 audit.archived@04-20 audit.archived@04-20]"
	if got := fmt.Sprint(actions(t, store)); got != want {
		t.Fatalf("left in the database %s, want %s", got, want)
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("the chain left after archiving does not verify: %v", err)
	}
	if n := strings.Count(string(arch.files["audit-2025-01.jsonl"]), "\n"); n != 3 {
		t.Fatalf("January's archive holds %d events, want 3", n)
	}
	cps := sink.checkpoints
	if len(cps) != 2 || cps[0].Count != 3 || cps[1].Count != 2 || cps[0].AnchorsCovered != 1 || cps[1].AnchorsCovered != 2 ||
		cps[0].PrevHash != nil || !bytes.Equal(cps[1].PrevHash, cps[0].LastHash) {
		t.Fatalf("checkpoints %+v", cps)
	}
	all, _ := store.All(ctx)
	if !bytes.Equal(all[0].PrevHash, cps[1].LastHash) {
		t.Fatal("the first event left does not follow the last checkpoint")
	}
	for _, e := range all[2:] {
		if e.Emitter != selfEmitter || e.ResourceType != "audit" {
			t.Fatalf("the archiving event %+v is not the Audit Service's own", e)
		}
	}
	// Nothing more is due, and a second pass changes nothing.
	if names, err := svc.ArchiveDue(ctx); err != nil || len(names) != 0 {
		t.Fatalf("second pass archived %v, %v", names, err)
	}
}

func TestArchive_NothingLeavesAChainThatDoesNotVerify(t *testing.T) {
	svc, store, sink, arch, _ := archivingService(t)
	all, _ := store.All(context.Background())
	all[4].ResourceID = "tampered"
	_, err := svc.ArchiveDue(context.Background())
	if !errors.Is(err, domain.ErrArchiveRefused) {
		t.Fatalf("got %v, want ErrArchiveRefused", err)
	}
	if left, _ := store.All(context.Background()); len(left) != 7 || len(sink.checkpoints) != 0 || len(arch.files) != 0 {
		t.Fatalf("%d events left, %d checkpoints, %d archives: nothing may move", len(left), len(sink.checkpoints), len(arch.files))
	}
}

func TestArchive_AnArchiveThatCannotBeWrittenTakesNothingOut(t *testing.T) {
	svc, store, sink, arch, _ := archivingService(t)
	arch.err = errors.New("disk full")
	if _, err := svc.ArchiveDue(context.Background()); !errors.Is(err, domain.ErrArchiveRefused) {
		t.Fatalf("got %v, want ErrArchiveRefused", err)
	}
	if left, _ := store.All(context.Background()); len(left) != 7 || len(sink.checkpoints) != 0 {
		t.Fatalf("%d events left, %d checkpoints: nothing may move", len(left), len(sink.checkpoints))
	}
}

func TestArchive_AFailureBeforeTheDeletionIsFinishedNextTime_Once(t *testing.T) {
	svc, store, sink, _, _ := archivingService(t)
	ctx := context.Background()
	store.failDeletes = 1
	if _, err := svc.ArchiveDue(ctx); err == nil {
		t.Fatal("the deletion failed, ArchiveDue said nothing")
	}
	if len(sink.checkpoints) != 1 {
		t.Fatalf("%d checkpoints, want 1", len(sink.checkpoints))
	}
	// Archived and checkpointed but still here: the chain verifies as it is.
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("between checkpoint and deletion: %v", err)
	}
	names, err := svc.ArchiveDue(ctx)
	if err != nil || fmt.Sprint(names) != "[audit-2025-01.jsonl audit-2025-02.jsonl]" {
		t.Fatalf("next pass %v, %v, want January finished then February", names, err)
	}
	n := 0
	for _, a := range actions(t, store) {
		if strings.HasPrefix(a, "audit.archived") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d archiving events, want 2 — January's is not written twice", n)
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestArchive_AFailureBeforeTheArchivingEventIsWrittenStillWritesIt(t *testing.T) {
	svc, store, sink, arch, c := archivingService(t)
	ctx := context.Background()
	// The archive and its checkpoint are written, then the process stops: no event, no deletion.
	all, _ := store.All(ctx)
	sum, _ := arch.Write(ctx, "audit-2025-01.jsonl", all[:3])
	cp := domain.Checkpoint{Archive: "audit-2025-01.jsonl", SHA256: sum, Count: 3, FirstID: all[0].ID, LastID: all[2].ID,
		LastHash: all[2].Hash, LastVersion: all[2].HashVersion, AnchorsCovered: 1, At: c.t, KeyID: svc.keys.current}
	cp.MAC = checkpointMAC(svc.keys.keys[svc.keys.current], cp)
	_ = sink.AppendCheckpoint(ctx, cp)
	if _, err := svc.ArchiveDue(ctx); err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(actions(t, store))
	if strings.Count(got, "audit.archived") != 2 {
		t.Fatalf("left %s: January's archiving is written when the deletion is finished", got)
	}
}

func TestArchive_AnArchiveChangedBeforeTheDeletionIsNotTrusted(t *testing.T) {
	svc, store, _, arch, _ := archivingService(t)
	ctx := context.Background()
	store.failDeletes = 1
	_, _ = svc.ArchiveDue(ctx)
	arch.files["audit-2025-01.jsonl"] = []byte("something else\n")
	if _, err := svc.ArchiveDue(ctx); !errors.Is(err, domain.ErrArchiveRefused) {
		t.Fatalf("got %v, want ErrArchiveRefused", err)
	}
	if left, _ := store.All(ctx); len(left) != 8 {
		t.Fatalf("%d events left, want 8: January stays until its archive is the one checkpointed", len(left))
	}
}

func TestVerifyChain_TheStartCutWithoutACheckpointIsFound(t *testing.T) {
	ctx := context.Background()
	t.Run("never archived", func(t *testing.T) {
		svc, store, _, _, _ := archivingService(t)
		_ = store.InMemoryStore.DeleteThrough(ctx, firstID(t, store), 1)
		if err := svc.VerifyChain(ctx); err == nil || !strings.Contains(err.Error(), "start of the chain was cut") {
			t.Fatalf("got %v, want the cut start found", err)
		}
	})
	t.Run("past the last checkpoint", func(t *testing.T) {
		svc, store, _, _, _ := archivingService(t)
		if _, err := svc.ArchiveDue(ctx); err != nil {
			t.Fatal(err)
		}
		_ = store.InMemoryStore.DeleteThrough(ctx, firstID(t, store), 1)
		if err := svc.VerifyChain(ctx); err == nil || !strings.Contains(err.Error(), "start of the chain was cut") {
			t.Fatalf("got %v, want the cut start found", err)
		}
	})
}

func firstID(t *testing.T, s Store) string {
	all, _ := s.All(context.Background())
	return all[0].ID
}

func TestVerifyChain_ACheckpointTamperedMissingOrForgedIsFound(t *testing.T) {
	ctx := context.Background()
	for name, tamper := range map[string]func(sink *memoryAnchors){
		"a field changed":        func(s *memoryAnchors) { s.checkpoints[1].Count = 99 },
		"the first removed":      func(s *memoryAnchors) { s.checkpoints = s.checkpoints[1:] },
		"the last removed":       func(s *memoryAnchors) { s.checkpoints = s.checkpoints[:1] },
		"anchors covered raised": func(s *memoryAnchors) { s.checkpoints[1].AnchorsCovered = 3 },
		"reordered": func(s *memoryAnchors) {
			s.checkpoints[0], s.checkpoints[1] = s.checkpoints[1], s.checkpoints[0]
		},
		"forged under another key": func(s *memoryAnchors) {
			c := s.checkpoints[1]
			c.AnchorsCovered = 3
			c.MAC = checkpointMAC(mustHex(keyB), c)
			s.checkpoints[1] = c
		},
	} {
		svc, _, sink, _, _ := archivingService(t)
		if _, err := svc.ArchiveDue(ctx); err != nil {
			t.Fatal(err)
		}
		tamper(sink)
		if err := svc.VerifyChain(ctx); err == nil {
			t.Fatalf("%s: verify-chain passed", name)
		}
	}
}

func TestVerifyChain_AnAnchorPastTheArchivedOnesMustStillBeThere(t *testing.T) {
	svc, store, _, _, _ := archivingService(t)
	ctx := context.Background()
	if _, err := svc.ArchiveDue(ctx); err != nil {
		t.Fatal(err)
	}
	// March's anchor named its second event: remove the end of the chain, it is not archived.
	all, _ := store.All(ctx)
	store.InMemoryStore = infrastructure.NewInMemoryStore()
	_ = store.InMemoryStore.Append(ctx, all[0])
	if err := svc.VerifyChain(ctx); err == nil || !strings.Contains(err.Error(), "not in the chain") {
		t.Fatalf("got %v, want the anchor of an unarchived event missing", err)
	}
}

func TestArchive_TheCurrentMonthAndTheRetainedOnesStay(t *testing.T) {
	svc, store, _, _, c := archivingService(t)
	c.t = day(2025, time.March, 31) // retention one month: only January is older than February
	names, err := svc.ArchiveDue(context.Background())
	if err != nil || fmt.Sprint(names) != "[audit-2025-01.jsonl]" {
		t.Fatalf("archived %v, %v, want January only", names, err)
	}
	if left := actions(t, store); len(left) != 5 {
		t.Fatalf("left %v", left)
	}
}

func TestCheckpointMAC_TheFormatIsFixed(t *testing.T) {
	c := domain.Checkpoint{Archive: "audit-2025-01.jsonl", SHA256: bytes.Repeat([]byte{0x11}, 32), Count: 3, FirstID: "evt_1",
		LastID: "evt_3", LastHash: bytes.Repeat([]byte{0x22}, 32), LastVersion: 3, AnchorsCovered: 2,
		At: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), KeyID: "k1"}
	if got := hexOf(checkpointMAC(mustHex(keyA), c)); got != wantCheckpointMAC {
		t.Fatalf("checkpoint MAC = %s, want %s", got, wantCheckpointMAC)
	}
}

// Computed independently (Python's hmac) before being written here.
const wantCheckpointMAC = "90f3591f741bbd4d83b1822eb137792b20ac3aefdfe89d20fe6916ca1acd28df"

// rewriteUnkeyed rewrites every event of the store in v2, the format an attacker computes
// without the key, keeping each id and the first prev_hash.
func rewriteUnkeyed(t *testing.T, s Store) {
	t.Helper()
	all, _ := s.All(context.Background())
	var prev []byte
	if len(all) > 0 {
		prev = all[0].PrevHash
	}
	for _, e := range all {
		e.ResourceID = "rewritten"
		e.PrevHash, e.HashVersion, e.Emitter, e.KeyID = prev, domain.HashV2, "", ""
		e.Hash = computeHashV2(e)
		prev = e.Hash
	}
}

func TestVerifyChain_NoAnchorYet_AChainRewrittenUnkeyedWhileItsArchiveIsPendingIsFound(t *testing.T) {
	svc, store, _, _, _ := archivingServiceAnchored(t, false)
	ctx := context.Background()
	store.failDeletes = 1
	_, _ = svc.ArchiveDue(ctx) // January archived and checkpointed, still in the database
	rewriteUnkeyed(t, store)
	if err := svc.VerifyChain(ctx); err == nil || !strings.Contains(err.Error(), "archived with") {
		t.Fatalf("got %v, want the checkpointed event found rewritten", err)
	}
}

func TestVerifyChain_NoAnchorYet_TheChainLeftRewrittenUnkeyedIsFound(t *testing.T) {
	svc, store, _, _, _ := archivingServiceAnchored(t, false)
	ctx := context.Background()
	if _, err := svc.ArchiveDue(ctx); err != nil {
		t.Fatal(err)
	}
	rewriteUnkeyed(t, store) // from the checkpoint's hash on, in the format with no key
	if err := svc.VerifyChain(ctx); err == nil || !strings.Contains(err.Error(), "hash version 2 after version 3") {
		t.Fatalf("got %v, want the version going back after the checkpoint found", err)
	}
}

func TestVerifyChain_ACheckpointUnderAKeyNoLongerHeldSaysSo(t *testing.T) {
	svc, _, _, _, _ := archivingService(t)
	ctx := context.Background()
	if _, err := svc.ArchiveDue(ctx); err != nil {
		t.Fatal(err)
	}
	svc.WithChainKeys(mustKeys(t, keyB, "")) // keyA lost
	err := svc.VerifyChain(ctx)
	if err == nil || !strings.Contains(err.Error(), "checkpoint 0") || !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("got %v, want the checkpoint named as signed with a key not held", err)
	}
}
