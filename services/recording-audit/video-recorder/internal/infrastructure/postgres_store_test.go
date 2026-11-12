package infrastructure_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/infrastructure"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed Video Recorder tests")
	}
	db, err := infrastructure.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func uniqueSessionID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func runRepositoryContract(t *testing.T, repository domain.Repository) {
	t.Helper()
	ctx := context.Background()
	sessionID := uniqueSessionID("recording")
	wrapped := []byte("wrapped data encryption key")
	if err := repository.BeginRecording(ctx, sessionID, "kek-v1", wrapped); err != nil {
		t.Fatalf("BeginRecording: %v", err)
	}
	if err := repository.BeginRecording(ctx, sessionID, "kek-v1", wrapped); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("duplicate BeginRecording = %v, want ErrAlreadyExists", err)
	}

	segment := domain.SegmentMetadata{
		SessionID: sessionID, FirstSequence: 1, LastSequence: 2,
		ObjectKey: "test/" + sessionID + "/1", SHA256: make([]byte, 32),
	}
	if err := repository.AppendSegment(ctx, segment); err != nil {
		t.Fatalf("AppendSegment: %v", err)
	}
	if err := repository.AppendSegment(ctx, domain.SegmentMetadata{
		SessionID: sessionID, FirstSequence: 4, LastSequence: 4,
		ObjectKey: "test/" + sessionID + "/4", SHA256: make([]byte, 32),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("sequence gap = %v, want ErrConflict", err)
	}
	stored, err := repository.GetSegment(ctx, sessionID, 1)
	if err != nil || stored.Complete || stored.LastSequence != 2 || stored.KeyID != "kek-v1" ||
		string(stored.WrappedDEK) != string(wrapped) || stored.ObjectKey != segment.ObjectKey {
		t.Fatalf("incomplete segment read: %+v err=%v", stored, err)
	}
	if err := repository.CompleteRecording(ctx, sessionID, 1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("wrong completion sequence = %v, want ErrConflict", err)
	}
	if err := repository.CompleteRecording(ctx, sessionID, 2); err != nil {
		t.Fatalf("CompleteRecording: %v", err)
	}
	stored, err = repository.GetSegment(ctx, sessionID, 1)
	if err != nil || !stored.Complete {
		t.Fatalf("completed segment read: %+v err=%v", stored, err)
	}
	if err := repository.AppendSegment(ctx, domain.SegmentMetadata{
		SessionID: sessionID, FirstSequence: 3, LastSequence: 3,
		ObjectKey: "test/" + sessionID + "/3", SHA256: make([]byte, 32),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("append after completion = %v, want ErrConflict", err)
	}
}

func TestMemoryStore_RecordingRepositoryContract(t *testing.T) {
	runRepositoryContract(t, infrastructure.NewMemoryStore())
}

func TestPostgresStore_RecordingRepositoryContract(t *testing.T) {
	db := testDB(t)
	runRepositoryContract(t, infrastructure.NewPostgresStore(db))
}

func TestPostgresStore_ConcurrentSequenceAppendHasOneWinner(t *testing.T) {
	db := testDB(t)
	repository := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	sessionID := uniqueSessionID("concurrent")
	if err := repository.BeginRecording(ctx, sessionID, "kek-v1", []byte("wrapped key")); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			results <- repository.AppendSegment(ctx, domain.SegmentMetadata{
				SessionID: sessionID, FirstSequence: 1, LastSequence: 1,
				ObjectKey: fmt.Sprintf("test/%s/%d", sessionID, i), SHA256: make([]byte, 32),
			})
		}(i)
	}
	wait.Wait()
	close(results)

	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, domain.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected append result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("append results: %d success, %d conflicts; want one each", successes, conflicts)
	}
}

// The run of segments a read serves (ADR-0093): from the first sequence asked, in order, bounded,
// with the recording's key and status; nothing from another session.
func runSegmentRangeContract(t *testing.T, repository domain.Repository) {
	t.Helper()
	ctx := context.Background()
	sessionID := uniqueSessionID("range")
	other := uniqueSessionID("other")
	for _, id := range []string{sessionID, other} {
		if err := repository.BeginRecording(ctx, id, "kek-v1", []byte("wrapped")); err != nil {
			t.Fatal(err)
		}
	}
	for i := int64(1); i <= 5; i++ {
		if err := repository.AppendSegment(ctx, domain.SegmentMetadata{SessionID: sessionID, FirstSequence: i, LastSequence: i,
			ObjectKey: fmt.Sprintf("test/%s/%d", sessionID, i), SHA256: make([]byte, 32)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.AppendSegment(ctx, domain.SegmentMetadata{SessionID: other, FirstSequence: 1, LastSequence: 1,
		ObjectKey: "test/" + other + "/1", SHA256: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	if err := repository.CompleteRecording(ctx, sessionID, 5); err != nil {
		t.Fatal(err)
	}
	firsts := func(segments []domain.StoredSegment) []int64 {
		var out []int64
		for _, s := range segments {
			if s.SessionID != sessionID || s.KeyID != "kek-v1" || !s.Complete || s.LastSequence != s.FirstSequence {
				t.Fatalf("segment %+v", s)
			}
			out = append(out, s.FirstSequence)
		}
		return out
	}
	for _, c := range []struct {
		first int64
		limit int
		want  string
	}{{1, 10, "[1 2 3 4 5]"}, {3, 10, "[3 4 5]"}, {2, 2, "[2 3]"}, {6, 10, "[]"}, {1, 0, "[]"}} {
		got, err := repository.GetSegmentsFrom(ctx, sessionID, c.first, c.limit)
		if err != nil || fmt.Sprint(firsts(got)) != c.want {
			t.Fatalf("from %d, limit %d: %v, %v; want %s", c.first, c.limit, firsts(got), err, c.want)
		}
	}
	if got, err := repository.GetSegmentsFrom(ctx, "no-such-session", 1, 10); err != nil || len(got) != 0 {
		t.Fatalf("an unknown session: %v, %v", got, err)
	}
}

func TestMemoryStore_SegmentRangeContract(t *testing.T) {
	runSegmentRangeContract(t, infrastructure.NewMemoryStore())
}

func TestPostgresStore_SegmentRangeContract(t *testing.T) {
	runSegmentRangeContract(t, infrastructure.NewPostgresStore(testDB(t)))
}
