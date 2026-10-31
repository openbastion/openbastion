package infrastructure

// ADR-0055: a session key re-wrapped by another process between RewrapDue's read and its write is
// left as the other process wrote it: the update is a compare-and-swap on the old key.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
)

// localWrapper is a KeyWrapper of its own id, under a fresh key.
type localWrapper struct {
	id  string
	key [32]byte
}

func newLocalWrapper(id string) *localWrapper {
	w := &localWrapper{id: id}
	_, _ = rand.Read(w.key[:])
	return w
}
func (w *localWrapper) KeyID() string                        { return w.id }
func (w *localWrapper) Wrap(dek, aad []byte) ([]byte, error) { return gcmSeal(w.key[:], dek, aad) }
func (w *localWrapper) Unwrap(wr, aad []byte) ([]byte, error) {
	return gcmOpen(w.key[:], wr, aad)
}

func TestRewrapDue_AKeyChangedBetweenTheReadAndTheWriteIsLeftToTheOtherWriter(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed tests (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	run := time.Now().Format("150405.000000000")
	a, b, c := newLocalWrapper("race-a-"+run), newLocalWrapper("race-b-"+run), newLocalWrapper("race-c-"+run)
	session := "race-session-" + run
	before, err := NewPostgresStore(ctx, db, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := before.AppendBatch(ctx, []domain.CommandEntry{{SessionID: session, Timestamp: time.Now().UTC().Truncate(time.Microsecond), Command: "id"}}); err != nil {
		t.Fatal(err)
	}
	other, _ := NewPostgresStore(ctx, db, c, a)
	rewrapRace = func(s string) {
		rewrapRace = nil // the other process re-wraps once, under c
		if r, err := other.RewrapDue(ctx, ""); err != nil || r.Rewrapped == 0 {
			t.Errorf("the other process: %+v, %v", r, err)
		}
	}
	defer func() { rewrapRace = nil }()
	mine, _ := NewPostgresStore(ctx, db, b, a)
	r, err := mine.RewrapDue(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var kek string
	_ = db.QueryRowContext(ctx, `SELECT kek_id FROM session_recording_keys WHERE session_id = $1`, session).Scan(&kek)
	if kek != c.KeyID() || r.Rewrapped != 0 {
		t.Fatalf("after the race the key is under %q, %d re-wrapped by me; want under %q, none by me", kek, r.Rewrapped, c.KeyID())
	}
	onlyC, _ := NewPostgresStore(ctx, db, c)
	if got, _, err := onlyC.ListBySession(ctx, session, 1, 10); err != nil || len(got) != 1 {
		t.Fatalf("the recording under the other writer's key: %v, %v", got, err)
	}
}
