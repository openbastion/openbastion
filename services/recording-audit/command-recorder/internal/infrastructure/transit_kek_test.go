package infrastructure_test

// ADR-0049 on PostgreSQL: once Transit is the key, a session's data key is wrapped there; what was
// wrapped under KMS_KEY_HEX before stays readable while that key is held as a previous one, and is
// refused — by name — once it is not.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
)

// playedTransit wraps for real (AES-GCM, aad bound) under its own key.
type playedTransit struct {
	gcm cipher.AEAD
	id  string
}

func newPlayedTransit() *playedTransit { return newPlayedTransitNamed("transit:transit/recorder") }

func newPlayedTransitNamed(id string) *playedTransit {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return &playedTransit{gcm: g, id: id}
}

func (p *playedTransit) KeyID() string { return p.id }
func (p *playedTransit) Encrypt(_ context.Context, pt, aad []byte) (string, error) {
	n := make([]byte, p.gcm.NonceSize())
	_, _ = rand.Read(n)
	return "vault:v1:" + base64.StdEncoding.EncodeToString(p.gcm.Seal(n, n, pt, aad)), nil
}
func (p *playedTransit) Decrypt(_ context.Context, ct string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "vault:v1:"))
	if err != nil || len(raw) < p.gcm.NonceSize() {
		return nil, errors.New("not a ciphertext")
	}
	return p.gcm.Open(nil, raw[:p.gcm.NonceSize()], raw[p.gcm.NonceSize():], aad)
}

func TestPostgresStore_FromTheLocalKeyToTransit_NothingBecomesUnreadable(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	old, fresh := uniqueID("before-transit"), uniqueID("after-transit")

	before := testPostgresStore(t, db, kekHexA)
	if err := before.AppendBatch(ctx, []domain.CommandEntry{{SessionID: old, Timestamp: t0, Command: "whoami"}}); err != nil {
		t.Fatal(err)
	}

	tr := infrastructure.NewTransitKEK(newPlayedTransit())
	after, err := infrastructure.NewPostgresStore(ctx, db, tr, testKEK(t, kekHexA))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := after.ListBySession(ctx, old, 1, 10); err != nil || !same(cmds(got), []string{"whoami"}) {
		t.Fatalf("a recording from before the switch: %v, %v", cmds(got), err)
	}
	if err := after.AppendBatch(ctx, []domain.CommandEntry{{SessionID: fresh, Timestamp: t0, Command: "id"}}); err != nil {
		t.Fatal(err)
	}
	var kekID string
	if err := db.QueryRowContext(ctx, `SELECT kek_id FROM session_recording_keys WHERE session_id = $1`, fresh).Scan(&kekID); err != nil || kekID != tr.KeyID() {
		t.Fatalf("a new session's key is wrapped under %q (%v), want %q", kekID, err, tr.KeyID())
	}
	if _, _, err := before.ListBySession(ctx, fresh, 1, 10); err == nil {
		t.Fatal("the local key alone read a session wrapped by Transit")
	}

	only, err := infrastructure.NewPostgresStore(ctx, db, tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := only.ListBySession(ctx, old, 1, 10); err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("without the previous key: %v, want a refusal that names the key it lacks", err)
	}
	if _, err := infrastructure.NewPostgresStore(ctx, db, tr, tr); err == nil {
		t.Fatal("a key given twice was accepted")
	}
}

// ADR-0055 on PostgreSQL: the session keys an earlier key still wraps are re-wrapped under the
// current one, the recording unchanged; then the earlier key is not needed any more. Two keys
// of their own, so that the rows other tests leave in the table are not touched.
func TestPostgresStore_RewrapDue_TheEarlierKeyIsNotNeededAfterwards(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	run := uniqueID("rewrap")
	a := infrastructure.NewTransitKEK(newPlayedTransitNamed("transit:test/a-" + run))
	b := infrastructure.NewTransitKEK(newPlayedTransitNamed("transit:test/b-" + run))
	sessions := []string{uniqueID("rw1"), uniqueID("rw2")}

	before, err := infrastructure.NewPostgresStore(ctx, db, a)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		if err := before.AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: t0, Command: "ls " + s}}); err != nil {
			t.Fatal(err)
		}
	}
	both, err := infrastructure.NewPostgresStore(ctx, db, b, a)
	if err != nil {
		t.Fatal(err)
	}
	r, err := both.RewrapDue(ctx, "")
	if err != nil || r.Rewrapped != 2 || r.Next != "" || r.Skipped != 0 {
		t.Fatalf("RewrapDue = %+v, %v; want the 2 sessions, the last page", r, err)
	}
	if r, err := both.RewrapDue(ctx, ""); r.Found != 0 || err != nil {
		t.Fatalf("a second pass: %+v, %v; want nothing found", r, err)
	}
	onlyB, _ := infrastructure.NewPostgresStore(ctx, db, b)
	for _, s := range sessions {
		got, _, err := onlyB.ListBySession(ctx, s, 1, 10)
		if err != nil || !same(cmds(got), []string{"ls " + s}) {
			t.Fatalf("%s with the current key alone, after the rewrap: %v, %v", s, cmds(got), err)
		}
		var kek string
		_ = db.QueryRowContext(ctx, `SELECT kek_id FROM session_recording_keys WHERE session_id = $1`, s).Scan(&kek)
		if kek != b.KeyID() {
			t.Fatalf("%s is wrapped under %q", s, kek)
		}
	}
}

// A session key the earlier key does not unwrap (altered, or of another era) is skipped and
// counted; the others are re-wrapped all the same.
func TestPostgresStore_RewrapDue_AKeyThatDoesNotUnwrapIsSkipped_TheOthersAreNot(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	run := uniqueID("rewrap-skip")
	a := infrastructure.NewTransitKEK(newPlayedTransitNamed("transit:test/a-" + run))
	b := infrastructure.NewTransitKEK(newPlayedTransitNamed("transit:test/b-" + run))
	broken, fine := uniqueID("rws-broken"), uniqueID("rws-fine")
	before, _ := infrastructure.NewPostgresStore(ctx, db, a)
	for _, s := range []string{broken, fine} {
		if err := before.AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: t0, Command: "id"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE session_recording_keys SET wrapped_dek = 'vault:v1:AAAA' WHERE session_id = $1`, broken); err != nil {
		t.Fatal(err)
	}
	both, _ := infrastructure.NewPostgresStore(ctx, db, b, a)
	r, err := both.RewrapDue(ctx, "")
	if err != nil || r.Rewrapped != 1 || r.Skipped != 1 {
		t.Fatalf("RewrapDue = %+v, %v; want 1 re-wrapped, 1 skipped", r, err)
	}
	var kek string
	_ = db.QueryRowContext(ctx, `SELECT kek_id FROM session_recording_keys WHERE session_id = $1`, broken).Scan(&kek)
	if kek != a.KeyID() {
		t.Fatalf("the key that does not unwrap was changed: %q", kek)
	}
}
