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
type playedTransit struct{ gcm cipher.AEAD }

func newPlayedTransit() *playedTransit {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return &playedTransit{gcm: g}
}

func (p *playedTransit) KeyID() string { return "transit:transit/recorder" }
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
