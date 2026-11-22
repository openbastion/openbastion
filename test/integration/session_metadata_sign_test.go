package integration_test

// The canonical form and MAC of ADR-0116, written again here, apart from the Session Broker's own
// (services/access/session-broker/internal/domain/metadata.go): a test that writes a session row in
// SQL signs it as the Broker would, and a change of the Broker's format that this copy does not
// follow fails these tests instead of passing silently.

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// signedSessionRow is the protected fields of a session row, as a test inserts it.
type signedSessionRow struct {
	ID, Status, Protocol, RequestedBy, Account, Justification string
	CreatedAt, ExpiresAt                                      time.Time
	BreakGlass, AfterUseOwed                                  bool
}

// sessionMetadataCanonical is the canonical form v1 of the row.
func sessionMetadataCanonical(r signedSessionRow) []byte {
	b := []byte{1}
	str := func(v string) { b = binary.BigEndian.AppendUint32(b, uint32(len(v))); b = append(b, v...) }
	i64 := func(v int64) { b = binary.BigEndian.AppendUint64(b, uint64(v)) }
	flag := func(v bool) {
		if v {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	micro := func(t time.Time) int64 { return t.UTC().Truncate(time.Microsecond).UnixMicro() }
	str(r.ID)
	str(r.Status)
	str(r.Protocol)
	str(r.RequestedBy)
	str(r.Account)
	str(r.Justification)
	i64(micro(r.CreatedAt))
	i64(micro(r.ExpiresAt))
	flag(false) // terminated_at
	i64(0)      // duration_minutes
	flag(r.BreakGlass)
	flag(false) // approval_required
	str("")     // ticket
	str("")     // decided_by
	flag(false) // decided_at
	flag(false) // clipboard_to_target
	flag(false) // clipboard_from_target
	flag(r.AfterUseOwed)
	return b
}

func sessionMetadataMAC(t *testing.T, r signedSessionRow, revision uint64, keyID string) []byte {
	t.Helper()
	raw, err := os.ReadFile(testMetadataKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	b := sessionMetadataCanonical(r)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("openbastion/session-metadata/v1\x00"))
	var head [8]byte
	binary.BigEndian.PutUint64(head[:], revision)
	m.Write(head[:])
	binary.BigEndian.PutUint32(head[:4], uint32(len(keyID)))
	m.Write(head[:4])
	m.Write([]byte(keyID))
	m.Write(b)
	return m.Sum(nil)
}

// insertSignedSession writes r as revision 1 under the tests' key ("k1", the Broker's default).
func insertSignedSession(t *testing.T, db *sql.DB, r signedSessionRow) {
	t.Helper()
	r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC().Truncate(time.Microsecond), r.ExpiresAt.UTC().Truncate(time.Microsecond)
	if _, err := db.Exec(`INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, break_glass,
			metadata_revision, metadata_key_id, metadata_mac)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, 'k1', $10)`,
		r.ID, r.Status, r.Protocol, r.RequestedBy, r.Account, r.Justification, r.CreatedAt, r.ExpiresAt, r.BreakGlass,
		sessionMetadataMAC(t, r, 1, "k1")); err != nil {
		t.Fatal(err)
	}
}
