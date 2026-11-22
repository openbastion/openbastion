package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

// The attestation of a session's metadata (ADR-0116). A role allowed to write the sessions table
// could change who asked, for which account, with which rights and until when; the Broker therefore
// keeps, with each row, an HMAC-SHA-256 under a key PostgreSQL never holds, over a canonical form of
// every field a security decision reads. A row whose MAC does not verify is not used: the read fails
// closed. (The independent head that makes an old, valid row unreplayable is ADR-0116 §3, the Audit
// Service's: not this file's.)

// MetadataFormatVersion is the version of the canonical form below; a change of field, order or
// encoding is a new version, never a silent one.
const MetadataFormatVersion = 1

// metadataDomain separates this MAC from every other use of the key.
const metadataDomain = "openbastion/session-metadata/v1\x00"

// MetadataKeyBytes is the size of the HMAC key (ADR-0116 §2).
const MetadataKeyBytes = 32

// MetadataIntegrity is what a store says of the row a session was read from. The zero value is
// neither: a session whose integrity nobody established is not used for a privileged action.
type MetadataIntegrity string

const (
	// IntegrityAttested: the row's MAC verified under a key the Broker holds.
	IntegrityAttested MetadataIntegrity = "attested"
	// IntegrityLegacyUnverified: a row written before ADR-0116, never signed and never to be signed
	// (§8): shown read-only, never connected to, decided, terminated nor typed into.
	IntegrityLegacyUnverified MetadataIntegrity = "legacy_unverified"
)

// ErrMetadataIntegrity is a row whose MAC is missing, malformed or wrong, or whose key is unknown:
// its metadata may have been changed outside the Broker. Nothing is done with it.
var ErrMetadataIntegrity = errors.New("session metadata failed its integrity check")

// ErrMetadataUnverified is a privileged action on a legacy, unattested session (ADR-0116 §8).
var ErrMetadataUnverified = errors.New("this session predates the attestation of session metadata (ADR-0116): it is read-only")

// MetadataKey is one HMAC key and the identifier stored with the rows it signs.
type MetadataKey struct {
	ID  string
	Key []byte
}

// RequireAttested refuses a privileged action on a session whose row was not attested.
func (s *Session) RequireAttested() error {
	switch s.Integrity {
	case IntegrityAttested:
		return nil
	case IntegrityLegacyUnverified:
		return ErrMetadataUnverified
	default:
		return ErrMetadataIntegrity
	}
}

// metadataTime is a time as PostgreSQL keeps it: microseconds, UTC. The canonical form uses it so
// that a time read back from the table encodes as the one that was signed.
func metadataTime(t time.Time) int64 { return t.UTC().Truncate(time.Microsecond).UnixMicro() }

// TruncateMetadataTimes rounds every time of s down to the microsecond, as the store writes them,
// so that what is signed is exactly what is stored.
func TruncateMetadataTimes(s *Session) {
	s.CreatedAt = s.CreatedAt.UTC().Truncate(time.Microsecond)
	s.ExpiresAt = s.ExpiresAt.UTC().Truncate(time.Microsecond)
	if s.TerminatedAt != nil {
		t := s.TerminatedAt.UTC().Truncate(time.Microsecond)
		s.TerminatedAt = &t
	}
	if s.DecidedAt != nil {
		t := s.DecidedAt.UTC().Truncate(time.Microsecond)
		s.DecidedAt = &t
	}
}

// CanonicalMetadata is the canonical form of the session's protected fields (ADR-0116 §1): a version
// byte, then each field in a fixed order, every variable-length one prefixed by its length, so that
// no two different sessions encode alike. JSON is not used: its encodings are not unique.
//
// Covered: identity (ID, requester), target (account, protocol), purpose (justification, ticket),
// lifecycle (status, creation, end, termination), approval (required, decider, decision time),
// rights (break-glass, clipboard), and the debt of telling the Vault the session ended (ADR-0044),
// whose loss would skip a rotation. Not covered: the bookkeeping of the expiry's audit delivery,
// which grants nothing.
func CanonicalMetadata(s *Session) []byte {
	b := make([]byte, 0, 256)
	b = append(b, MetadataFormatVersion)
	str := func(v string) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	i64 := func(v int64) { b = binary.BigEndian.AppendUint64(b, uint64(v)) }
	flag := func(v bool) {
		if v {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	optTime := func(t *time.Time) {
		flag(t != nil)
		if t != nil {
			i64(metadataTime(*t))
		}
	}
	str(s.ID)
	str(string(s.Status))
	str(s.Protocol)
	str(s.RequestedBy)
	str(s.PrivilegedAccountID)
	str(s.Justification)
	i64(metadataTime(s.CreatedAt))
	i64(metadataTime(s.ExpiresAt))
	optTime(s.TerminatedAt)
	i64(int64(s.DurationMinutes))
	flag(s.BreakGlass)
	flag(s.ApprovalRequired)
	str(s.Ticket)
	str(s.DecidedBy)
	optTime(s.DecidedAt)
	flag(s.ClipboardToTarget)
	flag(s.ClipboardFromTarget)
	flag(s.AfterUseOwed)
	return b
}

// MetadataDigest is the SHA-256 of the canonical form: what the Audit Service will hold as the head
// of each revision (ADR-0116 §3), never the metadata itself.
func MetadataDigest(s *Session) [sha256.Size]byte { return sha256.Sum256(CanonicalMetadata(s)) }

// metadataMAC covers the domain, the format, the revision and the key's identifier with the
// canonical form (§1): a MAC cannot be moved to another revision nor to another key.
func metadataMAC(key MetadataKey, s *Session, revision uint64) []byte {
	m := hmac.New(sha256.New, key.Key)
	m.Write([]byte(metadataDomain))
	var head [8]byte
	binary.BigEndian.PutUint64(head[:], revision)
	m.Write(head[:])
	binary.BigEndian.PutUint32(head[:4], uint32(len(key.ID)))
	m.Write(head[:4])
	m.Write([]byte(key.ID))
	m.Write(CanonicalMetadata(s))
	return m.Sum(nil)
}

// SignMetadata is the MAC of s at revision under key.
func SignMetadata(key MetadataKey, s *Session, revision uint64) []byte {
	return metadataMAC(key, s, revision)
}

// VerifyMetadata checks mac, written under keyID at revision, against s and the keys the Broker
// holds. Any doubt is ErrMetadataIntegrity.
func VerifyMetadata(keys []MetadataKey, keyID string, mac []byte, s *Session, revision uint64) error {
	if revision == 0 || len(mac) != sha256.Size {
		return ErrMetadataIntegrity
	}
	for _, k := range keys {
		if k.ID == keyID && len(k.Key) == MetadataKeyBytes {
			if hmac.Equal(mac, metadataMAC(k, s, revision)) {
				return nil
			}
			return ErrMetadataIntegrity
		}
	}
	return ErrMetadataIntegrity
}
