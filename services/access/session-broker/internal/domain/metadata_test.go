package domain_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

var testKey = domain.MetadataKey{ID: "k1", Key: bytes.Repeat([]byte{7}, domain.MetadataKeyBytes)}

func sampleSession() *domain.Session {
	decided := time.Date(2026, 11, 22, 10, 0, 0, 123456000, time.UTC)
	return &domain.Session{
		ID: "session_1", Status: domain.StatusActive, Protocol: "rdp", RequestedBy: "alice",
		PrivilegedAccountID: "acc_1", Justification: "maintenance",
		CreatedAt: time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 11, 22, 11, 0, 0, 0, time.UTC),
		DurationMinutes: 60, BreakGlass: false, ApprovalRequired: true, Ticket: "CHG-1", DecidedBy: "bob", DecidedAt: &decided,
		ClipboardToTarget: true,
	}
}

// Each protected field, changed alone, breaks the MAC: a write to any of them outside the Broker
// is seen (ADR-0116, validation: "mutation directe SQL de chaque champ protégé").
func TestMetadata_EveryProtectedFieldIsCovered(t *testing.T) {
	mac := domain.SignMetadata(testKey, sampleSession(), 3)
	if err := domain.VerifyMetadata([]domain.MetadataKey{testKey}, "k1", mac, sampleSession(), 3); err != nil {
		t.Fatalf("the session as signed: %v", err)
	}
	later := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for name, change := range map[string]func(*domain.Session){
		"id":                    func(s *domain.Session) { s.ID = "session_2" },
		"status":                func(s *domain.Session) { s.Status = domain.StatusTerminated },
		"protocol":              func(s *domain.Session) { s.Protocol = "vnc" },
		"requester":             func(s *domain.Session) { s.RequestedBy = "mallory" },
		"account":               func(s *domain.Session) { s.PrivilegedAccountID = "acc_root" },
		"justification":         func(s *domain.Session) { s.Justification = "other" },
		"creation":              func(s *domain.Session) { s.CreatedAt = later },
		"end":                   func(s *domain.Session) { s.ExpiresAt = later },
		"termination":           func(s *domain.Session) { s.TerminatedAt = &later },
		"duration":              func(s *domain.Session) { s.DurationMinutes = 600 },
		"break-glass":           func(s *domain.Session) { s.BreakGlass = true },
		"approval required":     func(s *domain.Session) { s.ApprovalRequired = false },
		"ticket":                func(s *domain.Session) { s.Ticket = "CHG-2" },
		"decider":               func(s *domain.Session) { s.DecidedBy = "alice" },
		"decision time":         func(s *domain.Session) { s.DecidedAt = &later },
		"no decision time":      func(s *domain.Session) { s.DecidedAt = nil },
		"clipboard to target":   func(s *domain.Session) { s.ClipboardToTarget = false },
		"clipboard from target": func(s *domain.Session) { s.ClipboardFromTarget = true },
		"after-use debt":        func(s *domain.Session) { s.AfterUseOwed = true },
	} {
		s := sampleSession()
		change(s)
		if err := domain.VerifyMetadata([]domain.MetadataKey{testKey}, "k1", mac, s, 3); !errors.Is(err, domain.ErrMetadataIntegrity) {
			t.Errorf("%s changed: %v, want ErrMetadataIntegrity", name, err)
		}
	}
}

// A MAC does not move to another revision (rollback within the row), another key, or a mangled MAC.
func TestMetadata_TheMACIsBoundToItsRevisionAndKey(t *testing.T) {
	s := sampleSession()
	mac := domain.SignMetadata(testKey, s, 3)
	other := domain.MetadataKey{ID: "k2", Key: bytes.Repeat([]byte{8}, domain.MetadataKeyBytes)}
	sameBytesOtherID := domain.MetadataKey{ID: "k2", Key: testKey.Key}
	keys := []domain.MetadataKey{testKey, other, sameBytesOtherID}
	for name, c := range map[string]struct {
		keyID    string
		mac      []byte
		revision uint64
		keys     []domain.MetadataKey
	}{
		"another revision":        {"k1", mac, 2, keys},
		"revision zero":           {"k1", domain.SignMetadata(testKey, s, 0), 0, keys},
		"another key's ID":        {"k2", mac, 3, []domain.MetadataKey{sameBytesOtherID}},
		"an unknown key":          {"k9", mac, 3, keys},
		"no key held":             {"k1", mac, 3, nil},
		"a truncated MAC":         {"k1", mac[:31], 3, keys},
		"a flipped bit":           {"k1", append(append([]byte(nil), mac[:31]...), mac[31]^1), 3, keys},
		"a key of the wrong size": {"k1", mac, 3, []domain.MetadataKey{{ID: "k1", Key: testKey.Key[:16]}}},
	} {
		if err := domain.VerifyMetadata(c.keys, c.keyID, c.mac, s, c.revision); !errors.Is(err, domain.ErrMetadataIntegrity) {
			t.Errorf("%s: %v, want ErrMetadataIntegrity", name, err)
		}
	}
	if err := domain.VerifyMetadata(keys, "k2", domain.SignMetadata(other, s, 3), s, 3); err != nil {
		t.Fatalf("the previous key still verifies its rows (§7): %v", err)
	}
}

// Length prefixes: moving bytes from one field to the next is another encoding.
func TestMetadata_FieldBoundariesAreUnambiguous(t *testing.T) {
	a, b := sampleSession(), sampleSession()
	a.RequestedBy, a.PrivilegedAccountID = "alice", "acc_1"
	b.RequestedBy, b.PrivilegedAccountID = "aliceacc", "_1"
	if bytes.Equal(domain.CanonicalMetadata(a), domain.CanonicalMetadata(b)) {
		t.Fatal("two sessions encode alike")
	}
}

// A time read back from PostgreSQL (microseconds) encodes as the one that was signed.
func TestMetadata_TimesAreTheStoresMicroseconds(t *testing.T) {
	s := sampleSession()
	s.ExpiresAt = s.ExpiresAt.Add(789 * time.Nanosecond).In(time.FixedZone("CET", 3600))
	domain.TruncateMetadataTimes(s)
	mac := domain.SignMetadata(testKey, s, 1)
	back := *s
	back.ExpiresAt = s.ExpiresAt.UTC()
	if err := domain.VerifyMetadata([]domain.MetadataKey{testKey}, "k1", mac, &back, 1); err != nil {
		t.Fatalf("a stored time does not verify: %v", err)
	}
}

func TestMetadata_OnlyAnAttestedRowIsUsed(t *testing.T) {
	for integrity, want := range map[domain.MetadataIntegrity]error{
		domain.IntegrityAttested: nil, domain.IntegrityLegacyUnverified: domain.ErrMetadataUnverified, "": domain.ErrMetadataIntegrity,
	} {
		s := sampleSession()
		s.Integrity = integrity
		if err := s.RequireAttested(); !errors.Is(err, want) && !(err == nil && want == nil) {
			t.Errorf("%q: %v, want %v", integrity, err, want)
		}
	}
}
