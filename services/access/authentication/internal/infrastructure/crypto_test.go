package infrastructure_test

import (
	"testing"

	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

func TestArgon2Hasher_VerifyAcceptsCorrectPassword(t *testing.T) {
	h := infrastructure.Argon2Hasher{}
	encoded, err := h.Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := h.Verify(encoded, "correct-horse-battery-staple"); err != nil {
		t.Fatalf("Verify should accept the correct password: %v", err)
	}
}

func TestArgon2Hasher_VerifyRejectsWrongPassword(t *testing.T) {
	h := infrastructure.Argon2Hasher{}
	encoded, _ := h.Hash("correct-horse-battery-staple")
	if err := h.Verify(encoded, "wrong-password"); err == nil {
		t.Fatal("Verify should reject an incorrect password")
	}
}

func TestArgon2Hasher_TwoHashesOfSamePasswordDiffer(t *testing.T) {
	// Confirms the salt is actually random per call — a fixed salt would
	// make identical passwords produce identical hashes, leaking that two
	// accounts share a password.
	h := infrastructure.Argon2Hasher{}
	a, _ := h.Hash("same-password")
	b, _ := h.Hash("same-password")
	if a == b {
		t.Fatal("expected two hashes of the same password to differ (random salt)")
	}
	// Both must still verify correctly against their own encoding.
	if err := h.Verify(a, "same-password"); err != nil {
		t.Fatalf("Verify(a): %v", err)
	}
	if err := h.Verify(b, "same-password"); err != nil {
		t.Fatalf("Verify(b): %v", err)
	}
}

func TestArgon2Hasher_EncodedHashNeverContainsPlaintext(t *testing.T) {
	h := infrastructure.Argon2Hasher{}
	encoded, _ := h.Hash("a-very-identifiable-plaintext-marker")
	if contains(encoded, "a-very-identifiable-plaintext-marker") {
		t.Fatal("encoded hash must never contain the plaintext password")
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
