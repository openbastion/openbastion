package infrastructure_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

func newTestIssuer(t *testing.T) *infrastructure.TokenIssuer {
	t.Helper()
	key, err := infrastructure.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	return infrastructure.NewTokenIssuer(key)
}

func TestTokenIssuer_IssueThenVerifyRoundTrips(t *testing.T) {
	issuer := newTestIssuer(t)
	expiresAt := time.Now().UTC().Add(time.Hour)

	token, err := issuer.Issue("user_1", "jdupont", []string{"dba"}, expiresAt)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	userID, username, roles, exp, err := issuer.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if userID != "user_1" || username != "jdupont" || len(roles) != 1 || roles[0] != "dba" {
		t.Fatalf("unexpected claims: userID=%q username=%q roles=%v", userID, username, roles)
	}
	if !exp.Equal(expiresAt) {
		t.Fatalf("expiresAt = %v, want %v", exp, expiresAt)
	}
}

func TestTokenIssuer_VerifyRejectsTamperedPayload(t *testing.T) {
	issuer := newTestIssuer(t)
	token, _ := issuer.Issue("user_1", "jdupont", []string{"dba"}, time.Now().UTC().Add(time.Hour))

	tampered := token[:len(token)-4] + "AAAA" // corrupt the signature portion
	if _, _, _, _, err := issuer.Verify(tampered); err == nil {
		t.Fatal("expected a tampered token to be rejected")
	}
}

func TestTokenIssuer_VerifyRejectsTokenSignedWithDifferentKey(t *testing.T) {
	issuerA := newTestIssuer(t)
	issuerB := newTestIssuer(t)

	token, _ := issuerA.Issue("user_1", "jdupont", []string{"dba"}, time.Now().UTC().Add(time.Hour))
	if _, _, _, _, err := issuerB.Verify(token); err == nil {
		t.Fatal("expected a token signed by a different key to be rejected")
	}
}

func TestTokenIssuer_VerifyRejectsExpiredToken(t *testing.T) {
	issuer := newTestIssuer(t)
	token, _ := issuer.Issue("user_1", "jdupont", []string{"dba"}, time.Now().UTC().Add(-time.Second))

	if _, _, _, _, err := issuer.Verify(token); err == nil {
		t.Fatal("expected an expired token to be rejected")
	}
}

func TestTokenIssuer_VerifyRejectsMalformedToken(t *testing.T) {
	issuer := newTestIssuer(t)
	if _, _, _, _, err := issuer.Verify("not-a-valid-token-at-all"); err == nil {
		t.Fatal("expected a malformed token to be rejected")
	}
}

func TestTokenIssuer_CannotEscalateRolesByEditingPayloadWithoutValidSignature(t *testing.T) {
	// A determined attacker could try swapping in a payload claiming
	// admin roles. Without the signing key, they cannot produce a
	// signature that verifies against it.
	issuer := newTestIssuer(t)
	token, _ := issuer.Issue("user_1", "jdupont", []string{"dba"}, time.Now().UTC().Add(time.Hour))

	forgedPayload, _, found := cut(token, ".")
	if !found {
		t.Fatal("test setup: could not split token")
	}
	forged := forgedPayload + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	if _, _, roles, _, err := issuer.Verify(forged); err == nil {
		t.Fatalf("expected forged token to be rejected, got roles=%v", roles)
	}
}

func TestSigningKeyFromHex_SameKeyAcrossInstancesVerifiesEachOthersTokens(t *testing.T) {
	// The fix for the same class of bug documented in NOTES_SANDBOX.md
	// for LocalKMS: two TokenIssuer instances built from the SAME hex
	// key — exactly what two authentication processes do when both are
	// given the same TOKEN_SIGNING_KEY_HEX — can verify each other's
	// tokens. This is the property a restarted process actually depends
	// on to keep honoring tokens issued by the process before it.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	hexKey := hex.EncodeToString(raw[:])

	key1, err := infrastructure.SigningKeyFromHex(hexKey)
	if err != nil {
		t.Fatalf("SigningKeyFromHex (1): %v", err)
	}
	key2, err := infrastructure.SigningKeyFromHex(hexKey)
	if err != nil {
		t.Fatalf("SigningKeyFromHex (2): %v", err)
	}

	issuer1 := infrastructure.NewTokenIssuer(key1)
	issuer2 := infrastructure.NewTokenIssuer(key2)

	token, err := issuer1.Issue("user_1", "jdupont", []string{"dba"}, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, _, _, err := issuer2.Verify(token); err != nil {
		t.Fatalf("expected a token issued by the first instance to verify against the second, built from the same hex key: %v", err)
	}
}

func TestSigningKeyFromHex_EmptyKeyFallsBackToRandomPerInstance(t *testing.T) {
	key1, err := infrastructure.SigningKeyFromHex("")
	if err != nil {
		t.Fatalf("SigningKeyFromHex(\"\") (1): %v", err)
	}
	key2, err := infrastructure.SigningKeyFromHex("")
	if err != nil {
		t.Fatalf("SigningKeyFromHex(\"\") (2): %v", err)
	}

	issuer1 := infrastructure.NewTokenIssuer(key1)
	issuer2 := infrastructure.NewTokenIssuer(key2)
	token, _ := issuer1.Issue("user_1", "jdupont", []string{"dba"}, time.Now().UTC().Add(time.Hour))
	if _, _, _, _, err := issuer2.Verify(token); err == nil {
		t.Fatal("expected two empty-key instances to each get their own random key, unable to verify one another's tokens")
	}
}

func TestSigningKeyFromHex_RejectsInvalidHex(t *testing.T) {
	if _, err := infrastructure.SigningKeyFromHex("not-hex-at-all-zz"); err == nil {
		t.Fatal("expected an error for a non-hex TOKEN_SIGNING_KEY_HEX value")
	}
}

func TestSigningKeyFromHex_RejectsWrongLength(t *testing.T) {
	// 16 bytes is valid hex but the wrong size for this HMAC-SHA256
	// implementation — must be rejected explicitly, not silently
	// accepted at a weaker length.
	shortKey := hex.EncodeToString(make([]byte, 16))
	if _, err := infrastructure.SigningKeyFromHex(shortKey); err == nil {
		t.Fatal("expected an error for a key that isn't exactly 32 bytes")
	}
}

func cut(s, sep string) (before, after string, found bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
