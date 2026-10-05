package infrastructure_test

import (
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

func cut(s, sep string) (before, after string, found bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
