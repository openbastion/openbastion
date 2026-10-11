package infrastructure_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	// A JWT's exp claim (RFC 7519 §2's NumericDate) only ever carries
	// whole-second precision — see Issue's doc comment. Comparing
	// against expiresAt truncated the same way is the correct
	// expectation here, not a loosened assertion: a real caller only
	// ever gets second precision back out, by the wire format's own
	// design, the same way a value read back from a PostgreSQL
	// TIMESTAMPTZ column only ever has microsecond precision
	// (NOTES_SANDBOX.md).
	if !exp.Equal(expiresAt.Truncate(time.Second)) {
		t.Fatalf("expiresAt = %v, want %v", exp, expiresAt.Truncate(time.Second))
	}
}

// TestTokenIssuer_IssuedTokenIsAStandardThreePartJWT pins the actual
// point of this increment: that Issue now produces a real RFC 7519
// token (header.payload.signature, each base64url), not merely
// something shaped like one. A regression back to the old hand-rolled
// two-part format would pass every other test in this file (they only
// ever go through Issue/Verify as a pair) without this one.
func TestTokenIssuer_IssuedTokenIsAStandardThreePartJWT(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.Issue("user_1", "jdupont", []string{"dba"}, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a standard 3-part JWT (header.payload.signature), got %d part(s): %q", len(parts), token)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header segment: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "HS256" {
		t.Fatalf(`header["alg"] = %q, want "HS256"`, header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Fatalf(`header["typ"] = %q, want "JWT"`, header["typ"])
	}
}

// TestTokenIssuer_VerifyRejectsAlgNoneToken is the classic JWT "alg
// confusion" attack (RFC 8725 §3.1): a token that declares "alg":"none"
// and carries no signature at all, forging arbitrary claims — here,
// platform-admin — with nothing to verify. WithValidMethods in Verify
// must reject this before the forged claims are ever trusted.
func TestTokenIssuer_VerifyRejectsAlgNoneToken(t *testing.T) {
	issuer := newTestIssuer(t)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"sub":"user_1","username":"jdupont","roles":["platform-admin"],"exp":%d}`,
		time.Now().UTC().Add(time.Hour).Unix())
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	forged := header + "." + payload + "." // alg:none tokens carry an empty signature segment

	if _, _, roles, _, err := issuer.Verify(forged); err == nil {
		t.Fatalf("expected an alg:none token to be rejected, got roles=%v", roles)
	}
}

// TestTokenIssuer_VerifyRejectsTokenSignedWithDifferentAlgorithm covers
// the other half of alg confusion: a token signed with the *correct*
// key but a *different* HMAC variant than this issuer ever uses. Even
// though HS384 is just as legitimate a MAC as HS256, and even though
// the key is the one this issuer trusts, Verify must still reject it —
// this issuer only ever signs and accepts HS256 (TokenIssuer's doc
// comment).
func TestTokenIssuer_VerifyRejectsTokenSignedWithDifferentAlgorithm(t *testing.T) {
	key, err := infrastructure.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	issuer := infrastructure.NewTokenIssuer(key)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.MapClaims{
		"sub":      "user_1",
		"username": "jdupont",
		"roles":    []string{"dba"},
		"exp":      time.Now().UTC().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	if _, _, _, _, err := issuer.Verify(signed); err == nil {
		t.Fatal("expected a token signed with HS384 to be rejected, even with the correct key")
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
