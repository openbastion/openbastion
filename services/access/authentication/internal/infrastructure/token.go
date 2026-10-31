package infrastructure

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// claims is the JWT payload OpenBastion issues for an authenticated
// session: the sub/exp/iat registered claims (RFC 7519 §4.1) plus two
// OpenBastion-specific ones, username and roles. The API Gateway trusts
// only these two — resolved exclusively via VerifyToken, never anything
// a client claims about itself in a request body (docs/api/grpc/README.md §2's
// RequestContext.actor_user_id/actor_roles; see
// application.AuthenticationService.VerifyToken's doc comment).
type claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// TokenIssuer issues and verifies HS256-signed JSON Web Tokens (RFC 7519).
//
// This replaces an earlier hand-rolled HMAC token format (base64 payload
// + "." + base64 HMAC signature) that predated
// github.com/golang-jwt/jwt — hosted directly on GitHub, so reachable
// under this sandbox's GOPROXY=direct — being pulled in; see
// NOTES_SANDBOX.md. The swap changed only this file:
// application.TokenIssuer's port never mentions encoding, by design,
// precisely so this would be possible. ADR-0007 anticipates
// Keycloak/OIDC-issued tokens for a full deployment; this is the
// local-auth half of that same token shape — a real JWT, not a
// permanent substitute for ADR-0007.
//
// The signing method is pinned to HS256 in two independent places —
// WithValidMethods below, and a check inside the keyfunc itself —
// against the well-known "alg confusion" family of attacks, where a
// token presents "alg": "none" or an asymmetric algorithm the attacker
// can forge a signature for using a key this service only ever intended
// as an HMAC secret (RFC 8725 §3.1, §3.2). Defense in depth: either
// check alone would already reject such a token.
type TokenIssuer struct {
	key []byte
}

func NewTokenIssuer(key []byte) *TokenIssuer {
	return &TokenIssuer{key: key}
}

func GenerateSigningKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// SigningKeyFromHex decodes a hex-encoded 32-byte HMAC signing key,
// typically TOKEN_SIGNING_KEY_HEX (cmd/authentication/main.go) — same
// pattern as password-vault's NewLocalKMSFromHexKey, and for the same
// reason: GenerateSigningKey's random, in-process-only key makes every
// token issued by a process unverifiable the moment that process
// restarts with a fresh random key, silently invalidating every active
// session on every single deploy once users persist across restarts
// (DATABASE_URL set). An empty hexKey falls back to GenerateSigningKey,
// fine for a single process's lifetime (the in-memory store, tests) but
// never for a deployment where DATABASE_URL is set — main.go enforces
// that distinction by refusing to start rather than silently defaulting
// to a key that cannot survive a restart.
func SigningKeyFromHex(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return GenerateSigningKey()
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("TOKEN_SIGNING_KEY_HEX: invalid hex encoding: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("TOKEN_SIGNING_KEY_HEX: expected 32 bytes (64 hex characters) for HMAC-SHA256, got %d bytes", len(raw))
	}
	return raw, nil
}

// Issue mints a JWT whose exp claim carries only whole-second precision
// (RFC 7519 §2's NumericDate, and essentially the only precision every
// other JWT implementation in the ecosystem assumes — which will matter
// the moment OpenBastion needs to interoperate with Keycloak/OIDC per
// ADR-0007). expiresAt is truncated to the second here, by
// jwt.NewNumericDate, before signing — the caller's value is never
// silently truncated somewhere downstream and quietly stops matching
// what was asked for. Same discipline as the audit hash-chain's
// microsecond-precision fix (NOTES_SANDBOX.md): truncate once, at the
// point the lossy wire format is chosen, not after. Here that boundary
// is the JWT encoding itself rather than a datastore underneath it, so
// it has to be handled one step earlier, in this function rather than
// in the caller.
func (t *TokenIssuer) Issue(userID, username string, roles []string, expiresAt time.Time) (string, error) {
	now := time.Now().UTC()
	c := claims{
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return token.SignedString(t.key)
}

var (
	ErrMalformedToken   = errors.New("malformed token")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrTokenExpired     = errors.New("token expired")
)

// Verify parses and validates token, translating the jwt library's error
// taxonomy — which distinguishes several failure modes RFC 7519/8725
// name separately — down to the three outcomes callers have always had
// to handle. AuthenticationService.VerifyToken, and everything built on
// it (the API Gateway's bearer-token middleware, ultimately), needed no
// change for this swap: the mapping happens entirely here.
//
// WithExpirationRequired rejects a token that omits exp outright, rather
// than treating a missing expiry as "never expires" — this service
// never issues such a token, so one arriving here can only be forged or
// mis-issued, and either way must not be trusted indefinitely.
func (t *TokenIssuer) Verify(tokenString string) (userID, username string, roles []string, expiresAt time.Time, err error) {
	var c claims
	_, parseErr := jwt.ParseWithClaims(tokenString, &c, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %q, want HS256", tok.Header["alg"])
		}
		return t.key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}), jwt.WithExpirationRequired())

	switch {
	case parseErr == nil:
		return c.Subject, c.Username, c.Roles, c.ExpiresAt.Time, nil
	case errors.Is(parseErr, jwt.ErrTokenExpired):
		return "", "", nil, time.Time{}, ErrTokenExpired
	case errors.Is(parseErr, jwt.ErrTokenSignatureInvalid), errors.Is(parseErr, jwt.ErrTokenUnverifiable):
		return "", "", nil, time.Time{}, ErrInvalidSignature
	default:
		return "", "", nil, time.Time{}, ErrMalformedToken
	}
}
