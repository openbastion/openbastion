package infrastructure

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type tokenPayload struct {
	UserID    string    `json:"sub"`
	Username  string    `json:"username"`
	Roles     []string  `json:"roles"`
	ExpiresAt time.Time `json:"exp"`
}

// TokenIssuer issues and verifies HMAC-SHA256 signed tokens.
//
// SANDBOX NOTE: this stands in for JWT/OIDC-issued tokens (ADR-0007:
// Keycloak as platform IdP) — it is deliberately NOT a JWT. No external
// JWT library was pulled in; this project has consistently favored the
// standard library for security-sensitive code when it suffices (AES-GCM
// in password-vault, SHA-256 hash chaining in audit-service). The encoded
// shape (base64 payload + "." + base64 HMAC signature) is close enough to
// a JWT's structure that swapping in a real one later — once
// google.golang.org's vanity domain is reachable, see /NOTES_SANDBOX.md —
// is a change contained entirely to this file; application.TokenIssuer's
// signature does not mention encoding at all.
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

func (t *TokenIssuer) Issue(userID, username string, roles []string, expiresAt time.Time) (string, error) {
	payload, err := json.Marshal(tokenPayload{UserID: userID, Username: username, Roles: roles, ExpiresAt: expiresAt})
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := t.sign(payloadB64)
	return payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

var (
	ErrMalformedToken   = errors.New("malformed token")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrTokenExpired     = errors.New("token expired")
)

func (t *TokenIssuer) Verify(token string) (userID, username string, roles []string, expiresAt time.Time, err error) {
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return "", "", nil, time.Time{}, ErrMalformedToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", "", nil, time.Time{}, ErrMalformedToken
	}
	want := t.sign(payloadB64)
	if subtle.ConstantTimeCompare(sig, want) != 1 {
		return "", "", nil, time.Time{}, ErrInvalidSignature
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", "", nil, time.Time{}, ErrMalformedToken
	}
	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", "", nil, time.Time{}, ErrMalformedToken
	}
	if time.Now().UTC().After(payload.ExpiresAt) {
		return "", "", nil, time.Time{}, ErrTokenExpired
	}
	return payload.UserID, payload.Username, payload.Roles, payload.ExpiresAt, nil
}

func (t *TokenIssuer) sign(payloadB64 string) []byte {
	mac := hmac.New(sha256.New, t.key)
	mac.Write([]byte(payloadB64))
	return mac.Sum(nil)
}
