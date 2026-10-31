// Package infrastructure implements the Authentication Service's password
// hashing (Argon2id, docs/security/authentication.md) and token issuance/verification.
package infrastructure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 16
)

// Argon2Hasher implements application.PasswordHasher using the real
// golang.org/x/crypto/argon2 (see go.mod and /NOTES_SANDBOX.md for how
// it's fetched in this build sandbox).
type Argon2Hasher struct{}

var ErrInvalidPassword = errors.New("invalid password")

// Hash returns a self-contained PHC-style encoded string ($argon2id$v=..
// $m=..,t=..,p=..$salt$hash) — the same convention most Argon2 tooling
// uses, so no separate salt column is needed alongside password_hash
// (docs/architecture/data-architecture.md §3).
func (Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// Verify re-derives the hash using the parameters and salt embedded in
// encoded, and compares in constant time.
func (Argon2Hasher) Verify(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("unrecognized hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return err
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrInvalidPassword
	}
	return nil
}
