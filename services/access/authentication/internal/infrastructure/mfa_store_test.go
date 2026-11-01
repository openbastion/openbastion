package infrastructure_test

// domain.MFARepository (ADR-0062) on both stores: what makes a code used once and a challenge
// end after its failures holds in memory and in PostgreSQL alike.

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

type mfaStore interface {
	domain.UserRepository
	domain.MFARepository
}

func mfaStores(t *testing.T) map[string]func(*testing.T) mfaStore {
	return map[string]func(*testing.T) mfaStore{
		"memory":   func(*testing.T) mfaStore { return infrastructure.NewInMemoryStore() },
		"postgres": func(t *testing.T) mfaStore { return infrastructure.NewPostgresStore(testDB(t)) },
	}
}

func TestPostgresMFA_AStepIsTakenOnce_AChallengeEndsAtItsLimit_ACodeIsTakenOnce(t *testing.T) {
	for name, open := range mfaStores(t) {
		t.Run(name, func(t *testing.T) {
			s, ctx := open(t), context.Background()
			id := fmt.Sprintf("user_mfa_%d", time.Now().UnixNano())
			if err := s.Create(ctx, &domain.User{ID: id, Username: id, DisplayName: id, PasswordHash: "x", Roles: []string{"platform-admin"}, IdentitySource: domain.SourceLocal}); err != nil {
				t.Fatal(err)
			}
			if sealed, last, err := s.TOTP(ctx, id); err != nil || sealed != nil || last != 0 {
				t.Fatalf("a new account: %x %d %v", sealed, last, err)
			}
			if took, _ := s.AdvanceTOTPStep(ctx, id, 10); took {
				t.Fatal("a step taken by an account with no secret")
			}
			if err := s.SetTOTP(ctx, id, []byte("sealed-secret"), 100); err != nil {
				t.Fatal(err)
			}
			for step, want := range map[int64]bool{100: false, 99: false} {
				if took, _ := s.AdvanceTOTPStep(ctx, id, step); took != want {
					t.Fatalf("step %d after 100: %v", step, took)
				}
			}
			if took, _ := s.AdvanceTOTPStep(ctx, id, 101); !took {
				t.Fatal("step 101 after 100 not taken")
			}
			if took, _ := s.AdvanceTOTPStep(ctx, id, 101); took {
				t.Fatal("step 101 taken twice")
			}
			if sealed, last, _ := s.TOTP(ctx, id); !bytes.Equal(sealed, []byte("sealed-secret")) || last != 101 {
				t.Fatalf("%q %d", sealed, last)
			}

			hash := []byte(fmt.Sprintf("challenge-%d-0123456789abcdef", time.Now().UnixNano()))
			if err := s.SaveChallenge(ctx, domain.MFAChallenge{Hash: hash, UserID: id, Roles: []string{"platform-admin"}, Kind: domain.MFAEnroll,
				LoginSource: domain.SourceLocal, LoginName: id, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if set, _ := s.SetPendingSecret(ctx, hash, []byte("pending"), []byte("code-hash")); !set {
				t.Fatal("first pending secret not set")
			}
			if set, _ := s.SetPendingSecret(ctx, hash, []byte("other"), []byte("other")); set {
				t.Fatal("a second pending secret replaced the first")
			}
			c, err := s.GetChallenge(ctx, hash)
			if err != nil || c.UserID != id || fmt.Sprint(c.Roles) != "[platform-admin]" || c.Kind != domain.MFAEnroll || string(c.PendingSecret) != "pending" || string(c.EnrollmentCodeHash) != "code-hash" {
				t.Fatalf("challenge %+v %v", c, err)
			}
			for i := 1; i <= 3; i++ {
				gone, err := s.FailChallenge(ctx, hash, 3)
				if err != nil || gone != (i == 3) {
					t.Fatalf("failure %d of 3: gone %v %v", i, gone, err)
				}
			}
			if _, err := s.GetChallenge(ctx, hash); err != domain.ErrChallengeNotFound {
				t.Fatalf("after its limit: %v", err)
			}

			now := time.Now()
			_ = s.PutEnrollmentCode(ctx, domain.SourceLDAP, id, []byte("old"), now.Add(time.Hour))
			_ = s.PutEnrollmentCode(ctx, domain.SourceLDAP, id, []byte("new"), now.Add(time.Hour))
			for code, want := range map[string]bool{"old": false, "new": true} {
				if ok, _ := s.EnrollmentCodeMatches(ctx, domain.SourceLDAP, id, []byte(code), now); ok != want {
					t.Fatalf("code %s: %v", code, ok)
				}
			}
			if ok, _ := s.EnrollmentCodeMatches(ctx, domain.SourceLocal, id, []byte("new"), now); ok {
				t.Fatal("a directory code matches the local account of the same name")
			}
			if ok, _ := s.TakeEnrollmentCode(ctx, domain.SourceLDAP, id, []byte("new"), now.Add(2*time.Hour)); ok {
				t.Fatal("an expired code taken")
			}
			if ok, _ := s.TakeEnrollmentCode(ctx, domain.SourceLDAP, id, []byte("new"), now); !ok {
				t.Fatal("the code not taken")
			}
			if ok, _ := s.TakeEnrollmentCode(ctx, domain.SourceLDAP, id, []byte("new"), now); ok {
				t.Fatal("the code taken twice")
			}
			if err := s.ResetTOTP(ctx, id); err != nil {
				t.Fatal(err)
			}
			if sealed, last, _ := s.TOTP(ctx, id); sealed != nil || last != 0 {
				t.Fatalf("after a reset: %q %d", sealed, last)
			}
		})
	}
}
