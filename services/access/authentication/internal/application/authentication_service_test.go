package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

func newTestService(t *testing.T) *application.AuthenticationService {
	t.Helper()
	key, err := infrastructure.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	return application.NewAuthenticationService(store, infrastructure.Argon2Hasher{}, infrastructure.NewTokenIssuer(key), time.Hour)
}

func TestLogin_SucceedsWithCorrectPassword(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, "jdupont", "Jean Dupont", "s3cret-pw", []string{"dba"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, expiresIn, err := svc.Login(ctx, "jdupont", "s3cret-pw")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty token")
	}
	if expiresIn <= 0 {
		t.Fatal("expected a positive expiry duration")
	}
}

func TestLogin_FailsWithWrongPassword(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_, _ = svc.CreateUser(ctx, "jdupont", "Jean Dupont", "s3cret-pw", []string{"dba"})

	if _, _, err := svc.Login(ctx, "jdupont", "wrong-password"); err == nil {
		t.Fatal("expected Login to fail with the wrong password")
	}
}

func TestLogin_FailsForUnknownUser_SameErrorAsWrongPassword(t *testing.T) {
	// Guarding against username enumeration: both failure modes must
	// return the identical error.
	svc := newTestService(t)
	ctx := context.Background()
	_, _ = svc.CreateUser(ctx, "jdupont", "Jean Dupont", "s3cret-pw", []string{"dba"})

	_, _, errUnknown := svc.Login(ctx, "does-not-exist", "irrelevant")
	_, _, errWrongPw := svc.Login(ctx, "jdupont", "wrong-password")

	if errUnknown == nil || errWrongPw == nil {
		t.Fatal("expected both cases to fail")
	}
	if errUnknown.Error() != errWrongPw.Error() {
		t.Fatalf("expected identical error messages to avoid username enumeration, got %q vs %q", errUnknown, errWrongPw)
	}
}

func TestVerifyToken_ReturnsTheRolesAssignedAtLogin(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_, _ = svc.CreateUser(ctx, "jdupont", "Jean Dupont", "s3cret-pw", []string{"dba", "auditor"})

	token, _, err := svc.Login(ctx, "jdupont", "s3cret-pw")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	userID, username, roles, err := svc.VerifyToken(ctx, token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if username != "jdupont" || userID == "" {
		t.Fatalf("unexpected identity: userID=%q username=%q", userID, username)
	}
	if len(roles) != 2 || roles[0] != "dba" || roles[1] != "auditor" {
		t.Fatalf("unexpected roles: %v", roles)
	}
}

func TestVerifyToken_RejectsGarbageToken(t *testing.T) {
	svc := newTestService(t)
	if _, _, _, err := svc.VerifyToken(context.Background(), "garbage"); err == nil {
		t.Fatal("expected VerifyToken to reject a garbage token")
	}
}

func TestCreateUser_RejectsDuplicateUsername(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, "jdupont", "Jean Dupont", "pw1", nil); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if _, err := svc.CreateUser(ctx, "jdupont", "Someone Else", "pw2", nil); err == nil {
		t.Fatal("expected CreateUser to reject a duplicate username")
	}
}
