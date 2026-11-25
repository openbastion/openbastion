package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

type failingUserRepository struct {
	domain.UserRepository
	err error
}

func (r failingUserRepository) GetByID(context.Context, string) (*domain.User, error) {
	return nil, r.err
}

func TestGetAuthorizationContext_RepositoryFailureIsNotConvertedToInactive(t *testing.T) {
	want := errors.New("database unavailable")
	svc := application.NewAuthenticationService(failingUserRepository{err: want}, infrastructure.Argon2Hasher{}, infrastructure.NewTokenIssuer(make([]byte, 32)), time.Hour)
	if _, err := svc.GetAuthorizationContext(context.Background(), "user_1"); !errors.Is(err, want) {
		t.Fatalf("error = %v, want repository failure %v", err, want)
	}
}

func TestGetAuthorizationContext_UnknownIdentityIsInactive(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuthenticationService(store, infrastructure.Argon2Hasher{}, infrastructure.NewTokenIssuer(make([]byte, 32)), time.Hour)
	got, err := svc.GetAuthorizationContext(context.Background(), "user_missing")
	if err != nil {
		t.Fatal(err)
	}
	if got.Exists || got.Active || len(got.Roles) != 0 {
		t.Fatalf("unknown identity must be inactive without roles: %+v", got)
	}
}
