package application_test

// ADR-0076, point 10: every login written to the audit says who vouches for its account — its
// source and, for a provider or a directory, which one; the accounts of the variables, or of the
// entry that adopts them, included. A refusal says where the login was tried.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

func (a *detailedAudit) last(t *testing.T, action string) map[string]string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.detailed) - 1; i >= 0; i-- {
		if a.detailed[i].action == action {
			return a.detailed[i].details
		}
	}
	t.Fatalf("no %s with details written; written: %+v", action, a.detailed)
	return nil
}

func wantDetails(t *testing.T, got map[string]string, source, provider string) {
	t.Helper()
	want := map[string]string{"identity_source": source}
	if provider != "" {
		want["identity_provider"] = provider
	}
	if len(got) != len(want) {
		t.Fatalf("details %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("details %v, want %v", got, want)
		}
	}
}

func TestAuditDetails_AFederatedLoginNamesItsProvider_AndALocalOneItsSource(t *testing.T) {
	w := newProvidersWorld(t, "")
	audit := &detailedAudit{}
	w.svc.WithAudit(audit, nil)
	ctx := context.Background()

	w.b.next = application.OIDCIdentity{Subject: "42", Groups: []string{"contractors"}}
	if _, _, err := w.svc.FinishOIDC(ctx, "code", w.startAt(t, "partner")); err != nil {
		t.Fatal(err)
	}
	wantDetails(t, audit.last(t, application.ActionLogin), "oidc", "partner")

	if _, _, err := w.svc.LoginLDAP(ctx, "ldap", "alice", "pass-b"); err != nil {
		t.Fatal(err)
	}
	wantDetails(t, audit.last(t, application.ActionLogin), "ldap", "ldap")

	hash, _ := infrastructure.Argon2Hasher{}.Hash("pw-local")
	_ = w.store.Create(ctx, &domain.User{ID: "u-local", Username: "bob", DisplayName: "Bob", PasswordHash: hash, Roles: []string{"dba"}, IdentitySource: domain.SourceLocal})
	if _, _, err := w.svc.Login(ctx, "bob", "pw-local"); err != nil {
		t.Fatal(err)
	}
	wantDetails(t, audit.last(t, application.ActionLogin), "local", "")
}

// The accounts kept under "" are named after the entry that adopts them: without it, the audit of
// a login of one of them would say nothing of where it came from.
func TestAuditDetails_AnAdoptedAccountIsNamedAfterTheEntryThatAdoptsIt(t *testing.T) {
	w := newProvidersWorld(t, "corp")
	audit := &detailedAudit{}
	w.svc.WithAudit(audit, nil)
	ctx := context.Background()
	_ = w.store.Create(ctx, &domain.User{ID: "u-legacy", Username: "oidc:9", DisplayName: "Legacy", Roles: []string{"platform-admin"},
		IdentitySource: domain.SourceOIDC, IdentityProvider: "", ExternalSubject: "9"})
	w.a.next = application.OIDCIdentity{Subject: "9", Groups: []string{"admins"}}
	tok, _, err := w.svc.FinishOIDC(ctx, "code", w.startAt(t, "corp"))
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := w.who(t, tok); name != "oidc:9" {
		t.Fatalf("logged into %q, want the adopted oidc:9", name)
	}
	wantDetails(t, audit.last(t, application.ActionLogin), "oidc", "corp")
}

func TestAuditDetails_TheProviderOfTheVariablesIsNamedAsSuch(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	key, _ := infrastructure.GenerateSigningKey()
	p := &fakeProvider{attempts: map[string][2]string{}}
	audit := &detailedAudit{}
	svc := application.NewAuthenticationService(store, infrastructure.Argon2Hasher{}, infrastructure.NewTokenIssuer(key), time.Hour).
		WithOIDC(p, application.RoleMap{"admins": {"dba"}}, store).WithAudit(audit, nil)
	ctx := context.Background()
	start, err := svc.StartOIDC(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	state := start[strings.Index(start, "state=")+len("state="):]
	if i := strings.IndexByte(state, '&'); i >= 0 {
		state = state[:i]
	}
	p.next = application.OIDCIdentity{Subject: "5", Groups: []string{"admins"}}
	if _, _, err := svc.FinishOIDC(ctx, "code", state); err != nil {
		t.Fatal(err)
	}
	wantDetails(t, audit.last(t, application.ActionLogin), "oidc", application.VariablesProvider)
}

func TestAuditDetails_ARefusedDirectoryLoginNamesTheDirectory_ALocalOneItsSource(t *testing.T) {
	w := newProvidersWorld(t, "")
	audit := &detailedAudit{}
	w.svc.WithAudit(audit, nil)
	ctx := context.Background()
	if _, _, err := w.svc.LoginLDAP(ctx, "ad", "alice", "wrong"); !errors.Is(err, application.ErrDirectoryRejected) {
		t.Fatalf("%v, want ErrDirectoryRejected", err)
	}
	wantDetails(t, audit.last(t, application.ActionLoginRefused), "ldap", "ad")
	// Refused before the directory is asked (an empty password): the directory is named all the same.
	if _, _, err := w.svc.LoginLDAP(ctx, "ldap", "alice", ""); !errors.Is(err, application.ErrDirectoryRejected) {
		t.Fatalf("%v, want ErrDirectoryRejected", err)
	}
	wantDetails(t, audit.last(t, application.ActionLoginRefused), "ldap", "ldap")
	if _, _, err := w.svc.Login(ctx, "nobody", "x"); !errors.Is(err, application.ErrInvalidCredentials) {
		t.Fatal(err)
	}
	wantDetails(t, audit.last(t, application.ActionLoginRefused), "local", "")
}

func TestAuditDetails_ARefusedSecondFactorNamesTheDirectoryOfItsLogin(t *testing.T) {
	w := newProvidersWorld(t, "")
	audit := &detailedAudit{}
	sealer, err := infrastructure.NewMFASealer(mfaKey)
	if err != nil {
		t.Fatal(err)
	}
	w.svc.WithAudit(audit, nil).WithMFA([]string{"platform-admin"}, w.store, sealer)
	ctx := context.Background()
	_, _, err = w.svc.LoginLDAP(ctx, "ad", "alice", "pass-a")
	var challenge *application.MFAChallengeRequired
	if !errors.As(err, &challenge) {
		t.Fatalf("%v, want a second-factor challenge", err)
	}
	// No factor yet: an enrollment, and a wrong enrollment code is a refusal of this login.
	if _, err := w.svc.StartEnrollment(ctx, challenge.Challenge, "not-the-code", application.FactorTOTP); err == nil {
		t.Fatal("a wrong enrollment code was taken")
	}
	wantDetails(t, audit.last(t, application.ActionLoginRefused), "ldap", "ad")
}
