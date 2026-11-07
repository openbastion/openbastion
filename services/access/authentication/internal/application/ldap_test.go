package application_test

// Directory login (ADR-0061): the directory checks the password and says which groups; only the
// role map says what that is worth.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

// fakeDirectory vouches for one user and password, with the identity set in `id`.
type fakeDirectory struct {
	user, password string
	id             application.DirectoryIdentity
	down           bool
	asked          int
}

func (f *fakeDirectory) Authenticate(_ context.Context, username, password string) (application.DirectoryIdentity, error) {
	f.asked++
	if f.down {
		return application.DirectoryIdentity{}, errors.New("the directory at ldaps://dc.example:636 cannot be reached")
	}
	if username != f.user || password != f.password {
		return application.DirectoryIdentity{}, application.ErrDirectoryRejected
	}
	return f.id, nil
}

const (
	adminsDN = "cn=bastion-admins,ou=groups,dc=example,dc=test"
	dbasDN   = "cn=dbas,ou=groups,dc=example,dc=test"
)

func ldapService(t *testing.T) (*application.AuthenticationService, *fakeDirectory, *infrastructure.InMemoryStore, *infrastructure.TokenIssuer) {
	t.Helper()
	key, _ := infrastructure.GenerateSigningKey()
	tokens := infrastructure.NewTokenIssuer(key)
	store := infrastructure.NewInMemoryStore()
	d := &fakeDirectory{user: "alice", password: "s3cret pass", id: application.DirectoryIdentity{ID: "1d2c3b4a-0000-4000-8000-00000000abcd", Name: "Alice A.", Groups: []string{dbasDN, "cn=unmapped,dc=example,dc=test"}}}
	svc := application.NewAuthenticationService(store, infrastructure.Argon2Hasher{}, tokens, time.Hour).
		WithDirectory(d, application.RoleMap{adminsDN: {"platform-admin"}, dbasDN: {"dba"}})
	return svc, d, store, tokens
}

func TestLoginLDAP_TheRolesAreTheMapsOfTheGroups_AndTheAccountIsLDAPAndItsStableID(t *testing.T) {
	svc, d, store, tokens := ldapService(t)
	token, ttl, err := svc.LoginLDAP(context.Background(), "", "alice", "s3cret pass")
	if err != nil || ttl != time.Hour {
		t.Fatalf("LoginLDAP: %v", err)
	}
	userID, username, roles, _, err := tokens.Verify(token)
	if err != nil || username != "ldap:"+d.id.ID || fmt.Sprint(roles) != "[dba]" {
		t.Fatalf("token: %s %v %v — want ldap:<id> with [dba] only", username, roles, err)
	}
	u, _ := store.GetByID(context.Background(), userID)
	if u.IdentitySource != domain.SourceLDAP || u.ExternalSubject != d.id.ID || u.DisplayName != "Alice A." || u.PasswordHash != "" {
		t.Fatalf("account %+v", u)
	}
	// The login name is not an account: a local login as alice, or as the directory account, fails.
	for _, name := range []string{"alice", "ldap:" + d.id.ID} {
		if _, _, err := svc.Login(context.Background(), name, "s3cret pass"); err == nil {
			t.Fatalf("a local login as %q succeeded with the directory password", name)
		}
	}

	// The groups change in the directory: the next login has today's roles, on the same account.
	d.id.Groups = []string{adminsDN}
	token, _, err = svc.LoginLDAP(context.Background(), "", "alice", "s3cret pass")
	if err != nil {
		t.Fatal(err)
	}
	again, _, roles, _, _ := tokens.Verify(token)
	if again != userID || fmt.Sprint(roles) != "[platform-admin]" {
		t.Fatalf("second login: account %s (first %s), roles %v", again, userID, roles)
	}
}

func TestLoginLDAP_NoMappedGroupIsRefused_AndNoAccountIsMade(t *testing.T) {
	svc, d, store, _ := ldapService(t)
	d.id.Groups = []string{"cn=unmapped,dc=example,dc=test"}
	if _, _, err := svc.LoginLDAP(context.Background(), "", "alice", "s3cret pass"); !errors.Is(err, application.ErrNoRole) {
		t.Fatalf("no mapped group: %v, want ErrNoRole", err)
	}
	if _, err := store.GetByExternalSubject(context.Background(), domain.SourceLDAP, "", d.id.ID); err == nil {
		t.Fatal("an account was made for a user with no role")
	}
}

func TestLoginLDAP_WhatTheDirectoryRefusesIsRefused_AndAnEmptyPasswordNeverReachesIt(t *testing.T) {
	svc, d, _, _ := ldapService(t)
	if _, _, err := svc.LoginLDAP(context.Background(), "", "alice", "wrong"); !errors.Is(err, application.ErrDirectoryRejected) {
		t.Fatalf("a wrong password: %v", err)
	}
	if _, _, err := svc.LoginLDAP(context.Background(), "", "bob", "s3cret pass"); !errors.Is(err, application.ErrDirectoryRejected) {
		t.Fatalf("an unknown user: %v", err)
	}
	asked := d.asked
	// An empty password is an anonymous bind, which a directory accepts: never sent. Neither is a
	// name that is empty, too long, or holds a control character.
	for _, c := range [][2]string{{"alice", ""}, {"", "s3cret pass"}, {strings.Repeat("a", application.MaxDirectoryUsername+1), "s3cret pass"},
		{"alice\x00", "s3cret pass"}, {"ali\nce", "s3cret pass"}, {"alice\xff", "s3cret pass"}} {
		if _, _, err := svc.LoginLDAP(context.Background(), "", c[0], c[1]); !errors.Is(err, application.ErrDirectoryRejected) {
			t.Fatalf("%q/%q: %v, want a refusal", c[0], c[1], err)
		}
	}
	if d.asked != asked {
		t.Fatalf("the directory was asked %d time(s) for what is refused before it", d.asked-asked)
	}
}

func TestLoginLDAP_ADirectoryThatCannotAnswerIsNotARefusal_AndNoIdentifierIsAFailure(t *testing.T) {
	svc, d, _, _ := ldapService(t)
	d.down = true
	_, _, err := svc.LoginLDAP(context.Background(), "", "alice", "s3cret pass")
	if err == nil || errors.Is(err, application.ErrDirectoryRejected) || errors.Is(err, application.ErrNoRole) {
		t.Fatalf("a directory down: %v, want an error that is neither a refusal nor a missing role (503)", err)
	}
	d.down, d.id.ID = false, ""
	if _, _, err := svc.LoginLDAP(context.Background(), "", "alice", "s3cret pass"); err == nil || errors.Is(err, application.ErrDirectoryRejected) {
		t.Fatalf("no stable identifier: %v, want a failure", err)
	}
}

func TestLoginLDAP_OffUnlessConfigured(t *testing.T) {
	svc := newTestService(t)
	if svc.DirectoryEnabled() {
		t.Fatal("directory login is on without a directory")
	}
	if _, _, err := svc.LoginLDAP(context.Background(), "", "alice", "x"); !errors.Is(err, application.ErrDirectoryOff) {
		t.Fatalf("%v, want ErrDirectoryOff", err)
	}
}
