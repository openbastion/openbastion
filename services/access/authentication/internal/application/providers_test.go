package application_test

// Several identity providers at once (ADR-0076): each account is bound to its provider, a group is
// worth something at its own provider only, an OIDC callback is exchanged where it was started,
// and a directory is never chosen for the user.

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

type providersWorld struct {
	svc    *application.AuthenticationService
	store  *infrastructure.InMemoryStore
	tokens *infrastructure.TokenIssuer
	a, b   *fakeProvider
	da, db *fakeDirectory
}

// providersWorld: two OIDC providers (a: groups "admins"; b: groups "admins" too, mapped to
// nothing but "dba") and two directories, each with its own user alice.
func newProvidersWorld(t *testing.T, adopt string) *providersWorld {
	t.Helper()
	key, _ := infrastructure.GenerateSigningKey()
	w := &providersWorld{store: infrastructure.NewInMemoryStore(), tokens: infrastructure.NewTokenIssuer(key),
		a: &fakeProvider{attempts: map[string][2]string{}}, b: &fakeProvider{attempts: map[string][2]string{}},
		da: &fakeDirectory{user: "alice", password: "pass-a", id: application.DirectoryIdentity{ID: "guid-1", Name: "Alice A", Groups: []string{adminsDN}}},
		db: &fakeDirectory{user: "alice", password: "pass-b", id: application.DirectoryIdentity{ID: "guid-1", Name: "Alice B", Groups: []string{adminsDN}}}}
	w.svc = application.NewAuthenticationService(w.store, infrastructure.Argon2Hasher{}, w.tokens, time.Hour).
		WithOIDCProviders([]application.OIDCEntry{
			{ID: "corp", Label: "Corp", Provider: w.a, Roles: application.RoleMap{"admins": {"platform-admin"}}, AdoptLegacyAccounts: adopt == "corp"},
			{ID: "partner", Label: "Partner", Provider: w.b, Roles: application.RoleMap{"contractors": {"dba"}}},
		}, w.store).
		WithDirectories([]application.DirectoryEntry{
			{ID: "ad", Label: "AD", Directory: w.da, Roles: application.RoleMap{adminsDN: {"platform-admin"}}, AdoptLegacyAccounts: adopt == "ad"},
			{ID: "ldap", Label: "LDAP", Directory: w.db, Roles: application.RoleMap{adminsDN: {"dba"}}},
		})
	return w
}

func (w *providersWorld) startAt(t *testing.T, provider string) string {
	t.Helper()
	u, err := w.svc.StartOIDC(context.Background(), provider)
	if err != nil {
		t.Fatalf("start at %q: %v", provider, err)
	}
	parsed, _ := url.Parse(u)
	return parsed.Query().Get("state")
}

func (w *providersWorld) who(t *testing.T, token string) (string, []string) {
	t.Helper()
	_, name, roles, _, err := w.tokens.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	return name, roles
}

func TestProviders_TheSameSubAtTwoIssuersIsTwoAccounts_EachWithTheRolesOfItsOwnMap(t *testing.T) {
	w := newProvidersWorld(t, "")
	w.a.next = application.OIDCIdentity{Subject: "42", Groups: []string{"admins"}}
	w.b.next = application.OIDCIdentity{Subject: "42", Groups: []string{"admins", "contractors"}}
	tokA, _, err := w.svc.FinishOIDC(context.Background(), "code", w.startAt(t, "corp"))
	if err != nil {
		t.Fatal(err)
	}
	tokB, _, err := w.svc.FinishOIDC(context.Background(), "code", w.startAt(t, "partner"))
	if err != nil {
		t.Fatal(err)
	}
	nameA, rolesA := w.who(t, tokA)
	nameB, rolesB := w.who(t, tokB)
	if nameA != "oidc:corp:42" || nameB != "oidc:partner:42" {
		t.Fatalf("accounts %q and %q, want oidc:corp:42 and oidc:partner:42", nameA, nameB)
	}
	// partner's "admins" is not corp's: it gives nothing there.
	if len(rolesA) != 1 || rolesA[0] != "platform-admin" || len(rolesB) != 1 || rolesB[0] != "dba" {
		t.Fatalf("roles %v and %v, want [platform-admin] and [dba]", rolesA, rolesB)
	}
	ua, _ := w.store.GetByExternalSubject(context.Background(), domain.SourceOIDC, "corp", "42")
	ub, _ := w.store.GetByExternalSubject(context.Background(), domain.SourceOIDC, "partner", "42")
	if ua == nil || ub == nil || ua.ID == ub.ID {
		t.Fatalf("one account for two issuers: %+v %+v", ua, ub)
	}
}

func TestProviders_AGroupOfAnotherProviderGivesNothing_AndNoAccountIsMade(t *testing.T) {
	w := newProvidersWorld(t, "")
	w.b.next = application.OIDCIdentity{Subject: "7", Groups: []string{"admins"}} // corp's group, at partner
	if _, _, err := w.svc.FinishOIDC(context.Background(), "code", w.startAt(t, "partner")); !errors.Is(err, application.ErrNoRole) {
		t.Fatalf("a group mapped at corp only, at partner: %v, want ErrNoRole", err)
	}
	if _, err := w.store.GetByExternalSubject(context.Background(), domain.SourceOIDC, "partner", "7"); err == nil {
		t.Fatal("an account was made for an identity with no role")
	}
}

// The mix-up attack (RFC 9207): the callback is exchanged at the provider of its attempt, never at
// another — whatever the code is, the other provider is not asked.
func TestProviders_ACallbackIsExchangedAtTheProviderItWasStartedAt_Only(t *testing.T) {
	w := newProvidersWorld(t, "")
	w.a.next = application.OIDCIdentity{Subject: "1", Groups: []string{"admins"}}
	w.b.next = application.OIDCIdentity{Subject: "1", Groups: []string{"contractors"}}
	state := w.startAt(t, "partner")
	tok, _, err := w.svc.FinishOIDC(context.Background(), "a-code-corp-issued", state)
	if err != nil {
		t.Fatal(err)
	}
	if w.a.exchanged != 0 || w.b.exchanged != 1 {
		t.Fatalf("exchanged at corp %d, at partner %d: want 0 and 1", w.a.exchanged, w.b.exchanged)
	}
	if name, _ := w.who(t, tok); name != "oidc:partner:1" {
		t.Fatalf("account %q, want the partner's", name)
	}
	// A token of corp verified at partner: refused (partner does not know corp's attempt).
	stateA := w.startAt(t, "corp")
	if _, _, err := w.svc.FinishOIDC(context.Background(), "code", stateA); err != nil {
		t.Fatal(err)
	}
	if w.b.exchanged != 1 {
		t.Fatal("corp's callback reached partner")
	}
}

func TestProviders_SeveralAndNoneNamed_OrAnUnknownOne_IsRefusedBeforeAnyProviderOrDirectory(t *testing.T) {
	w := newProvidersWorld(t, "")
	for _, c := range []struct {
		id   string
		want error
	}{{"", application.ErrProviderRequired}, {"nope", application.ErrUnknownProvider}, {"CORP", application.ErrUnknownProvider}} {
		if _, err := w.svc.StartOIDC(context.Background(), c.id); !errors.Is(err, c.want) {
			t.Fatalf("StartOIDC(%q): %v, want %v", c.id, err, c.want)
		}
		if _, _, err := w.svc.LoginLDAP(context.Background(), c.id, "alice", "pass-a"); !errors.Is(err, c.want) {
			t.Fatalf("LoginLDAP(%q): %v, want %v", c.id, err, c.want)
		}
	}
	// Never one directory after the other: alice's password reached none.
	if w.da.asked != 0 || w.db.asked != 0 {
		t.Fatalf("a directory was asked: ad %d, ldap %d", w.da.asked, w.db.asked)
	}
	if got := w.svc.Directories(); len(got) != 2 || got[0] != (application.ProviderInfo{ID: "ad", Label: "AD"}) {
		t.Fatalf("directories %v", got)
	}
	if got := w.svc.OIDCProviders(); len(got) != 2 || got[1] != (application.ProviderInfo{ID: "partner", Label: "Partner"}) {
		t.Fatalf("providers %v", got)
	}
}

func TestProviders_ADirectoryLoginGoesToTheNamedDirectoryOnly_TheSameGUIDElsewhereIsAnotherAccount(t *testing.T) {
	w := newProvidersWorld(t, "")
	tokAD, _, err := w.svc.LoginLDAP(context.Background(), "ad", "alice", "pass-a")
	if err != nil {
		t.Fatal(err)
	}
	if w.da.asked != 1 || w.db.asked != 0 {
		t.Fatalf("asked ad %d, ldap %d", w.da.asked, w.db.asked)
	}
	// ad's password at ldap: refused there, and ad is not asked.
	if _, _, err := w.svc.LoginLDAP(context.Background(), "ldap", "alice", "pass-a"); !errors.Is(err, application.ErrDirectoryRejected) {
		t.Fatalf("ad's password at ldap: %v", err)
	}
	tokLDAP, _, err := w.svc.LoginLDAP(context.Background(), "ldap", "alice", "pass-b")
	if err != nil {
		t.Fatal(err)
	}
	if w.da.asked != 1 {
		t.Fatal("a login at ldap asked ad")
	}
	nameAD, rolesAD := w.who(t, tokAD)
	nameLDAP, rolesLDAP := w.who(t, tokLDAP)
	if nameAD != "ldap:ad:guid-1" || nameLDAP != "ldap:ldap:guid-1" || rolesAD[0] != "platform-admin" || rolesLDAP[0] != "dba" {
		t.Fatalf("%q %v / %q %v", nameAD, rolesAD, nameLDAP, rolesLDAP)
	}
}

func TestProviders_TheAccountsMadeBeforeAreTheAdoptingEntrysOnly(t *testing.T) {
	ctx := context.Background()
	for _, adopt := range []string{"corp", ""} {
		w := newProvidersWorld(t, adopt)
		legacy := &domain.User{ID: "user_legacy", Username: "oidc:42", DisplayName: "Old", Roles: []string{"dba"}, IdentitySource: domain.SourceOIDC, ExternalSubject: "42"}
		if err := w.store.Create(ctx, legacy); err != nil {
			t.Fatal(err)
		}
		w.a.next = application.OIDCIdentity{Subject: "42", Groups: []string{"admins"}}
		tok, _, err := w.svc.FinishOIDC(ctx, "code", w.startAt(t, "corp"))
		if err != nil {
			t.Fatal(err)
		}
		userID, name, _, _, _ := w.tokens.Verify(tok)
		if adopt == "corp" && (userID != legacy.ID || name != "oidc:42") {
			t.Fatalf("adopting: account %s %q, want the legacy one", userID, name)
		}
		if adopt == "" && (userID == legacy.ID || name != "oidc:corp:42") {
			t.Fatalf("not adopting: account %s %q, want a new oidc:corp:42", userID, name)
		}
		// partner never adopts: its sub 42 is never the legacy account.
		w.b.next = application.OIDCIdentity{Subject: "42", Groups: []string{"contractors"}}
		tok, _, _ = w.svc.FinishOIDC(ctx, "code", w.startAt(t, "partner"))
		if userID, _, _, _, _ := w.tokens.Verify(tok); userID == legacy.ID {
			t.Fatal("partner's sub 42 reached the legacy account")
		}
	}
}

func TestProviders_AnAttemptWhoseProviderIsGoneIsRefused(t *testing.T) {
	w := newProvidersWorld(t, "")
	state := w.startAt(t, "partner")
	// The service restarts with corp only: partner's attempt, kept in the store, finds no provider.
	w.svc.WithOIDCProviders([]application.OIDCEntry{{ID: "corp", Provider: w.a, Roles: application.RoleMap{"admins": {"platform-admin"}}}}, w.store)
	if _, _, err := w.svc.FinishOIDC(context.Background(), "code", state); !errors.Is(err, application.ErrOIDCRejected) {
		t.Fatalf("%v, want ErrOIDCRejected", err)
	}
	if w.a.exchanged != 0 {
		t.Fatal("the attempt of a provider gone was exchanged at another")
	}
}

// alice of one directory is not alice of another (ADR-0076): an enrollment code is issued for a
// login name at one directory, and enrolls nobody at the other; a directory not configured is not a
// source.
func TestProviders_AnEnrollmentCodeIsForTheLoginNameAtOneDirectoryOnly(t *testing.T) {
	ctx := context.Background()
	key, _ := infrastructure.GenerateSigningKey()
	store := infrastructure.NewInMemoryStore()
	sealer, err := infrastructure.NewMFASealer(mfaKey)
	if err != nil {
		t.Fatal(err)
	}
	da := &fakeDirectory{user: "alice", password: "pass-a", id: application.DirectoryIdentity{ID: "guid-a", Groups: []string{adminsDN}}}
	db := &fakeDirectory{user: "alice", password: "pass-b", id: application.DirectoryIdentity{ID: "guid-b", Groups: []string{adminsDN}}}
	svc := application.NewAuthenticationService(store, infrastructure.Argon2Hasher{}, infrastructure.NewTokenIssuer(key), time.Hour).
		WithDirectories([]application.DirectoryEntry{
			{ID: "ad", Directory: da, Roles: application.RoleMap{adminsDN: {"platform-admin"}}},
			{ID: "ldap", Directory: db, Roles: application.RoleMap{adminsDN: {"platform-admin"}}},
		}).
		WithMFA([]string{"platform-admin"}, store, sealer)
	for _, source := range []string{"ldap:nope", "ldap:", "ldapx", "oidc"} {
		if _, _, err := svc.IssueEnrollmentCode(ctx, "admin-cli", source, "alice"); !errors.Is(err, application.ErrUnknownAccount) {
			t.Fatalf("source %q: %v, want ErrUnknownAccount", source, err)
		}
	}
	code, _, err := svc.IssueEnrollmentCode(ctx, "admin-cli", "ldap:ad", "alice")
	if err != nil {
		t.Fatal(err)
	}
	var atB *application.MFAChallengeRequired
	if _, _, err := svc.LoginLDAP(ctx, "ldap", "alice", "pass-b"); !errors.As(err, &atB) || atB.Kind != domain.MFAEnroll {
		t.Fatalf("alice at ldap: %v, want an enrollment challenge", err)
	}
	if _, err := svc.StartEnrollment(ctx, atB.Challenge, code, ""); err == nil {
		t.Fatal("ad's enrollment code enrolled alice of ldap")
	}
	var atA *application.MFAChallengeRequired
	if _, _, err := svc.LoginLDAP(ctx, "ad", "alice", "pass-a"); !errors.As(err, &atA) {
		t.Fatalf("alice at ad: %v", err)
	}
	if _, err := svc.StartEnrollment(ctx, atA.Challenge, code, ""); err != nil {
		t.Fatalf("ad's code at ad: %v", err)
	}
}
