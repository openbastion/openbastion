package application_test

// Federated login (ADR-0035): the provider says who and which groups; only the role map says
// what that is worth.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

// fakeProvider hands out, for any code, the identity set in `next`, if the verifier and the
// nonce are the attempt's.
type fakeProvider struct {
	next      application.OIDCIdentity
	exchanged int
	refuse    bool
	attempts  map[string][2]string // state -> verifier, nonce, as the authorize URL carried them
}

func (f *fakeProvider) AuthorizeURL(state, nonce, verifier string) string {
	f.attempts[state] = [2]string{verifier, nonce}
	return "https://idp.example/authorize?" + url.Values{"state": {state}}.Encode()
}

func (f *fakeProvider) Exchange(_ context.Context, code, verifier string) (string, error) {
	f.exchanged++
	if f.refuse {
		return "", errors.New("invalid_grant")
	}
	return "idtoken|" + verifier, nil
}

func (f *fakeProvider) VerifyIDToken(_ context.Context, raw, nonce string) (application.OIDCIdentity, error) {
	for _, a := range f.attempts {
		if raw == "idtoken|"+a[0] && nonce == a[1] {
			return f.next, nil
		}
	}
	return application.OIDCIdentity{}, application.ErrOIDCRejected
}

func oidcService(t *testing.T) (*application.AuthenticationService, *fakeProvider, *infrastructure.InMemoryStore, *time.Time, *infrastructure.TokenIssuer) {
	t.Helper()
	key, _ := infrastructure.GenerateSigningKey()
	tokens := infrastructure.NewTokenIssuer(key)
	store := infrastructure.NewInMemoryStore()
	p := &fakeProvider{attempts: map[string][2]string{}}
	// The tokens are verified on the real clock: the service's starts from it.
	now := time.Now().UTC()
	svc := application.NewAuthenticationService(store, infrastructure.Argon2Hasher{}, tokens, time.Hour).
		WithOIDC(p, application.RoleMap{"bastion-admins": {"platform-admin", "vault-admin"}, "dbas": {"dba"}}, store).
		WithClock(func() time.Time { return now })
	return svc, p, store, &now, tokens
}

func start(t *testing.T, svc *application.AuthenticationService) string {
	t.Helper()
	u, err := svc.StartOIDC(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(u)
	return parsed.Query().Get("state")
}

func TestFinishOIDC_TheRolesAreTheMapsNotTheProviders_AndTheAccountIsOIDCSub(t *testing.T) {
	svc, p, store, _, tokens := oidcService(t)
	p.next = application.OIDCIdentity{Subject: "sub-42", Name: "root-admin", Groups: []string{"dbas", "unmapped", "platform-admin"}}
	token, ttl, err := svc.FinishOIDC(context.Background(), "code", start(t, svc))
	if err != nil || ttl != time.Hour {
		t.Fatalf("FinishOIDC: %v", err)
	}
	userID, username, roles, _, err := tokens.Verify(token)
	if err != nil || username != "oidc:sub-42" || fmt.Sprint(roles) != "[dba]" {
		t.Fatalf("token: %s %v %v — want oidc:sub-42 with [dba] only: a group named like a role gives nothing", username, roles, err)
	}
	u, _ := store.GetByID(context.Background(), userID)
	if u.IdentitySource != domain.SourceOIDC || u.ExternalSubject != "sub-42" || u.DisplayName != "root-admin" || u.PasswordHash != "" {
		t.Fatalf("account %+v", u)
	}
	// The display name the provider chose is not a login: no local account root-admin exists,
	// and the federated one cannot log in with a password.
	if _, _, err := svc.Login(context.Background(), "oidc:sub-42", ""); err == nil {
		t.Fatal("the federated account logs in locally with an empty password")
	}
}

func TestFinishOIDC_AStateIsTakenOnce_AndExpires(t *testing.T) {
	svc, p, _, now, _ := oidcService(t)
	p.next = application.OIDCIdentity{Subject: "s", Groups: []string{"dbas"}}
	state := start(t, svc)
	if _, _, err := svc.FinishOIDC(context.Background(), "code", state); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.FinishOIDC(context.Background(), "code", state); !errors.Is(err, application.ErrOIDCRejected) {
		t.Fatalf("the same state again: %v, want refused", err)
	}
	for name, s := range map[string]string{"never started": "forged-state", "empty": ""} {
		if _, _, err := svc.FinishOIDC(context.Background(), "code", s); !errors.Is(err, application.ErrOIDCRejected) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	late := start(t, svc)
	*now = now.Add(application.AttemptTTL)
	before := p.exchanged
	if _, _, err := svc.FinishOIDC(context.Background(), "code", late); !errors.Is(err, application.ErrOIDCRejected) {
		t.Fatalf("an attempt at its end: %v, want refused", err)
	}
	if p.exchanged != before {
		t.Fatal("an expired attempt's code was sent to the provider")
	}
}

func TestFinishOIDC_NoMappedRoleIsRefused_AndRolesFollowTheGroupsAtEachLogin(t *testing.T) {
	svc, p, store, _, tokens := oidcService(t)
	p.next = application.OIDCIdentity{Subject: "s", Groups: []string{"marketing"}}
	if _, _, err := svc.FinishOIDC(context.Background(), "code", start(t, svc)); !errors.Is(err, application.ErrNoRole) {
		t.Fatalf("no mapped group: %v, want ErrNoRole", err)
	}
	if _, err := store.GetByExternalSubject(context.Background(), domain.SourceOIDC, "s"); err == nil {
		t.Fatal("an account was made for an identity with no role")
	}
	p.next.Groups = []string{"bastion-admins"}
	tok, _, _ := svc.FinishOIDC(context.Background(), "code", start(t, svc))
	_, _, roles, _, _ := tokens.Verify(tok)
	if fmt.Sprint(roles) != "[platform-admin vault-admin]" {
		t.Fatalf("roles %v", roles)
	}
	p.next.Groups = []string{"dbas"} // left the admins at the provider
	tok, _, _ = svc.FinishOIDC(context.Background(), "code", start(t, svc))
	id, _, roles, _, _ := tokens.Verify(tok)
	if fmt.Sprint(roles) != "[dba]" {
		t.Fatalf("after leaving the group: %v, want [dba]", roles)
	}
	u, _ := store.GetByID(context.Background(), id)
	if fmt.Sprint(u.Roles) != "[dba]" {
		t.Fatalf("stored roles %v", u.Roles)
	}
}

func TestFinishOIDC_ACodeTheProviderRefusesOrATokenThatDoesNotVerifyIsRefused(t *testing.T) {
	svc, p, _, _, _ := oidcService(t)
	p.next = application.OIDCIdentity{Subject: "s", Groups: []string{"dbas"}}
	p.refuse = true
	if _, _, err := svc.FinishOIDC(context.Background(), "code", start(t, svc)); !errors.Is(err, application.ErrOIDCRejected) {
		t.Fatalf("code refused: %v", err)
	}
	p.refuse = false
	state := start(t, svc)
	p.attempts[state] = [2]string{"another-verifier", "another-nonce"} // what the provider saw is not this attempt
	if _, _, err := svc.FinishOIDC(context.Background(), "code", state); !errors.Is(err, application.ErrOIDCRejected) {
		t.Fatalf("a token for another attempt: %v", err)
	}
}

func TestOIDC_OffUnlessConfigured(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.StartOIDC(context.Background()); !errors.Is(err, application.ErrOIDCOff) {
		t.Fatalf("StartOIDC: %v", err)
	}
	if _, _, err := svc.FinishOIDC(context.Background(), "c", "s"); !errors.Is(err, application.ErrOIDCOff) {
		t.Fatalf("FinishOIDC: %v", err)
	}
}

func TestLoadRoleMap_RefusesAMapThatCannotBeRight(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"not JSON":             "groups: admins",
		"empty":                "{}",
		"a group with no role": `{"admins": []}`,
		"an empty group":       `{"": ["dba"]}`,
		"a role with a space":  `{"admins": ["platform admin"]}`,
		"a role in capitals":   `{"admins": ["Platform-Admin"]}`,
		"a role that is a map": `{"admins": {"role": "dba"}}`,
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		_ = os.WriteFile(path, []byte(body), 0o600)
		if _, err := application.LoadRoleMap(path); err == nil {
			t.Fatalf("%s: loaded", name)
		}
	}
	path := filepath.Join(dir, "ok.json")
	_ = os.WriteFile(path, []byte(`{"bastion-admins": ["platform-admin", "vault-admin"], "dbas": ["dba"]}`), 0o600)
	m, err := application.LoadRoleMap(path)
	if err != nil || fmt.Sprint(m.Roles([]string{"dbas", "bastion-admins", "dbas"})) != "[dba platform-admin vault-admin]" {
		t.Fatalf("%v %v", m, err)
	}
	if _, err := application.LoadRoleMap(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("a missing file loaded")
	}
}
