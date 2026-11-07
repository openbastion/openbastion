package application

// Federated login with OpenID Connect (ADR-0035): the provider says who the user is and which
// groups they are in; only the role map declared here says what that is worth.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// OIDCIdentity is what a verified ID token says.
type OIDCIdentity struct {
	Subject string
	Name    string
	Groups  []string
}

// OIDCProvider is the port to one OpenID Connect provider.
type OIDCProvider interface {
	AuthorizeURL(state, nonce, verifier string) string
	Exchange(ctx context.Context, code, verifier string) (idToken string, err error)
	VerifyIDToken(ctx context.Context, idToken, nonce string) (OIDCIdentity, error)
}

var (
	// ErrOIDCRejected: the login cannot be trusted — an unknown or used state, a code the
	// provider refused, an ID token that does not verify. The client learns nothing more.
	ErrOIDCRejected = errors.New("the federated login was refused")
	// ErrNoRole: the identity is genuine, and the role map gives it no OpenBastion role.
	ErrNoRole = errors.New("this identity has no OpenBastion role")
	// ErrOIDCOff: no provider is configured.
	ErrOIDCOff = errors.New("federated login is not configured")
	// ErrProviderRequired: several providers are configured and the request names none (400).
	ErrProviderRequired = errors.New("several identity providers are configured: name one")
	// ErrUnknownProvider: the request names a provider that is not configured (400).
	ErrUnknownProvider = errors.New("no such identity provider")
)

// ProviderInfo is all the login screen may show of a provider or a directory (ADR-0076 §9): never
// its issuer, its URL or its base.
type ProviderInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// OIDCEntry is one provider to turn on (ADR-0076). ID "" is the one of the OIDC_* variables.
// AdoptLegacyAccounts: this provider's accounts are those made before ADR-0076 (provider "").
type OIDCEntry struct {
	ID, Label           string
	Provider            OIDCProvider
	Roles               RoleMap
	AdoptLegacyAccounts bool
}

type oidcEntry struct {
	info     ProviderInfo
	provider OIDCProvider
	roles    RoleMap
	accounts string // the identity_provider of its accounts
}

// accountsKey is the identity_provider under which an entry's accounts are kept: "" for the
// variables' provider and the one that adopts the accounts made before ADR-0076, its ID otherwise.
func accountsKey(id string, adopt bool) string {
	if adopt {
		return ""
	}
	return id
}

// AttemptTTL is how long a login may take between start and callback.
const AttemptTTL = 10 * time.Minute

// RoleMap says what each group of the provider is worth: a group absent from it gives nothing.
type RoleMap map[string][]string

// LoadRoleMap reads the role map file: a JSON object of group to list of roles, each role a
// non-empty name of a-z, 0-9, - and _.
func LoadRoleMap(path string) (RoleMap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m RoleMap
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("the role map is not a JSON object of group to list of roles: %v", err)
	}
	if len(m) == 0 {
		return nil, errors.New("the role map is empty: no federated user could ever have a role")
	}
	for g, roles := range m {
		if g == "" || len(roles) == 0 {
			return nil, fmt.Errorf("the role map has an empty group or a group with no role")
		}
		for _, r := range roles {
			if !validRole(r) {
				return nil, fmt.Errorf("the role map gives group %q the role %q, which is not a role name (a-z, 0-9, - and _)", g, r)
			}
		}
	}
	return m, nil
}

func validRole(r string) bool {
	if r == "" || len(r) > 64 {
		return false
	}
	for _, c := range r {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Roles is what groups are worth: the union of their roles, sorted, each once.
func (m RoleMap) Roles(groups []string) []string {
	set := map[string]bool{}
	for _, g := range groups {
		for _, r := range m[g] {
			set[r] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// WithOIDC turns federated login on with one provider, the one of the OIDC_* variables.
func (s *AuthenticationService) WithOIDC(p OIDCProvider, roles RoleMap, attempts domain.LoginAttemptRepository) *AuthenticationService {
	return s.WithOIDCProviders([]OIDCEntry{{Provider: p, Roles: roles}}, attempts)
}

// WithOIDCProviders turns federated login on with entries (ADR-0076); cmd/authentication has
// checked them: distinct IDs, at most one that adopts the accounts made before.
func (s *AuthenticationService) WithOIDCProviders(entries []OIDCEntry, attempts domain.LoginAttemptRepository) *AuthenticationService {
	s.oidcProviders = nil
	for _, e := range entries {
		s.oidcProviders = append(s.oidcProviders, oidcEntry{info: ProviderInfo{ID: e.ID, Label: e.Label}, provider: e.Provider,
			roles: e.Roles, accounts: accountsKey(e.ID, e.AdoptLegacyAccounts || e.ID == "")})
	}
	s.attempts = attempts
	return s
}

// OIDCProviders is what the login screen may show of the providers, in the declared order.
func (s *AuthenticationService) OIDCProviders() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(s.oidcProviders))
	for _, e := range s.oidcProviders {
		out = append(out, e.info)
	}
	return out
}

// oidcProvider is the provider id names; with a single provider, id may be empty. Several and
// none named: ErrProviderRequired — never a default, which would send the user to a provider
// they did not choose.
func (s *AuthenticationService) oidcProvider(id string) (*oidcEntry, error) {
	if len(s.oidcProviders) == 0 {
		return nil, ErrOIDCOff
	}
	if id == "" && len(s.oidcProviders) == 1 {
		return &s.oidcProviders[0], nil
	}
	if id == "" {
		return nil, ErrProviderRequired
	}
	for i := range s.oidcProviders {
		if s.oidcProviders[i].info.ID == id {
			return &s.oidcProviders[i], nil
		}
	}
	return nil, ErrUnknownProvider
}

func random32() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// StartOIDC begins a federated login at provider and returns where to send the browser. The
// attempt keeps the provider: its callback is exchanged there only (ADR-0076 §7).
func (s *AuthenticationService) StartOIDC(ctx context.Context, provider string) (string, error) {
	p, err := s.oidcProvider(provider)
	if err != nil {
		return "", err
	}
	a := domain.LoginAttempt{Provider: p.info.ID}
	for _, v := range []*string{&a.State, &a.Nonce, &a.Verifier} {
		if *v, err = random32(); err != nil {
			return "", err
		}
	}
	a.ExpiresAt = s.clock().Add(AttemptTTL)
	if err := s.attempts.SaveAttempt(ctx, a); err != nil {
		return "", err
	}
	return p.provider.AuthorizeURL(a.State, a.Nonce, a.Verifier), nil
}

// FinishOIDC ends a federated login: the attempt is taken (once), the code exchanged, the ID
// token verified, the roles computed from the map — none is a refusal — and the account
// found or made, its roles replaced by those of today.
//
// The provider is the attempt's, never one the callback names: a code or an ID token of another
// provider is exchanged and verified where it was not issued, and refused (the mix-up attack,
// RFC 9207). A provider no longer configured since the start: refused.
func (s *AuthenticationService) FinishOIDC(ctx context.Context, code, state string) (token string, expiresIn time.Duration, err error) {
	if len(s.oidcProviders) == 0 {
		return "", 0, ErrOIDCOff
	}
	if code == "" || state == "" {
		return "", 0, ErrOIDCRejected
	}
	a, err := s.attempts.TakeAttempt(ctx, state)
	if err != nil {
		if errors.Is(err, domain.ErrAttemptNotFound) {
			return "", 0, ErrOIDCRejected
		}
		return "", 0, err
	}
	if !s.clock().Before(a.ExpiresAt) {
		return "", 0, ErrOIDCRejected
	}
	var p *oidcEntry
	for i := range s.oidcProviders {
		if s.oidcProviders[i].info.ID == a.Provider {
			p = &s.oidcProviders[i]
		}
	}
	if p == nil {
		return "", 0, ErrOIDCRejected
	}
	raw, err := p.provider.Exchange(ctx, code, a.Verifier)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrOIDCRejected, err)
	}
	id, err := p.provider.VerifyIDToken(ctx, raw, a.Nonce)
	if err != nil {
		if errors.Is(err, ErrOIDCRejected) {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("%w: %v", ErrOIDCRejected, err)
	}
	roles := p.roles.Roles(id.Groups)
	if len(roles) == 0 {
		return "", 0, ErrNoRole
	}
	u, err := s.federatedUser(ctx, p.accounts, id, roles)
	if err != nil {
		return "", 0, err
	}
	// The provider's second factor is its own (ADR-0035): an auth.login, written first (ADR-0064).
	return s.issue(ctx, u, roles, ActionLogin)
}

// federatedUser finds the account of id's subject at the provider whose accounts are kept under
// accounts, and gives it today's roles, or makes it.
func (s *AuthenticationService) federatedUser(ctx context.Context, accounts string, id OIDCIdentity, roles []string) (*domain.User, error) {
	display := id.Name
	if display == "" {
		display = id.Subject
	}
	return s.externalUser(ctx, domain.SourceOIDC, accounts, id.Subject, display, roles)
}

// externalUser finds the account that provider of source vouches for as subject and gives it
// today's roles, or makes it. Its name is <source>:<provider>:<subject>, or <source>:<subject> for
// the provider "" (the accounts made before ADR-0076 keep their name) — never a name the provider
// or the directory chooses. The account is found by its subject, never by its name: a name already
// taken (a subject holding ':' at the provider "", or a local account named so) makes Create fail,
// and the login is refused — a collision of names never joins two identities.
func (s *AuthenticationService) externalUser(ctx context.Context, source, provider, subject, display string, roles []string) (*domain.User, error) {
	u, err := s.users.GetByExternalSubject(ctx, source, provider, subject)
	if err == nil {
		if err := s.users.UpdateIdentity(ctx, u.ID, display, roles); err != nil {
			return nil, err
		}
		u.DisplayName, u.Roles = display, roles
		return u, nil
	}
	name := source + ":" + subject
	if provider != "" {
		name = source + ":" + provider + ":" + subject
	}
	u = &domain.User{ID: randomID("user"), Username: name, DisplayName: display, Roles: roles,
		IdentitySource: source, IdentityProvider: provider, ExternalSubject: subject}
	if err := s.users.Create(ctx, u); err != nil {
		// Two first logins at once: the other made it.
		if again, err2 := s.users.GetByExternalSubject(ctx, source, provider, subject); err2 == nil {
			if err := s.users.UpdateIdentity(ctx, again.ID, display, roles); err != nil {
				return nil, err
			}
			again.DisplayName, again.Roles = display, roles
			return again, nil
		}
		return nil, err
	}
	return u, nil
}
