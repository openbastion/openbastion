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
)

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

// WithOIDC turns federated login on.
func (s *AuthenticationService) WithOIDC(p OIDCProvider, roles RoleMap, attempts domain.LoginAttemptRepository) *AuthenticationService {
	s.oidc, s.roleMap, s.attempts = p, roles, attempts
	return s
}

func random32() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// StartOIDC begins a federated login and returns where to send the browser.
func (s *AuthenticationService) StartOIDC(ctx context.Context) (string, error) {
	if s.oidc == nil {
		return "", ErrOIDCOff
	}
	var a domain.LoginAttempt
	var err error
	for _, v := range []*string{&a.State, &a.Nonce, &a.Verifier} {
		if *v, err = random32(); err != nil {
			return "", err
		}
	}
	a.ExpiresAt = s.clock().Add(AttemptTTL)
	if err := s.attempts.SaveAttempt(ctx, a); err != nil {
		return "", err
	}
	return s.oidc.AuthorizeURL(a.State, a.Nonce, a.Verifier), nil
}

// FinishOIDC ends a federated login: the attempt is taken (once), the code exchanged, the ID
// token verified, the roles computed from the map — none is a refusal — and the account
// found or made, its roles replaced by those of today.
func (s *AuthenticationService) FinishOIDC(ctx context.Context, code, state string) (token string, expiresIn time.Duration, err error) {
	if s.oidc == nil {
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
	raw, err := s.oidc.Exchange(ctx, code, a.Verifier)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrOIDCRejected, err)
	}
	id, err := s.oidc.VerifyIDToken(ctx, raw, a.Nonce)
	if err != nil {
		if errors.Is(err, ErrOIDCRejected) {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("%w: %v", ErrOIDCRejected, err)
	}
	roles := s.roleMap.Roles(id.Groups)
	if len(roles) == 0 {
		return "", 0, ErrNoRole
	}
	u, err := s.federatedUser(ctx, id, roles)
	if err != nil {
		return "", 0, err
	}
	expiresAt := s.clock().Add(s.ttl)
	token, err = s.tokens.Issue(u.ID, u.Username, roles, expiresAt)
	if err != nil {
		return "", 0, err
	}
	return token, s.ttl, nil
}

// federatedUser finds the account of id's subject and gives it today's roles, or makes it. Its
// name is oidc:<sub> — never a name the provider chooses, which could be a local account's.
func (s *AuthenticationService) federatedUser(ctx context.Context, id OIDCIdentity, roles []string) (*domain.User, error) {
	display := id.Name
	if display == "" {
		display = id.Subject
	}
	u, err := s.users.GetByExternalSubject(ctx, domain.SourceOIDC, id.Subject)
	if err == nil {
		if err := s.users.UpdateIdentity(ctx, u.ID, display, roles); err != nil {
			return nil, err
		}
		u.DisplayName, u.Roles = display, roles
		return u, nil
	}
	u = &domain.User{ID: randomID("user"), Username: "oidc:" + id.Subject, DisplayName: display, Roles: roles,
		IdentitySource: domain.SourceOIDC, ExternalSubject: id.Subject}
	if err := s.users.Create(ctx, u); err != nil {
		// Two first logins at once: the other made it.
		if again, err2 := s.users.GetByExternalSubject(ctx, domain.SourceOIDC, id.Subject); err2 == nil {
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
