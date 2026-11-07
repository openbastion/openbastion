package application

// Each OIDC provider keeps its issuer (ADR-0078). A subject is unique only at its issuer: another
// issuer under the same provider would log its users into the accounts of the first. At start, the
// issuer of every provider is compared with the one it was bound to; another one refuses the start,
// unless the change is declared — and written to the audit before the binding changes.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// ActionIdentityProviderRebound: a declared change of issuer, written before the binding changes.
const ActionIdentityProviderRebound = "auth.identity_provider_rebound"

// maxAuditedIssuerBytes is the Audit Service's bound on a detail's value (ADR-0068).
const maxAuditedIssuerBytes = 256

// DetailedAuditEmitter writes an event with bounded details (ADR-0068). The change of an issuer
// names both issuers; an emitter without details cannot write it, so the change is refused.
type DetailedAuditEmitter interface {
	EmitEventWithDetails(ctx context.Context, actorID, action, resourceType, resourceID string, details map[string]string, success bool) error
}

// IssuerDeclaration is one OIDC provider as configured.
type IssuerDeclaration struct {
	Provider string // "" for the OIDC_* variables, and for the entry that adopts their accounts
	Issuer   string
	// PreviousIssuer declares a change: the issuer the provider was bound to. Empty: none declared.
	PreviousIssuer string
	// Name is how the configuration names it, for the messages: `OIDC_ISSUER`, `oidc "corp"`.
	Name string
	// Declare is where a change is declared: `OIDC_PREVIOUS_ISSUER`, `oidc "corp": previous_issuer`.
	Declare string
}

// IssuerOutcome is what the start did with one provider.
type IssuerOutcome struct {
	Provider, Name, Issuer string
	Created                bool   // no binding yet: the issuer configured is the one kept from now on
	ReboundFrom            string // the change declared and written: the issuer it was bound to
	StalePrevious          bool   // a declaration with nothing to change: to be removed
}

// ErrIssuerChanged: a provider is configured with another issuer than its own, and no change is
// declared for it — or the one declared is not from the issuer it was bound to.
var ErrIssuerChanged = errors.New("an OIDC provider is configured with another issuer than the one it is bound to")

// BindIssuers checks every declaration against the binding of its provider, all at once: one
// refused, and nothing is recorded, not even the new providers'. A declared change is written to
// the audit first; the audit down, nothing changes (ErrAuditUnavailable).
func (s *AuthenticationService) BindIssuers(ctx context.Context, repo domain.IssuerBindingRepository, decls []IssuerDeclaration) ([]IssuerOutcome, error) {
	want := map[string]string{}
	byProvider := map[string]IssuerDeclaration{}
	for _, d := range decls {
		if d.Issuer == "" {
			return nil, fmt.Errorf("%s: no issuer to bind", d.Name)
		}
		if other, ok := byProvider[d.Provider]; ok {
			return nil, fmt.Errorf("%s and %s are the same provider %q", other.Name, d.Name, d.Provider)
		}
		byProvider[d.Provider], want[d.Provider] = d, d.Issuer
	}
	var outcomes []IssuerOutcome
	err := repo.BindIssuers(ctx, want, func(bound map[string]domain.IssuerBinding) (map[string]string, error) {
		outcomes = outcomes[:0]
		var refusals []error
		replace := map[string]string{}
		for _, p := range sortedKeys(byProvider) {
			d, b := byProvider[p], bound[p]
			o := IssuerOutcome{Provider: p, Name: d.Name, Issuer: d.Issuer}
			switch {
			case b.Created:
				o.Created, o.StalePrevious = true, d.PreviousIssuer != ""
			case b.Issuer == d.Issuer:
				o.StalePrevious = d.PreviousIssuer != ""
			case d.PreviousIssuer == "":
				refusals = append(refusals, fmt.Errorf("%w: %s is bound to the issuer %s, and is configured with %s. Another issuer is another provider: give it a new id in IDENTITY_PROVIDERS_FILE. If it is the same provider under a new URL, with the same subjects, declare the change: %s = %s",
					ErrIssuerChanged, d.Name, b.Issuer, d.Issuer, d.Declare, b.Issuer))
				continue
			case d.PreviousIssuer != b.Issuer:
				refusals = append(refusals, fmt.Errorf("%w: %s declares a change from %s, but it is bound to %s: nothing is changed",
					ErrIssuerChanged, d.Name, d.PreviousIssuer, b.Issuer))
				continue
			default:
				o.ReboundFrom, replace[p] = b.Issuer, d.Issuer
			}
			outcomes = append(outcomes, o)
		}
		if len(refusals) > 0 {
			return nil, errors.Join(refusals...)
		}
		// Every check passed: only now is a change written, each before its row changes.
		for _, p := range sortedKeys(replace) {
			if err := s.recordRebind(ctx, byProvider[p], bound[p].Issuer); err != nil {
				return nil, err
			}
		}
		return replace, nil
	})
	if err != nil {
		return nil, err
	}
	return outcomes, nil
}

func (s *AuthenticationService) recordRebind(ctx context.Context, d IssuerDeclaration, from string) error {
	if len(from) > maxAuditedIssuerBytes || len(d.Issuer) > maxAuditedIssuerBytes {
		return fmt.Errorf("%w: %s: an issuer longer than %d bytes cannot be written to the audit, so its change is not made", ErrAuditUnavailable, d.Name, maxAuditedIssuerBytes)
	}
	emitter, ok := s.audit.(DetailedAuditEmitter)
	if !ok {
		return fmt.Errorf("%w: %s: no audit that writes both issuers, so the change is not made", ErrAuditUnavailable, d.Name)
	}
	resource := d.Provider
	if resource == "" {
		resource = "(variables)"
	}
	if err := emitter.EmitEventWithDetails(ctx, "", ActionIdentityProviderRebound, "identity_provider", resource,
		map[string]string{"previous_issuer": from, "issuer": d.Issuer}, true); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrAuditUnavailable, ActionIdentityProviderRebound, err)
	}
	return nil
}

// LogIssuerOutcomes says at start what was bound, changed, or is to be cleaned.
func LogIssuerOutcomes(outcomes []IssuerOutcome) {
	for _, o := range outcomes {
		switch {
		case o.ReboundFrom != "":
			log.Printf("authentication: %s changed from the issuer %s to %s, as declared — written to the audit (%s)", o.Name, o.ReboundFrom, o.Issuer, ActionIdentityProviderRebound)
		case o.Created:
			log.Printf("authentication: %s bound to the issuer %s: another issuer under it will refuse the start (ADR-0078)", o.Name, o.Issuer)
		}
		if o.StalePrevious {
			log.Printf("authentication: %s declares a previous issuer, and there is nothing to change: remove the declaration", o.Name)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
