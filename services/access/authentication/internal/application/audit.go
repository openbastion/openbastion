package application

// What the Authentication Service writes to the audit (ADR-0064): every token it issues, before it
// issues it (no audit, no token); the second factor's administrative gestures, before they are
// made; and the refusals, at best, within a budget per login name. Never a password, a code, a
// challenge or a secret.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"unicode"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// AuditEmitter is the port to the Audit Service (POST /audit/v1/emit-event).
type AuditEmitter interface {
	EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error
}

// RefusalBudget says whether one more refusal of a key is written (pkg/refusalbudget).
type RefusalBudget interface {
	Take(key string) (write, firstUnwritten bool)
}

// ErrAuditUnavailable: what was to be done is not, because it could not be written first. 503 —
// never a refusal of the credentials.
var ErrAuditUnavailable = errors.New("the audit cannot be written now")

// The actions, as they appear in the chain.
const (
	ActionLogin                    = "auth.login"         // a token without a second factor
	ActionLoginMFA                 = "auth.login_mfa"     // a token after the second factor
	ActionLoginRefused             = "auth.login_refused" // a password, a directory, a code or an enrollment code refused
	ActionMFACodeIssued            = "auth.mfa_enrollment_code_issued"
	ActionMFAEnrolled              = "auth.mfa_enrolled"
	ActionMFAReset                 = "auth.mfa_reset"
	ActionLoginWebAuthn            = "auth.login_webauthn"              // a token after a security key (ADR-0065)
	ActionMFAWebAuthnRegistered    = "auth.mfa_webauthn_registered"     // a security key enrolled
	ActionMFAWebAuthnRevoked       = "auth.mfa_webauthn_revoked"        // one security key revoked (ADR-0066)
	ActionMFAActionChallengeIssued = "auth.mfa_action_challenge_issued" // a fresh action-bound MFA challenge
	ActionMFAActionVerified        = "auth.mfa_action_verified"         // a one-time action grant was issued
	ActionMFAActionGrantConsumed   = "auth.mfa_action_grant_consumed"   // the Session Broker consumed the grant
	ActionMFAActionRefused         = "auth.mfa_action_refused"          // an action-bound MFA proof was refused
	maxAuditedLoginLength          = 256
)

// WithAudit writes to audit; refusals within budget. A service built without it writes nothing:
// cmd/authentication always calls it (and a test proves a login without the audit gets no token).
func (s *AuthenticationService) WithAudit(audit AuditEmitter, refusals RefusalBudget) *AuthenticationService {
	s.audit, s.refusals = audit, refusals
	return s
}

// record writes one event, and fails closed: its error is ErrAuditUnavailable.
func (s *AuthenticationService) record(ctx context.Context, actor, action, resourceType, resourceID string) error {
	return s.recordWith(ctx, actor, action, resourceType, resourceID, nil)
}

// recordWith is record with details (ADR-0068), written when the audit takes them — the client of
// cmd/authentication does.
func (s *AuthenticationService) recordWith(ctx context.Context, actor, action, resourceType, resourceID string, details map[string]string) error {
	if s.audit == nil {
		return nil
	}
	if err := s.emit(ctx, actor, action, resourceType, resourceID, details, true); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrAuditUnavailable, action, err)
	}
	return nil
}

func (s *AuthenticationService) emit(ctx context.Context, actor, action, resourceType, resourceID string, details map[string]string, success bool) error {
	if d, ok := s.audit.(DetailedAuditEmitter); ok && len(details) > 0 {
		return d.EmitEventWithDetails(ctx, actor, action, resourceType, resourceID, details, success)
	}
	return s.audit.EmitEvent(ctx, actor, action, resourceType, resourceID, success)
}

// VariablesProvider names, in the audit, the provider of the OIDC_* and LDAP_* variables (ADR-0078).
const VariablesProvider = "(variables)"

// loginDetails says in the audit who vouches for an account (ADR-0076, point 10): its source and,
// for a provider or a directory, which one. The accounts kept under "" are named after the entry
// that adopts them, or the variables'. A local account has no provider.
func (s *AuthenticationService) loginDetails(source, provider string) map[string]string {
	if source == "" {
		source = domain.SourceLocal
	}
	details := map[string]string{"identity_source": source}
	if source == domain.SourceLocal {
		return details
	}
	if provider == "" {
		provider = VariablesProvider
		var ids []ProviderInfo
		switch source {
		case domain.SourceOIDC:
			for _, e := range s.oidcProviders {
				if e.accounts == "" {
					ids = append(ids, e.info)
				}
			}
		case domain.SourceLDAP:
			for _, d := range s.directories {
				if d.accounts == "" {
					ids = append(ids, d.info)
				}
			}
		}
		if len(ids) == 1 && ids[0].ID != "" {
			provider = ids[0].ID
		}
	}
	details["identity_provider"] = provider
	return details
}

// refused writes a refusal at best — not writing a refusal protects nothing — within the budget of
// its login name; beyond it, the first unwritten one is said in the log.
func (s *AuthenticationService) refused(ctx context.Context, loginName string, details map[string]string) {
	if s.audit == nil {
		return
	}
	name := auditedName(loginName)
	if s.refusals != nil {
		write, first := s.refusals.Take(strings.ToLower(name))
		if !write {
			if first {
				log.Printf("authentication: the refusals of a login name are past their audit budget: the next ones are not written until it refills")
			}
			return
		}
	}
	if err := s.emit(ctx, "", ActionLoginRefused, "login", name, details, false); err != nil {
		log.Printf("authentication: a refused login could not be written to the audit: %v", err)
	}
}

// auditedName is a login name as the chain keeps it: what an attacker typed, so bounded, its
// control characters replaced; empty is said as such.
func auditedName(n string) string {
	if n == "" {
		return "(empty)"
	}
	var b strings.Builder
	for _, c := range n {
		if b.Len() >= maxAuditedLoginLength {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(c) || c == unicode.ReplacementChar {
			c = '?'
		}
		b.WriteRune(c)
	}
	return b.String()
}
