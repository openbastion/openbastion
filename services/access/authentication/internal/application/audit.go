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
	ActionLogin           = "auth.login"         // a token without a second factor
	ActionLoginMFA        = "auth.login_mfa"     // a token after the second factor
	ActionLoginRefused    = "auth.login_refused" // a password, a directory, a code or an enrollment code refused
	ActionMFACodeIssued   = "auth.mfa_enrollment_code_issued"
	ActionMFAEnrolled     = "auth.mfa_enrolled"
	ActionMFAReset        = "auth.mfa_reset"
	maxAuditedLoginLength = 256
)

// WithAudit writes to audit; refusals within budget. A service built without it writes nothing:
// cmd/authentication always calls it (and a test proves a login without the audit gets no token).
func (s *AuthenticationService) WithAudit(audit AuditEmitter, refusals RefusalBudget) *AuthenticationService {
	s.audit, s.refusals = audit, refusals
	return s
}

// record writes one event, and fails closed: its error is ErrAuditUnavailable.
func (s *AuthenticationService) record(ctx context.Context, actor, action, resourceType, resourceID string) error {
	if s.audit == nil {
		return nil
	}
	if err := s.audit.EmitEvent(ctx, actor, action, resourceType, resourceID, true); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrAuditUnavailable, action, err)
	}
	return nil
}

// refused writes a refusal at best — not writing a refusal protects nothing — within the budget of
// its login name; beyond it, the first unwritten one is said in the log.
func (s *AuthenticationService) refused(ctx context.Context, loginName string) {
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
	if err := s.audit.EmitEvent(ctx, "", ActionLoginRefused, "login", name, false); err != nil {
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
