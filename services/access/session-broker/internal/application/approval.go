package application

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// SessionApproveResourcePrefix prefixes the RBAC resource that lets somebody approve or
// reject an ordinary session on an account that requires approval (ADR-0067):
// "session-approve:account:{accountId}". It is not breakglass-approve: being trusted to
// let an emergency through is not being the approver of the account's daily work, and
// the reverse.
const SessionApproveResourcePrefix = "session-approve:account:"

// MaxTicketBytes bounds a ticket whatever the declared format allows: it is the
// requester's input, and it ends up in the audit trail, the list the approvers read and
// a notification channel.
const MaxTicketBytes = 128

// defaultTicketPattern is the format of a ticket when the platform declares none: a plain
// reference, 1 to 64 characters among letters, digits and - _ . : /.
var defaultTicketPattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,64}$`)

// CompileTicketPattern compiles APPROVAL_TICKET_PATTERN (ADR-0067). The expression is
// anchored at both ends whatever it says, so that a pattern written as "INC[0-9]{7}"
// does not accept "INC0000001; anything". An empty pattern is the default format.
func CompileTicketPattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return defaultTicketPattern, nil
	}
	re, err := regexp.Compile(`^(?:` + pattern + `)$`)
	if err != nil {
		return nil, fmt.Errorf("APPROVAL_TICKET_PATTERN is not a valid regular expression: %w", err)
	}
	return re, nil
}

// WithApprovalTicketPattern sets the format a ticket must follow (CompileTicketPattern);
// nil keeps the default.
func (s *SessionBrokerService) WithApprovalTicketPattern(re *regexp.Regexp) *SessionBrokerService {
	s.ticketPattern = re
	return s
}

func (s *SessionBrokerService) validTicket(ticket string) bool {
	re := s.ticketPattern
	if re == nil {
		re = defaultTicketPattern
	}
	return ticket != "" && len(ticket) <= MaxTicketBytes && re.MatchString(ticket)
}

// countPending is the early answer to "has this requester room for another request
// waiting?" (ADR-0013), break-glass and approval requests together.
func (s *SessionBrokerService) countPending(ctx context.Context, requestedBy string, now time.Time) error {
	n, err := s.sessions.CountPending(ctx, requestedBy, now)
	if err != nil {
		// Fail closed: a request that cannot be counted is not accepted.
		return fmt.Errorf("%w (counting the requests waiting: %v)", domain.ErrUnavailable, err)
	}
	if n >= s.maxPending() {
		return s.tooManyPending()
	}
	return nil
}

// savePending stores a request that waits for a second person — a break-glass one
// (ADR-0011) or one on an account that requires approval (ADR-0067) — once its request
// event is on the audit trail: under the requester's limit, with the deadline for a
// decision, then notified. action is the request event, written again as a refusal if
// another request of the same requester took the last place first.
func (s *SessionBrokerService) savePending(ctx context.Context, sess *domain.Session, now time.Time, action, event string, details map[string]string) (*domain.Session, error) {
	sess.Status = domain.StatusPendingApproval
	sess.ExpiresAt = now.Add(s.window()) // the deadline for a decision
	saved, err := s.sessions.SaveIfUnderPendingLimit(ctx, sess, s.maxPending(), now)
	if err != nil {
		return nil, fmt.Errorf("%w: saving the request: %w", domain.ErrUnavailable, err)
	}
	if !saved {
		// The count said there was room, and another request of the same requester
		// took it first (ADR-0013). Refused like any other: the event written said
		// "requested"; this one, for the same session, says it was not, and the last
		// one decides.
		sess.Status = domain.StatusDenied
		if err := s.sessions.Save(ctx, sess); err != nil {
			return nil, fmt.Errorf("%w: recording the refused request: %w", domain.ErrUnavailable, err)
		}
		if err := s.emitAudit(ctx, sess.RequestedBy, action, "session", sess.ID, details, false); err != nil {
			return nil, fmt.Errorf("%w: auditing the refused request: %w", domain.ErrUnavailable, err)
		}
		return nil, fmt.Errorf("request refused: %w", s.tooManyPending())
	}
	// Told only now that the request exists to be decided (ADR-0012).
	s.notify(ctx, domain.ApprovalNotification{
		Event: event, SessionID: sess.ID, AccountID: sess.PrivilegedAccountID,
		RequestedBy: sess.RequestedBy, DurationMinutes: sess.DurationMinutes, Ticket: sess.Ticket,
		ExpiresAt: sess.ExpiresAt, At: now,
	})
	return sess, nil
}

// requestApproval is the request for an ordinary session on an account that requires
// another person's approval (ADR-0067). The ticket is checked against the declared
// format, the requester's limit of requests waiting is the break-glass one, and the
// request is on the audit trail BEFORE it is stored: without the event, no request.
// Every refusal is a denied session and an audited one, under the same action.
func (s *SessionBrokerService) requestApproval(ctx context.Context, sess *domain.Session, ticketInput ApprovalTicketInput, now time.Time) (*domain.Session, error) {
	const action = "session.approval_requested"
	sess.ApprovalRequired = true
	ticket := ticketInput.Value
	validTicket := ticketInput.IsString && s.validTicket(ticket)
	var refusal error
	if !validTicket {
		refusal = domain.ErrInvalidTicket
	} else {
		sess.Ticket = ticket
		refusal = s.countPending(ctx, sess.RequestedBy, now)
	}
	if refusal != nil {
		sess.Ticket = "" // a refused ticket is not kept: it is input nobody accepted
		sess.Status = domain.StatusDenied
		if err := s.sessions.Save(ctx, sess); err != nil {
			return nil, fmt.Errorf("%w: recording the refused approval request: %w", domain.ErrUnavailable, err)
		}
		details := map[string]string(nil)
		if validTicket {
			details = map[string]string{"ticket": ticket}
		}
		if err := s.emitAudit(ctx, sess.RequestedBy, action, "session", sess.ID, details, false); err != nil {
			return nil, fmt.Errorf("%w: auditing the refused approval request: %w", domain.ErrUnavailable, err)
		}
		return nil, fmt.Errorf("approval request refused: %w", refusal)
	}
	if err := s.emitAudit(ctx, sess.RequestedBy, action, "session", sess.ID, map[string]string{"ticket": ticket}, true); err != nil {
		sess.Status = domain.StatusDenied
		_ = s.sessions.Save(ctx, sess)
		return nil, fmt.Errorf("%w: cannot accept the request: audit emission failed (fail-closed, docs/deployment/high-availability.md §1): %w", domain.ErrUnavailable, err)
	}
	return s.savePending(ctx, sess, now, action, domain.NotifyApprovalRequested, map[string]string{"ticket": ticket})
}
