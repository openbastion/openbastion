package application

// The search of sessions (ADR-0080, point 5): their metadata only — the requester, the account,
// the justification and the ticket, already in clear in the Broker's database. Who may see a
// session is who may read it (GetSession, ADR-0021): its requester and the person who decided it,
// who are given nothing new and write nothing; anybody else on the strength of a policy on its
// account — and each session so served is a session.read, written BEFORE it is served. Any of
// them unwritten: nothing is served.

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// The bounds of a search of sessions (ADR-0080, points 5 and 6): constants, not settings.
const (
	SessionSearchMaxWindow = 31 * 24 * time.Hour
	SessionSearchPageSize  = 50
	SessionSearchMinText   = 3
	SessionSearchMaxText   = 256
	// SessionSearchMaxScanned bounds what one page looks at: past it, the page ends and says
	// where the next one starts, even with fewer than 50 sessions served.
	SessionSearchMaxScanned = 500
	sessionSearchBatch      = 100
)

// ErrInvalidSearch: a text or a window outside the bounds.
var ErrInvalidSearch = errors.New("invalid search")

// SessionSearchRequest is a search as the Gateway relays it.
type SessionSearchRequest struct {
	domain.SessionSearch
	Status domain.SessionStatus // the effective status; empty: any
}

// SessionSearchResult is one page.
type SessionSearchResult struct {
	Sessions []*domain.Session
	// Next is where the next page starts; nil when the window holds nothing more.
	Next *domain.SearchCursor
}

// SearchSessions serves one page of the sessions of the window that match, among those the
// caller may read. callerID and actorRoles are the Gateway's, from the verified token.
func (s *SessionBrokerService) SearchSessions(ctx context.Context, callerID string, actorRoles []string, req SessionSearchRequest) (SessionSearchResult, error) {
	if callerID == "" {
		return SessionSearchResult{}, fmt.Errorf("%w: searching sessions needs an authenticated user", domain.ErrForbidden)
	}
	if n := utf8.RuneCountInString(req.Text); !utf8.ValidString(req.Text) || n != 0 && (n < SessionSearchMinText || n > SessionSearchMaxText) {
		return SessionSearchResult{}, fmt.Errorf("%w: the text searched is %d to %d characters, or none", ErrInvalidSearch, SessionSearchMinText, SessionSearchMaxText)
	}
	if req.From.IsZero() || req.To.IsZero() || !req.From.Before(req.To) || req.To.Sub(req.From) > SessionSearchMaxWindow {
		return SessionSearchResult{}, fmt.Errorf("%w: the window is from before to, at most %d days", ErrInvalidSearch, int(SessionSearchMaxWindow.Hours()/24))
	}
	now := s.clock()
	byPolicy := map[string]bool{} // account -> may the caller read its sessions, asked once per page
	var served []*domain.Session
	var policyRead []string
	q := req.SessionSearch
	scanned := 0
	var last *domain.SearchCursor
	more := true
	for len(served) < SessionSearchPageSize && scanned < SessionSearchMaxScanned && more {
		batch, err := s.sessions.SearchSessions(ctx, q, sessionSearchBatch)
		if err != nil {
			return SessionSearchResult{}, fmt.Errorf("%w (searching the sessions: %v)", domain.ErrUnavailable, err)
		}
		more = len(batch) == sessionSearchBatch
		for i, sess := range batch {
			scanned++
			last = &domain.SearchCursor{CreatedAt: sess.CreatedAt, ID: sess.ID}
			reflected := *sess
			reflected.Status = sess.EffectiveStatus(now)
			if req.Status != "" && reflected.Status != req.Status {
				if scanned >= SessionSearchMaxScanned {
					more = more || i < len(batch)-1
					break
				}
				continue
			}
			own := callerID == sess.RequestedBy || sess.DecidedBy != "" && callerID == sess.DecidedBy
			if !own {
				allowed, asked := byPolicy[sess.PrivilegedAccountID]
				if !asked {
					ok, _, err := s.authz.CheckAccess(ctx, actorRoles, SessionReadResourcePrefix+sess.PrivilegedAccountID, "session:read")
					if err != nil {
						return SessionSearchResult{}, fmt.Errorf("%w (asking the Authorization Service: %v)", domain.ErrUnavailable, err)
					}
					allowed, byPolicy[sess.PrivilegedAccountID] = ok, ok
				}
				if !allowed {
					if scanned >= SessionSearchMaxScanned {
						more = more || i < len(batch)-1
						break
					}
					continue
				}
				policyRead = append(policyRead, sess.ID)
			}
			served = append(served, &reflected)
			if len(served) == SessionSearchPageSize || scanned >= SessionSearchMaxScanned {
				more = more || i < len(batch)-1
				break
			}
		}
		q.After = last
	}
	// Each session served on the strength of a policy is on the record before it is served.
	for _, id := range policyRead {
		if err := s.audit.EmitEvent(ctx, callerID, "session.read", "session", id, true); err != nil {
			return SessionSearchResult{}, fmt.Errorf("%w (recording a read by the search: %v)", domain.ErrUnavailable, err)
		}
	}
	result := SessionSearchResult{Sessions: served}
	if more && last != nil {
		// Something may be left: the next page starts after the last session looked at.
		result.Next = last
	}
	return result, nil
}
