package application

// Rotation after use (ADR-0037, ADR-0044): when a granted session ends, the Vault is told, and
// rotates the account's secret if its policy says post_use. Telling it is a debt, written with
// the end of the session: it is cleared once the Vault has it, and sent again until it does.

import (
	"context"
	"log"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// AfterUseRotator is the port to the Vault's rotate-after-use. nil: the Vault has the notice —
// recorded there, whether the rotation has happened yet or not (ADR-0044).
type AfterUseRotator interface {
	RotateAfterUse(ctx context.Context, accountID, sessionID string, endedAt time.Time) error
}

const (
	// AfterUseTimeout bounds one notice: the Vault may rotate before it answers — a few SSH
	// round trips to the target.
	AfterUseTimeout = 60 * time.Second
	// AfterUseResendAfter is how long after a session's end its notice, if still owed, is sent
	// again by DeliverAfterUse: the first attempt has had its chance.
	AfterUseResendAfter = AfterUseTimeout
	// AfterUseBatch bounds one DeliverAfterUse.
	AfterUseBatch = 20
)

// WithAfterUseRotation tells r when a granted session ends.
func (s *SessionBrokerService) WithAfterUseRotation(r AfterUseRotator) *SessionBrokerService {
	s.rotator = r
	return s
}

// afterUse tells the Vault, apart from the caller — a rotation takes seconds, and the end of a
// session must not wait for it — that sess ended at endedAt. Only a session that owes it (it
// was active when it ended, ADR-0044); the debt is cleared once the Vault has the notice, and
// DeliverAfterUse sends it again otherwise.
func (s *SessionBrokerService) afterUse(sess *domain.Session, endedAt time.Time) {
	if s.rotator == nil || !sess.AfterUseOwed {
		return
	}
	go func(n domain.AfterUseNotice) {
		ctx, cancel := context.WithTimeout(context.Background(), AfterUseTimeout)
		defer cancel()
		s.deliver(ctx, n)
	}(domain.AfterUseNotice{SessionID: sess.ID, AccountID: sess.PrivilegedAccountID, EndedAt: endedAt})
}

// deliver sends one notice and, once the Vault has it, clears the debt.
func (s *SessionBrokerService) deliver(ctx context.Context, n domain.AfterUseNotice) bool {
	logf := s.logf
	if logf == nil {
		logf = log.Printf
	}
	if err := s.rotator.RotateAfterUse(ctx, n.AccountID, n.SessionID, n.EndedAt); err != nil {
		logf("session-broker: telling the Vault that session %s of account %s ended (rotation after use) failed, sent again later: %v", n.SessionID, n.AccountID, err)
		return false
	}
	if err := s.sessions.MarkAfterUseDelivered(ctx, n.SessionID); err != nil {
		logf("session-broker: the Vault has the end of session %s, but it could not be noted (it will be told again, harmlessly): %v", n.SessionID, err)
	}
	return true
}

// DeliverAfterUse sends again the notices still owed for sessions that ended more than
// AfterUseResendAfter ago, at most AfterUseBatch, oldest first, each bounded by
// AfterUseTimeout (ADR-0044). The Vault owes nothing for a notice it already had, so a resend
// — by this Broker or another — is harmless.
func (s *SessionBrokerService) DeliverAfterUse(ctx context.Context) (delivered, failed int, err error) {
	if s.rotator == nil {
		return 0, 0, nil
	}
	owed, err := s.sessions.AfterUseOwed(ctx, s.clock().Add(-AfterUseResendAfter), AfterUseBatch)
	if err != nil {
		return 0, 0, err
	}
	for _, n := range owed {
		one, cancel := context.WithTimeout(ctx, AfterUseTimeout)
		ok := s.deliver(one, n)
		cancel()
		if ok {
			delivered++
		} else {
			failed++
		}
	}
	return delivered, failed, nil
}
