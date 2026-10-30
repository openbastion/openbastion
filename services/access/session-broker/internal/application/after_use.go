package application

// Rotation after use (ADR-0037): when a granted session ends, the Vault is told, and rotates
// the account's secret if its policy says post_use.

import (
	"context"
	"log"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// AfterUseRotator is the port to the Vault's rotate-after-use.
type AfterUseRotator interface {
	RotateAfterUse(ctx context.Context, accountID, sessionID string) error
}

// AfterUseTimeout bounds one rotation after use: a few SSH round trips to the target.
const AfterUseTimeout = 60 * time.Second

// WithAfterUseRotation tells r when a granted session ends.
func (s *SessionBrokerService) WithAfterUseRotation(r AfterUseRotator) *SessionBrokerService {
	s.rotator = r
	return s
}

// afterUse tells the Vault that sess ended, apart from the caller — a rotation takes seconds,
// and the end of a session must not wait for it. A request that was never granted (a
// break-glass request no one approved) was never used: nothing to rotate. A failure is
// written to the log; the Vault audits its own rotations.
func (s *SessionBrokerService) afterUse(sess *domain.Session) {
	if s.rotator == nil || (sess.BreakGlass && sess.DecidedBy == "") {
		return
	}
	logf := s.logf
	if logf == nil {
		logf = log.Printf
	}
	go func(accountID, sessionID string) {
		ctx, cancel := context.WithTimeout(context.Background(), AfterUseTimeout)
		defer cancel()
		if err := s.rotator.RotateAfterUse(ctx, accountID, sessionID); err != nil {
			logf("session-broker: telling the Vault that session %s of account %s ended (rotation after use) failed: %v", sessionID, accountID, err)
		}
	}(sess.PrivilegedAccountID, sess.ID)
}
