package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// OperatorPasteTTL is how long a paste token lives at the proxy (ADR-0133 §2): long enough for the
// browser to encrypt and send the password, short enough that a token nobody used is soon gone.
const OperatorPasteTTL = 60 * time.Second

// PasteProxy hands a paste token to the screen proxy that relays the session (ADR-0133 §2). No text
// crosses it: the password comes to the proxy encrypted for it, over the screen stream.
type PasteProxy interface {
	AuthorizePaste(ctx context.Context, protocol, sessionID, accountID, token string, ttl time.Duration) error
}

// OperatorPasteGrant is what the operator's browser receives: the one-use token, and how long it lives.
type OperatorPasteGrant struct {
	Token            string `json:"pasteToken"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
}

// WithPasteProxy enables an operator's paste (ADR-0133). Without it, the paste is unavailable.
func (s *SessionBrokerService) WithPasteProxy(proxy PasteProxy) *SessionBrokerService {
	s.pasteProxy = proxy
	return s
}

// AuthorizeOperatorPasteWithStepUp is the control plane of ADR-0133 option A: the operator's second
// factor for this paste (secret:paste on the session's account), checked, the session and the right
// read again, the grant consumed, then a one-use token handed to the proxy that relays the session,
// and the same token returned to the browser. The Broker never sees the password; it is typed by the
// proxy, from what the browser encrypts for it.
func (s *SessionBrokerService) AuthorizeOperatorPasteWithStepUp(ctx context.Context, actorID string, actorRoles []string, sessionID string, proof MFAActionProof) (OperatorPasteGrant, error) {
	binding, err := s.authorizedSecretAction(ctx, actorID, actorRoles, sessionID, "secret:paste")
	if err != nil {
		return OperatorPasteGrant{}, err
	}
	// The encrypted channel is the screen stream's (ADR-0133 §5): SSH has none.
	if binding.Protocol != "vnc" && binding.Protocol != "rdp" {
		return OperatorPasteGrant{}, domain.ErrUnsupportedProtocol
	}
	if s.mfaAction == nil || s.pasteProxy == nil {
		return OperatorPasteGrant{}, fmt.Errorf("%w: operator paste dependencies are not configured", domain.ErrUnavailable)
	}
	grant, err := s.mfaAction.Verify(ctx, binding, proof)
	if err != nil {
		return OperatorPasteGrant{}, fmt.Errorf("%w: verifying action step-up: %v", domain.ErrForbidden, err)
	}
	if grant.Grant == "" || grant.ExpiresIn <= 0 || grant.ExpiresIn > 30 {
		return OperatorPasteGrant{}, fmt.Errorf("%w: authentication returned an invalid action grant", domain.ErrUnavailable)
	}
	// Read the session and the right again after the factor: a session that ended, or a right that
	// was withdrawn, while the factor was checked gets no token.
	current, err := s.authorizedSecretAction(ctx, actorID, actorRoles, sessionID, "secret:paste")
	if err != nil {
		return OperatorPasteGrant{}, err
	}
	if current != binding {
		return OperatorPasteGrant{}, domain.ErrForbidden
	}
	// The grant is consumed before the token exists: any later failure needs a new factor.
	if err := s.mfaAction.Consume(ctx, binding, grant.Grant); err != nil {
		return OperatorPasteGrant{}, fmt.Errorf("%w: consuming action grant: %v", domain.ErrForbidden, err)
	}
	grant.Grant = ""
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return OperatorPasteGrant{}, fmt.Errorf("%w: drawing a paste token: %v", domain.ErrUnavailable, err)
	}
	token := hex.EncodeToString(raw[:])
	if err := s.pasteProxy.AuthorizePaste(ctx, binding.Protocol, binding.SessionID, binding.AccountID, token, OperatorPasteTTL); err != nil {
		return OperatorPasteGrant{}, fmt.Errorf("%w: the proxy refused the paste token: %v", domain.ErrUnavailable, err)
	}
	// Written before the token leaves: without the audit, the browser gets nothing, and the token the
	// proxy holds expires unused.
	if err := s.audit.EmitEvent(ctx, actorID, "session.secret_paste_authorized", "session", sessionID, true); err != nil {
		return OperatorPasteGrant{}, fmt.Errorf("%w: auditing the paste grant: %v", domain.ErrUnavailable, err)
	}
	return OperatorPasteGrant{Token: token, ExpiresInSeconds: int(OperatorPasteTTL / time.Second)}, nil
}
