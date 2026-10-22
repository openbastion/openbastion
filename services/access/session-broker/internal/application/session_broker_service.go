// Package application implements SessionOrchestration
// (proto/access/v1/session_orchestration.proto, doc 07 §3) plus the
// "Vault Authorizer" responsibility from the Session Broker's component
// diagram (OpenBastion_01_Diagrammes_C4.md §4.1).
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// AuthorizationClient is the port to the Authorization Service
// (proto/authz/v1/authorization.proto, doc 07 §8).
type AuthorizationClient interface {
	CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (allowed bool, reason string, err error)
}

// VaultAuthorizer is the port to VaultAuthorization ONLY
// (proto/vault/v1/vault.proto, doc 07 §5) — note there is no
// FetchCredential method on this interface. The Session Broker is
// structurally incapable of fetching a credential; that capability
// belongs to VaultCredentialIssuance, callable only by a proxy
// (ADR-0003). This is the invariant enforced at the Go type level, not
// just in documentation.
type VaultAuthorizer interface {
	AuthorizeScope(ctx context.Context, sessionID, accountID, proxyServiceID string, ttl time.Duration) (scopeToken string, expiresAt time.Time, err error)
}

// AuditEmitter is the port to AuditIngestion (proto/audit/v1/audit.proto).
type AuditEmitter interface {
	EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error
}

// AccountLookup resolves a privileged account's connection metadata —
// target host and username — never a secret (doc 05 §2: "GET
// /vault/accounts/{id}... métadonnées, jamais le secret"). The Broker
// needs this to tell a proxy where and as whom to connect; it has no
// other way to learn it, and this port cannot return secret material by
// construction (its return type has no field for it).
type AccountLookup interface {
	GetAccount(ctx context.Context, accountID string) (targetHost, targetUser string, err error)
}

// ProxyClient is the port to a single proxy's ProxyControl.EstablishSession
// (proto/proxy/v1/proxy_control.proto, doc 07 §4). It returns a
// connection_ticket — safe to hand to a client — never the scope token
// that was used to obtain it.
type ProxyClient interface {
	// breakGlass is the Broker's authorisation for a recording waiver (ADR-0009).
	// The proxy honours it only if it was itself configured to.
	EstablishSession(ctx context.Context, sessionID, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool) (proxyEndpoint, connectionTicket string, err error)
}

// ProxySelector resolves which proxy family serves a given protocol.
// MVP supports SSH only (doc 04 §2); v1.0 extends this switch, not the
// callers of it.
type ProxySelector struct{}

func (ProxySelector) Select(protocol string) (proxyServiceID string, err error) {
	switch protocol {
	case "ssh":
		return "ssh-proxy", nil
	default:
		return "", fmt.Errorf("no proxy available for protocol %q (MVP scope is SSH only, doc 04 §2)", protocol)
	}
}

type SessionBrokerService struct {
	sessions domain.SessionRepository
	authz    AuthorizationClient
	vault    VaultAuthorizer
	audit    AuditEmitter
	accounts AccountLookup
	// proxy is a single client because MVP supports exactly one proxy
	// family (SSH, doc 04 §2). v1.0 will need a registry keyed by
	// proxyServiceID once ProxySelector resolves to more than one value —
	// not a concern to solve before it exists.
	proxy   ProxyClient
	proxies ProxySelector

	// breakGlassMaxMinutes is both the switch and the limit of break-glass
	// (ADR-0009): zero — the default — means the platform does not grant it at all.
	breakGlassMaxMinutes int

	// breakGlassWithoutApproval is the weak mode (ADR-0011). Its zero value is the
	// strict one: a service wired by hand and never told anything about approval
	// asks for a second person rather than granting break-glass to one.
	breakGlassWithoutApproval bool
	approvalWindow            time.Duration

	// now is the clock: injectable so that the deadline of a pending request and
	// the start of an approved session can be tested without waiting.
	now func() time.Time
}

// BreakGlassResourcePrefix prefixes the RBAC resource that governs break-glass:
// "breakglass:account:{accountId}". A distinct resource, not a distinct action,
// because the Authorization Service matches policies on role and resource only.
// Having session:create on an account, or administering policies, grants nothing
// here: a policy on this resource has to exist, and be written for the purpose.
const BreakGlassResourcePrefix = "breakglass:account:"

// BreakGlassApproveResourcePrefix prefixes the RBAC resource that governs the
// approval of a break-glass request: "breakglass-approve:account:{accountId}"
// (ADR-0011). Its prefix differs from BreakGlassResourcePrefix on purpose: a policy
// "breakglass:*" — the requesters' — does not cover it, so being allowed to ask is
// not being allowed to approve.
const BreakGlassApproveResourcePrefix = "breakglass-approve:account:"

// DefaultBreakGlassApprovalWindow is how long a break-glass request waits for a
// decision when the platform says nothing: long enough for an on-call to be
// reached, short enough that a forgotten request does not linger as an open offer.
const DefaultBreakGlassApprovalWindow = 15 * time.Minute

// MinBreakGlassJustification is a floor against an accidental blank or a lone
// punctuation mark, not a judgement of quality: the justification is for the human
// who reviews the session afterwards.
const MinBreakGlassJustification = 10

// WithBreakGlass enables break-glass sessions of at most maxMinutes minutes.
// Zero or negative leaves it disabled.
func (s *SessionBrokerService) WithBreakGlass(maxMinutes int) *SessionBrokerService {
	if maxMinutes < 0 {
		maxMinutes = 0
	}
	s.breakGlassMaxMinutes = maxMinutes
	return s
}

// WithoutBreakGlassApproval is the weak mode of ADR-0011: a break-glass request that
// passes ADR-0009's locks is granted at once, as it was before the double validation
// existed. It has to be asked for by name, and the Broker announces it at start-up.
func (s *SessionBrokerService) WithoutBreakGlassApproval() *SessionBrokerService {
	s.breakGlassWithoutApproval = true
	return s
}

// WithBreakGlassApprovalWindow sets how long a request waits for its decision.
// Zero or negative keeps DefaultBreakGlassApprovalWindow.
func (s *SessionBrokerService) WithBreakGlassApprovalWindow(d time.Duration) *SessionBrokerService {
	if d > 0 {
		s.approvalWindow = d
	}
	return s
}

// WithClock replaces the clock; for tests.
func (s *SessionBrokerService) WithClock(now func() time.Time) *SessionBrokerService {
	s.now = now
	return s
}

func (s *SessionBrokerService) clock() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func (s *SessionBrokerService) approvalRequired() bool { return !s.breakGlassWithoutApproval }

func (s *SessionBrokerService) window() time.Duration {
	if s.approvalWindow > 0 {
		return s.approvalWindow
	}
	return DefaultBreakGlassApprovalWindow
}

func NewSessionBrokerService(sessions domain.SessionRepository, authz AuthorizationClient, vault VaultAuthorizer, audit AuditEmitter, accounts AccountLookup, proxy ProxyClient) *SessionBrokerService {
	return &SessionBrokerService{sessions: sessions, authz: authz, vault: vault, audit: audit, accounts: accounts, proxy: proxy}
}

// CreateSession implements SessionOrchestration.CreateSession. In MVP
// scope, a request that passes CheckAccess is granted immediately — no
// Workflow/Approval Engine exists yet (doc 04 §2).
//
// Audit emission is fail-closed (Guide HA §1: "fail-closed sur tout ce qui
// touche... à l'audit"): if the audit event cannot be recorded, the
// session is not left active — an unauditable grant is not a valid grant.
func (s *SessionBrokerService) CreateSession(ctx context.Context, requestedBy string, actorRoles []string, privilegedAccountID, protocol, justification string, durationMinutes int) (*domain.Session, error) {
	return s.createSession(ctx, requestedBy, actorRoles, privilegedAccountID, protocol, justification, durationMinutes, false)
}

// CreateBreakGlassSession is CreateSession for an emergency (ADR-0009): the
// session, if granted, may run while the Command Recorder is down. It needs
// everything CreateSession needs, and on top of that a justification, a duration
// within the platform's limit, and a RBAC policy on breakglass:account:{id} — each
// refusal is audited as session.breakglass_requested, success=false.
func (s *SessionBrokerService) CreateBreakGlassSession(ctx context.Context, requestedBy string, actorRoles []string, privilegedAccountID, protocol, justification string, durationMinutes int) (*domain.Session, error) {
	return s.createSession(ctx, requestedBy, actorRoles, privilegedAccountID, protocol, justification, durationMinutes, true)
}

// authorizeBreakGlass says why a break-glass request is refused, or nil. The
// cheap, local conditions come first; the Authorization Service is asked last.
func (s *SessionBrokerService) authorizeBreakGlass(ctx context.Context, actorRoles []string, accountID, justification string, durationMinutes int) error {
	if s.breakGlassMaxMinutes <= 0 {
		return fmt.Errorf("break-glass is not enabled on this platform")
	}
	if utf8.RuneCountInString(strings.TrimSpace(justification)) < MinBreakGlassJustification {
		return fmt.Errorf("a justification of at least %d characters is required", MinBreakGlassJustification)
	}
	if durationMinutes < 1 || durationMinutes > s.breakGlassMaxMinutes {
		return fmt.Errorf("break-glass sessions last between 1 and %d minutes", s.breakGlassMaxMinutes)
	}
	allowed, reason, err := s.authz.CheckAccess(ctx, actorRoles, BreakGlassResourcePrefix+accountID, "session:breakglass")
	if err != nil {
		// Fail closed: a waiver nobody could authorise is not granted.
		return fmt.Errorf("the Authorization Service could not be asked: %w", err)
	}
	if !allowed {
		return fmt.Errorf("no break-glass policy allows this: %s", reason)
	}
	return nil
}

func (s *SessionBrokerService) createSession(ctx context.Context, requestedBy string, actorRoles []string, privilegedAccountID, protocol, justification string, durationMinutes int, breakGlass bool) (*domain.Session, error) {
	resource := "vault:account:" + privilegedAccountID
	allowed, reason, err := s.authz.CheckAccess(ctx, actorRoles, resource, "session:create")
	if err != nil {
		return nil, fmt.Errorf("checking access: %w", err)
	}

	now := s.clock()
	sess := &domain.Session{
		ID: randomID("session"), Protocol: protocol, RequestedBy: requestedBy,
		PrivilegedAccountID: privilegedAccountID, Justification: justification, BreakGlass: breakGlass,
		CreatedAt: now, DurationMinutes: durationMinutes,
		ExpiresAt: now.Add(time.Duration(durationMinutes) * time.Minute),
	}

	if !allowed {
		sess.Status = domain.StatusDenied
		_ = s.sessions.Save(ctx, sess) // a denied attempt is still recorded — Full Auditability, doc 00 §2
		_ = s.audit.EmitEvent(ctx, requestedBy, "session.create", "session", sess.ID, false)
		return nil, fmt.Errorf("access denied: %s", reason)
	}

	if breakGlass {
		// A refused waiver is a denied session, and an audited one. It is recorded
		// under its own action so a reviewer can list every break-glass attempt,
		// granted or not, without sifting ordinary session.create events.
		if err := s.authorizeBreakGlass(ctx, actorRoles, privilegedAccountID, justification, durationMinutes); err != nil {
			sess.Status = domain.StatusDenied
			_ = s.sessions.Save(ctx, sess)
			_ = s.audit.EmitEvent(ctx, requestedBy, "session.breakglass_requested", "session", sess.ID, false)
			return nil, fmt.Errorf("break-glass refused: %w", err)
		}
		// Fail-closed like the grant itself: an emergency access that cannot be
		// audited is not granted.
		if err := s.audit.EmitEvent(ctx, requestedBy, "session.breakglass_requested", "session", sess.ID, true); err != nil {
			sess.Status = domain.StatusDenied
			_ = s.sessions.Save(ctx, sess)
			return nil, fmt.Errorf("cannot grant break-glass: audit emission failed (fail-closed, Guide HA §1): %w", err)
		}
		if s.approvalRequired() {
			// Not granted: waiting for a second person (ADR-0011). Nothing is
			// audited as session.create, because nothing has been created that
			// anyone could connect to; the approval is what grants.
			sess.Status = domain.StatusPendingApproval
			sess.ExpiresAt = now.Add(s.window()) // the deadline for a decision
			if err := s.sessions.Save(ctx, sess); err != nil {
				return nil, fmt.Errorf("saving break-glass request: %w", err)
			}
			return sess, nil
		}
	}

	sess.Status = domain.StatusActive
	if err := s.audit.EmitEvent(ctx, requestedBy, "session.create", "session", sess.ID, true); err != nil {
		sess.Status = domain.StatusDenied
		_ = s.sessions.Save(ctx, sess)
		return nil, fmt.Errorf("cannot grant session: audit emission failed (fail-closed, Guide HA §1): %w", err)
	}
	if err := s.sessions.Save(ctx, sess); err != nil {
		return nil, fmt.Errorf("saving session: %w", err)
	}
	return sess, nil
}

// GetSession implements SessionOrchestration.GetSession. The returned
// status reflects expiry lazily (domain.Session.EffectiveStatus) without
// mutating the stored record — a stand-in for the Scheduler's not-yet-
// implemented expiration sweep (doc 04 §2).
func (s *SessionBrokerService) GetSession(ctx context.Context, id string) (*domain.Session, error) {
	sess, err := s.sessions.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	reflected := *sess
	reflected.Status = sess.EffectiveStatus(s.clock())
	return &reflected, nil
}

// TerminateSession implements SessionOrchestration.TerminateSession.
func (s *SessionBrokerService) TerminateSession(ctx context.Context, id string) (*domain.Session, error) {
	sess, err := s.sessions.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if status := sess.EffectiveStatus(s.clock()); status != domain.StatusActive {
		return nil, fmt.Errorf("cannot terminate a session in status %q", status)
	}
	now := s.clock()
	sess.Status = domain.StatusTerminated
	sess.TerminatedAt = &now
	if err := s.sessions.Save(ctx, sess); err != nil {
		return nil, err
	}
	_ = s.audit.EmitEvent(ctx, sess.RequestedBy, "session.terminate", "session", sess.ID, true)
	return sess, nil
}

// Connect implements the flow behind POST /sessions/{id}/connect
// (doc 05 §2): for an active, non-expired session, it resolves the
// account's target host/username, obtains a single-use Vault scope token,
// then exchanges that token with the resolved proxy for a client-facing
// connection ticket. The scope token itself never leaves this method —
// it is constructed here and handed to ProxyClient.EstablishSession, and
// nowhere else; only the connection ticket the proxy returns is safe to
// give back to a client, and is the only thing this method returns.
//
// Only the person who requested the session may connect to it (ADR-0011, rule 7):
// callerID is the user the Gateway verified, and anyone else — the approver of a
// break-glass included — is refused before anything about the session is said.
func (s *SessionBrokerService) Connect(ctx context.Context, sessionID, callerID string) (proxyEndpoint, connectionTicket string, expiresAt time.Time, err error) {
	sess, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if callerID == "" || callerID != sess.RequestedBy {
		return "", "", time.Time{}, fmt.Errorf("%w: only the person who requested a session can connect to it", domain.ErrForbidden)
	}
	status := sess.EffectiveStatus(s.clock())
	if status != domain.StatusActive {
		return "", "", time.Time{}, fmt.Errorf("cannot connect a session in status %q", status)
	}

	proxyServiceID, err := s.proxies.Select(sess.Protocol)
	if err != nil {
		return "", "", time.Time{}, err
	}

	targetHost, targetUser, err := s.accounts.GetAccount(ctx, sess.PrivilegedAccountID)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("resolving account: %w", err)
	}

	ttl := sess.ExpiresAt.Sub(s.clock())
	if ttl <= 0 {
		return "", "", time.Time{}, fmt.Errorf("session has no time remaining")
	}

	scopeToken, _, err := s.vault.AuthorizeScope(ctx, sess.ID, sess.PrivilegedAccountID, proxyServiceID, ttl)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("authorizing vault scope: %w", err)
	}

	// The waiver is passed on only while the platform still grants break-glass:
	// switching it off takes effect at once, even for sessions already created.
	// The same goes for approval (ADR-0011, rule 7): where it is required, a
	// break-glass session nobody approved — granted before the requirement, say —
	// runs under "record or refuse" like any other.
	approved := !s.approvalRequired() || sess.DecidedBy != ""
	waiver := sess.BreakGlass && s.breakGlassMaxMinutes > 0 && approved
	proxyEndpoint, connectionTicket, err = s.proxy.EstablishSession(ctx, sess.ID, targetHost, targetUser, scopeToken, ttl, waiver)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("establishing session on proxy: %w", err)
	}

	expiresAt = s.clock().Add(ttl)
	_ = s.audit.EmitEvent(ctx, sess.RequestedBy, "session.connect", "session", sess.ID, true)
	return proxyEndpoint, connectionTicket, expiresAt, nil
}

// ApproveBreakGlass is the second person's yes (ADR-0011): the pending request
// becomes an active session, for the duration asked, starting now.
//
// decidedBy and actorRoles are the Gateway's — the verified user, never the
// request body's. The refusals that say something about the caller are audited
// (session.breakglass_approved, success=false); a request that is simply not pending
// any more is a conflict, not an event.
func (s *SessionBrokerService) ApproveBreakGlass(ctx context.Context, sessionID, decidedBy string, actorRoles []string) (*domain.Session, error) {
	return s.decide(ctx, sessionID, decidedBy, actorRoles, true)
}

// RejectBreakGlass is the second person's no: the request becomes denied and can
// never be connected to. It needs the same authority as approval — a stranger must
// not be able to kill someone's emergency request — but not a different person: to
// withdraw one's own request is not an escalation.
func (s *SessionBrokerService) RejectBreakGlass(ctx context.Context, sessionID, decidedBy string, actorRoles []string) (*domain.Session, error) {
	return s.decide(ctx, sessionID, decidedBy, actorRoles, false)
}

func (s *SessionBrokerService) decide(ctx context.Context, sessionID, decidedBy string, actorRoles []string, approve bool) (*domain.Session, error) {
	action := "session.breakglass_rejected"
	if approve {
		action = "session.breakglass_approved"
	}
	if decidedBy == "" {
		return nil, fmt.Errorf("%w: a decision needs an authenticated user", domain.ErrForbidden)
	}
	sess, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w (reading the session: %v)", domain.ErrUnavailable, err)
	}

	// A refusal that says something about the caller is on the record, with the
	// caller's name on it.
	refuse := func(reason string) error {
		_ = s.audit.EmitEvent(ctx, decidedBy, action, "session", sess.ID, false)
		return fmt.Errorf("%w: %s", domain.ErrForbidden, reason)
	}

	// Who the caller is comes first, and the state of the request only afterwards:
	// a caller with no authority is told "forbidden" whatever the request is, so the
	// answer does not describe sessions to someone who may not decide on them.
	if approve && decidedBy == sess.RequestedBy {
		return nil, refuse("a break-glass request cannot be approved by the person who made it")
	}
	allowed, reason, err := s.authz.CheckAccess(ctx, actorRoles, BreakGlassApproveResourcePrefix+sess.PrivilegedAccountID, "session:approve")
	if err != nil {
		// Fail closed: a decision nobody could authorise is not taken.
		return nil, fmt.Errorf("%w (asking the Authorization Service: %v)", domain.ErrUnavailable, err)
	}
	if !allowed {
		return nil, refuse("no approval policy allows this: " + reason)
	}

	now := s.clock()
	if !sess.BreakGlass {
		return nil, fmt.Errorf("%w: this is not a break-glass request", domain.ErrConflict)
	}
	if status := sess.EffectiveStatus(now); status != domain.StatusPendingApproval {
		return nil, fmt.Errorf("%w: the request is %s, not pending approval", domain.ErrConflict, status)
	}
	if approve {
		// Approval takes today's rules, not those of the day of the request: switching
		// break-glass off, or lowering its limit, reaches the requests already waiting.
		if s.breakGlassMaxMinutes <= 0 {
			return nil, refuse("break-glass is not enabled on this platform")
		}
		if sess.DurationMinutes < 1 || sess.DurationMinutes > s.breakGlassMaxMinutes {
			return nil, refuse(fmt.Sprintf("break-glass sessions now last at most %d minutes", s.breakGlassMaxMinutes))
		}
	}

	// The decision is audited BEFORE it takes effect, and the audit is fail-closed:
	// a grant nobody could record is not made (Guide HA §1).
	if err := s.audit.EmitEvent(ctx, decidedBy, action, "session", sess.ID, true); err != nil {
		return nil, fmt.Errorf("%w (audit: %v)", domain.ErrUnavailable, err)
	}

	decided := *sess
	decided.DecidedBy = decidedBy
	decided.DecidedAt = &now
	if approve {
		decided.Status = domain.StatusActive
		decided.ExpiresAt = now.Add(time.Duration(sess.DurationMinutes) * time.Minute)
	} else {
		decided.Status = domain.StatusDenied
	}
	swapped, err := s.sessions.SaveIfStatus(ctx, &decided, domain.StatusPendingApproval)
	if err != nil {
		return nil, fmt.Errorf("%w (saving the decision: %v)", domain.ErrUnavailable, err)
	}
	if !swapped {
		return nil, fmt.Errorf("%w: another decision was taken first", domain.ErrConflict)
	}
	return &decided, nil
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
