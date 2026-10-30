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
	"log"
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

	// RevokeSession tells the proxy that a session is ended (ADR-0018): its open
	// connections are cut, its unused tickets refused and it is never established
	// again. remaining is the time the session had left — what the proxy has to
	// remember. A nil error means the session can carry nothing any more; any other
	// answer means it may still be open, and the Broker must not say it was ended.
	// It is idempotent: asking again for a session already cut is not an error.
	RevokeSession(ctx context.Context, sessionID string, remaining time.Duration) error
}

// RevocationMargin is added to the time a session has left when the Broker tells the
// proxy to remember its revocation: a ticket issued a moment before the end of the
// session, or a clock that is a little off, must not outlive the memory.
const RevocationMargin = time.Minute

// ApprovalNotifier tells whoever should know that a break-glass request is waiting,
// or has been decided (ADR-0012). It is a courtesy, not a control: it has no return
// value because nothing may depend on it — an implementation that cannot deliver logs
// and goes on, and must not block the caller. The Broker calls it only once the thing
// being announced has really happened (the request is saved; the decision has won
// its compare-and-swap).
type ApprovalNotifier interface {
	Notify(ctx context.Context, n domain.ApprovalNotification)
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
	maxPendingPerRequester    int

	// now is the clock: injectable so that the deadline of a pending request and
	// the start of an approved session can be tested without waiting.
	now func() time.Time

	// notifier is optional (ADR-0012): nil means nobody is told, and the approvers
	// look at the list.
	notifier ApprovalNotifier

	// readRefusals bounds what the refused reads of one identity write to the audit
	// (ADR-0020). Never nil: the constructor gives the strict default.
	readRefusals *RefusalBudget
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

// SessionTerminateResourcePrefix prefixes the RBAC resource that lets somebody other
// than the requester end a session: "session-terminate:account:{accountId}"
// (ADR-0017). Its prefix differs from the others on purpose: being allowed to ask for
// access, or to approve an emergency, is not being allowed to cut somebody's session.
const SessionTerminateResourcePrefix = "session-terminate:account:"

// DefaultMaxPendingPerRequester is how many break-glass requests one requester may
// have waiting for a decision at once (ADR-0013): enough for an on-call person with a
// few incidents at the same time, few enough that one identity cannot drown the list
// and the channel the approvers read.
const DefaultMaxPendingPerRequester = 3

// DefaultBreakGlassApprovalWindow is how long a break-glass request waits for a
// decision when the platform says nothing: long enough for an on-call to be
// reached, short enough that a forgotten request does not linger as an open offer.
const DefaultBreakGlassApprovalWindow = 15 * time.Minute

// wellFormedAccountID says whether id has the shape of an identifier the platform
// issues: letters, digits and . _ : - only, starting with a letter or a digit, at most
// 128 characters.
func wellFormedAccountID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '_' || r == ':' || r == '-'):
		default:
			return false
		}
	}
	return true
}

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

// WithMaxPendingPerRequester sets how many break-glass requests one requester may
// have waiting for a decision (ADR-0013). Zero or negative keeps
// DefaultMaxPendingPerRequester: there is no way to ask for "no limit", and a Broker
// built by hand without this call is strict, like it is for the approval itself.
func (s *SessionBrokerService) WithMaxPendingPerRequester(n int) *SessionBrokerService {
	if n > 0 {
		s.maxPendingPerRequester = n
	}
	return s
}

func (s *SessionBrokerService) maxPending() int {
	if s.maxPendingPerRequester > 0 {
		return s.maxPendingPerRequester
	}
	return DefaultMaxPendingPerRequester
}

// WithApprovalNotifier sets who is told of break-glass requests and decisions
// (ADR-0012). Nil, the default, tells nobody.
func (s *SessionBrokerService) WithApprovalNotifier(n ApprovalNotifier) *SessionBrokerService {
	s.notifier = n
	return s
}

func (s *SessionBrokerService) notify(ctx context.Context, n domain.ApprovalNotification) {
	if s.notifier != nil {
		s.notifier.Notify(ctx, n)
	}
}

// WithClock replaces the clock; for tests.
func (s *SessionBrokerService) WithClock(now func() time.Time) *SessionBrokerService {
	s.now = now
	s.readRefusals.WithClock(now)
	return s
}

// WithReadRefusalAudit sets the budget of what the refused reads of one identity write to
// the audit (ADR-0020): `burst` at once, then `perMinute` a minute. Zero or negative keeps
// the default: there is no way to ask for "everything" or for "nothing", and a Broker built
// by hand without this call is strict.
func (s *SessionBrokerService) WithReadRefusalAudit(burst, perMinute int) *SessionBrokerService {
	s.readRefusals = NewRefusalBudget(burst, perMinute)
	if s.now != nil {
		s.readRefusals.WithClock(s.now)
	}
	return s
}

// ReadRefusalAudit says the budget the Broker really applies, for its start-up line.
func (s *SessionBrokerService) ReadRefusalAudit() (burst, perMinute int) {
	return s.readRefusals.Burst(), s.readRefusals.RatePerMinute()
}

func (s *SessionBrokerService) clock() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func (s *SessionBrokerService) approvalRequired() bool { return !s.breakGlassWithoutApproval }

// checkPendingQuota is the early answer to "has this requester room for another
// request waiting?" (ADR-0013). It is asked after the Authorization Service, so that
// only someone with the authority to request learns anything from it, and it only
// applies when requests wait at all. SaveIfUnderPendingLimit holds the limit itself;
// this makes the common refusal exact and audited before anything is written.
func (s *SessionBrokerService) checkPendingQuota(ctx context.Context, requestedBy string, now time.Time) error {
	if !s.approvalRequired() {
		return nil
	}
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

func (s *SessionBrokerService) tooManyPending() error {
	return fmt.Errorf("%w (at most %d per requester; one frees itself when it is decided or expires)", domain.ErrTooManyPending, s.maxPending())
}

func (s *SessionBrokerService) window() time.Duration {
	if s.approvalWindow > 0 {
		return s.approvalWindow
	}
	return DefaultBreakGlassApprovalWindow
}

func NewSessionBrokerService(sessions domain.SessionRepository, authz AuthorizationClient, vault VaultAuthorizer, audit AuditEmitter, accounts AccountLookup, proxy ProxyClient) *SessionBrokerService {
	return &SessionBrokerService{sessions: sessions, authz: authz, vault: vault, audit: audit, accounts: accounts, proxy: proxy,
		readRefusals: NewRefusalBudget(0, 0)}
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
	// The account identifier is the requester's own input, and it ends up in what
	// approvers read — in the list, and in a chat channel (ADR-0012). A real
	// identifier is a plain word; anything else is not a request for a real account.
	if !wellFormedAccountID(accountID) {
		return fmt.Errorf("the account identifier is not well-formed")
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
		refusal := s.authorizeBreakGlass(ctx, actorRoles, privilegedAccountID, justification, durationMinutes)
		if refusal == nil {
			refusal = s.checkPendingQuota(ctx, requestedBy, now)
		}
		if err := refusal; err != nil {
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
			saved, err := s.sessions.SaveIfUnderPendingLimit(ctx, sess, s.maxPending(), now)
			if err != nil {
				return nil, fmt.Errorf("saving break-glass request: %w", err)
			}
			if !saved {
				// The count said there was room, and another request of the same
				// requester took it first (ADR-0013). Refused like any other: the
				// event above said "requested"; this one, for the same session,
				// says it was not, and the last one decides.
				sess.Status = domain.StatusDenied
				_ = s.sessions.Save(ctx, sess)
				_ = s.audit.EmitEvent(ctx, requestedBy, "session.breakglass_requested", "session", sess.ID, false)
				return nil, fmt.Errorf("break-glass refused: %w", s.tooManyPending())
			}
			// Told only now that the request exists to be decided (ADR-0012).
			s.notify(ctx, domain.ApprovalNotification{
				Event: domain.NotifyBreakGlassRequested, SessionID: sess.ID, AccountID: sess.PrivilegedAccountID,
				RequestedBy: sess.RequestedBy, DurationMinutes: sess.DurationMinutes, ExpiresAt: sess.ExpiresAt, At: now,
			})
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

// SessionReadResourcePrefix is the Authorization Service resource a policy names to let
// somebody READ the sessions of an account (ADR-0019): session-read:account:{accountId}.
// It is distinct from vault:, breakglass:, breakglass-approve: and session-terminate: —
// being allowed to open, approve or end a session is not being allowed to read the
// justification and the requester of somebody else's.
const SessionReadResourcePrefix = "session-read:account:"

// GetSession implements SessionOrchestration.GetSession (ADR-0019). The returned
// status reflects expiry lazily (domain.Session.EffectiveStatus) without
// mutating the stored record — a stand-in for the Scheduler's not-yet-
// implemented expiration sweep (doc 04 §2).
//
// callerID and actorRoles are the Gateway's — the verified user, never the request's.
// A session is read by its requester, always; by the person who decided it, which is the
// record of their own decision; and by somebody holding a policy on
// session-read:account:{privilegedAccountId}, refused by default. Anybody else is refused.
// The order is the session (ErrNotFound), then the caller (ErrForbidden): a caller with no
// right learns nothing of the session, and the refusal does not name the account, the
// requester or anything else in the record.
//
// Reading changes nothing in the session store, and what it writes to the audit depends on
// what it did. A read by the requester or by the person who decided the session writes
// nothing: they are given nothing they did not have. A read served on the strength of a
// policy is an event, written BEFORE it is served, and not served without it (ADR-0021). A
// refusal is an event too, but best effort and within the caller's own budget (ADR-0020):
// it discloses nothing, so a refusal that could not be recorded is still the same refusal.
func (s *SessionBrokerService) GetSession(ctx context.Context, id, callerID string, actorRoles []string) (*domain.Session, error) {
	if callerID == "" {
		return nil, fmt.Errorf("%w: reading a session needs an authenticated user", domain.ErrForbidden)
	}
	sess, err := s.sessions.Get(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w (reading the session: %v)", domain.ErrUnavailable, err)
	}
	if callerID != sess.RequestedBy && (sess.DecidedBy == "" || callerID != sess.DecidedBy) {
		allowed, _, err := s.authz.CheckAccess(ctx, actorRoles, SessionReadResourcePrefix+sess.PrivilegedAccountID, "session:read")
		if err != nil {
			// Fail closed: a read nobody could authorise is not served.
			return nil, fmt.Errorf("%w (asking the Authorization Service: %v)", domain.ErrUnavailable, err)
		}
		if !allowed {
			// The refusal is on the record (ADR-0020), within the caller's budget, and it is
			// the same refusal whatever the budget says.
			s.auditRefusedRead(ctx, callerID, sess.ID)
			// No reason from the Authorization Service: it names the resource, and the resource
			// carries the account of a session this caller may not know exists.
			return nil, fmt.Errorf("%w: only the requester of a session, the person who decided it, or somebody with a policy to read sessions on this account, can read it", domain.ErrForbidden)
		}
		// A read served on the strength of a policy is on the record BEFORE it is served
		// (ADR-0021): serving it is what discloses the requester, the account and the
		// justification of the session, so a read that could not be recorded is not served —
		// not a refusal, a dependency that is unavailable. The requester and the person who
		// decided the session do not come through here: they are not given anything new.
		if err := s.audit.EmitEvent(ctx, callerID, "session.read", "session", sess.ID, true); err != nil {
			return nil, fmt.Errorf("%w (recording the read: %v)", domain.ErrUnavailable, err)
		}
	}
	reflected := *sess
	reflected.Status = sess.EffectiveStatus(s.clock())
	return &reflected, nil
}

// auditRefusedRead writes the refusal of a read to the audit, under the name of the one who
// asked — the verified identity the Gateway named, never the requester of the session —
// when that identity's budget allows it (ADR-0020). It is best effort, like the refusals of
// ADR-0017: there is nothing for an audit that is down to prevent, the read is refused
// anyway; the failure is in the Broker's log, which the caller is not told.
func (s *SessionBrokerService) auditRefusedRead(ctx context.Context, callerID, sessionID string) {
	write, firstUnwritten := s.readRefusals.Take(callerID)
	if !write {
		if firstUnwritten {
			log.Printf("session-broker: refused reads by user %s are no longer written to the audit one by one (budget spent)", callerID)
		}
		return
	}
	if err := s.audit.EmitEvent(ctx, callerID, "session.read", "session", sessionID, false); err != nil {
		log.Printf("session-broker: the refusal of a read of %s by user %s could not be audited: %v", sessionID, callerID, err)
	}
}

// TerminateSession implements SessionOrchestration.TerminateSession (ADR-0017).
//
// callerID and actorRoles are the Gateway's — the verified user, never the request
// body's. A session is ended by its requester, always, or by somebody holding a policy
// on session-terminate:account:{accountId}; anybody else is refused, and the refusal is
// audited under the caller's own name. The order is the session, then the caller, then
// the state: a caller with no authority is told "forbidden" whatever the state is.
//
// The requester is never made to ask the Authorization Service: ending one's own access
// does not depend on a remote service. The success event is emitted after the change, at
// best, as it always was: this action reduces access, and refusing to reduce it because
// the audit is down would do more harm than a missing event (the opposite of a grant,
// ADR-0011).
func (s *SessionBrokerService) TerminateSession(ctx context.Context, id, callerID string, actorRoles []string) (*domain.Session, error) {
	if callerID == "" {
		return nil, fmt.Errorf("%w: ending a session needs an authenticated user", domain.ErrForbidden)
	}
	sess, err := s.sessions.Get(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w (reading the session: %v)", domain.ErrUnavailable, err)
	}
	if callerID != sess.RequestedBy {
		allowed, reason, err := s.authz.CheckAccess(ctx, actorRoles, SessionTerminateResourcePrefix+sess.PrivilegedAccountID, "session:terminate")
		if err != nil {
			// Fail closed: a termination nobody could authorise is not made.
			return nil, fmt.Errorf("%w (asking the Authorization Service: %v)", domain.ErrUnavailable, err)
		}
		if !allowed {
			_ = s.audit.EmitEvent(ctx, callerID, "session.terminate", "session", sess.ID, false)
			return nil, fmt.Errorf("%w: only the requester of a session, or somebody with a policy to terminate on this account, can end it: %s", domain.ErrForbidden, reason)
		}
	}
	if status := sess.EffectiveStatus(s.clock()); status != domain.StatusActive {
		return nil, fmt.Errorf("%w: cannot terminate a session in status %q", domain.ErrConflict, status)
	}
	// Ending a session is cutting it: the proxy is told BEFORE the record changes
	// (ADR-0018). If it cannot be told, nothing is ended and the caller is told so — a
	// session the Broker calls terminated while a connection is still open is the
	// lie this order exists to prevent. If it is told and the record then fails to
	// change, the session is cut but still marked active: the safe direction, and the
	// same call, which is idempotent, finishes it.
	now := s.clock()
	if err := s.proxy.RevokeSession(ctx, sess.ID, sess.ExpiresAt.Sub(now)+RevocationMargin); err != nil {
		// The attempt is on the record, under the caller's name: it did not end the session.
		_ = s.audit.EmitEvent(ctx, callerID, "session.terminate", "session", sess.ID, false)
		return nil, fmt.Errorf("%w (revoking at the proxy: %v)", domain.ErrUnavailable, err)
	}
	now = s.clock()
	ended := *sess
	ended.Status = domain.StatusTerminated
	ended.TerminatedAt = &now
	// A compare-and-swap, as for a decision: of two people who end the same session at
	// once, one wins and is the one the audit names; the other is told it is already over.
	swapped, err := s.sessions.SaveIfStatus(ctx, &ended, domain.StatusActive)
	if err != nil {
		return nil, fmt.Errorf("%w (saving the termination: %v)", domain.ErrUnavailable, err)
	}
	if !swapped {
		return nil, fmt.Errorf("%w: the session was changed first", domain.ErrConflict)
	}
	_ = s.audit.EmitEvent(ctx, callerID, "session.terminate", "session", ended.ID, true)
	return &ended, nil
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
	// Told only of the decision that was taken: not of one that was refused, and not
	// of one that lost the race (ADR-0012).
	event := domain.NotifyBreakGlassRejected
	if approve {
		event = domain.NotifyBreakGlassApproved
	}
	s.notify(ctx, domain.ApprovalNotification{
		Event: event, SessionID: decided.ID, AccountID: decided.PrivilegedAccountID,
		RequestedBy: decided.RequestedBy, DecidedBy: decidedBy,
		DurationMinutes: decided.DurationMinutes, ExpiresAt: decided.ExpiresAt, At: now,
	})
	return &decided, nil
}

// MaxPendingScanned bounds how many pending requests one listing reads (ADR-0012):
// each distinct account among them costs a question to the Authorization Service.
const MaxPendingScanned = 100

// The page sizes of a listing, as for GET /vault/accounts.
const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// ClampPage returns the page and size a listing actually serves: page at least 1, a
// size in [1, 100] or else the default of 20.
func ClampPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > maxPageSize {
		pageSize = defaultPageSize
	}
	return page, pageSize
}

// ListPendingApprovals is what a person who may approve break-glass requests sees
// of them (ADR-0012): the requests that ApproveBreakGlass would not refuse for a
// reason that is the caller's or today's rules' — still pending, not the caller's
// own, on an account whose approval policy the caller's roles hold, with the
// platform still granting break-glass for that long. Whoever holds no authority sees
// an empty list, not a refusal: the answer does not say whether requests exist.
//
// callerID and actorRoles are the Gateway's. The Authorization Service is asked once
// per distinct account; if it cannot answer, nothing is returned — a list that
// silently lacks a request is worse than none. truncated says the store held more
// pending requests than MaxPendingScanned.
func (s *SessionBrokerService) ListPendingApprovals(ctx context.Context, callerID string, actorRoles []string, page, pageSize int) (items []*domain.Session, totalItems int, truncated bool, err error) {
	if callerID == "" {
		return nil, 0, false, fmt.Errorf("%w: a listing needs an authenticated user", domain.ErrForbidden)
	}
	page, pageSize = ClampPage(page, pageSize)
	items = []*domain.Session{}
	if s.breakGlassMaxMinutes <= 0 {
		return items, 0, false, nil // nothing can be approved while the platform grants nothing
	}

	pending, more, err := s.sessions.ListPending(ctx, s.clock(), MaxPendingScanned)
	if err != nil {
		return nil, 0, false, fmt.Errorf("%w (listing pending requests: %v)", domain.ErrUnavailable, err)
	}

	authority := map[string]bool{} // per account: the answer of the Authorization Service
	var visible []*domain.Session
	for _, sess := range pending {
		if sess.RequestedBy == callerID || !sess.BreakGlass {
			continue
		}
		if sess.DurationMinutes < 1 || sess.DurationMinutes > s.breakGlassMaxMinutes {
			continue
		}
		allowed, known := authority[sess.PrivilegedAccountID]
		if !known {
			allowed, _, err = s.authz.CheckAccess(ctx, actorRoles, BreakGlassApproveResourcePrefix+sess.PrivilegedAccountID, "session:approve")
			if err != nil {
				return nil, 0, false, fmt.Errorf("%w (asking the Authorization Service: %v)", domain.ErrUnavailable, err)
			}
			authority[sess.PrivilegedAccountID] = allowed
		}
		if allowed {
			visible = append(visible, sess)
		}
	}

	totalItems = len(visible)
	start := (page - 1) * pageSize
	if start >= len(visible) {
		return items, totalItems, more, nil
	}
	end := start + pageSize
	if end > len(visible) {
		end = len(visible)
	}
	return visible[start:end], totalItems, more, nil
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
