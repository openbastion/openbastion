package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

type fakeAuthz struct {
	allowed bool
	reason  string
	calls   int

	// Per resource, when set: a decision that overrides allowed, or an error.
	byResource map[string]bool
	errFor     map[string]error
	asked      []string // "action resource", in order
}

func (f *fakeAuthz) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	f.calls++
	f.asked = append(f.asked, action+" "+resource)
	if err, ok := f.errFor[resource]; ok {
		return true, "", err // an error with a "yes": the caller must not take the yes
	}
	if v, ok := f.byResource[resource]; ok {
		return v, f.reason, nil
	}
	return f.allowed, f.reason, nil
}

type fakeVaultAuthorizer struct {
	calls        int
	lastProxyID  string
	scopeToken   string
	authorizeErr error
}

func (f *fakeVaultAuthorizer) AuthorizeScope(ctx context.Context, sessionID, accountID, proxyServiceID string, ttl time.Duration) (string, time.Time, error) {
	f.calls++
	f.lastProxyID = proxyServiceID
	if f.authorizeErr != nil {
		return "", time.Time{}, f.authorizeErr
	}
	if f.scopeToken == "" {
		f.scopeToken = "scope-token-fake"
	}
	return f.scopeToken, time.Now().UTC().Add(ttl), nil
}

type fakeAudit struct {
	events  []string
	failing bool
}

func (f *fakeAudit) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	if f.failing {
		return errors.New("audit unreachable")
	}
	f.events = append(f.events, action)
	return nil
}

func (f *fakeAudit) EmitEventWithDetails(ctx context.Context, actorID, action, resourceType, resourceID string, details map[string]string, success bool) error {
	return f.EmitEvent(ctx, actorID, action, resourceType, resourceID, success)
}

type fakeAccountLookup struct {
	targetHost string
	targetUser string
	err        error
	checkErr   error // what CheckAccount answers (ADR-0043); nil: the account exists, pinned

	// approvalRequired: the account requires another person's approval (ADR-0067).
	approvalRequired bool
	protocol         string
}

func (f *fakeAccountLookup) CheckAccount(context.Context, string) (bool, string, error) {
	protocol := f.protocol
	if protocol == "" {
		protocol = "ssh"
	}
	return f.approvalRequired, protocol, f.checkErr
}

func (f *fakeAccountLookup) GetAccount(ctx context.Context, accountID string) (string, string, error) {
	if f.err != nil {
		return "", "", f.err
	}
	host, user := f.targetHost, f.targetUser
	if host == "" {
		host = "10.0.0.9:22"
	}
	if user == "" {
		user = "root"
	}
	return host, user, nil
}

type fakeProxyClient struct {
	calls            int
	lastScopeToken   string
	lastTargetHost   string
	lastTargetUser   string
	lastBreakGlass   bool
	lastClipboard    domain.ClipboardRights
	connectionTicket string
	proxyEndpoint    string
	establishErr     error

	// revoke records what the Broker told the proxy about ended sessions (ADR-0018).
	revokeCalls     int
	revokedSessions []string
	revokedFor      []time.Duration
	revokeErr       error
	onRevoke        func(sessionID string) // runs inside the call, before it answers
}

func (f *fakeProxyClient) RevokeSession(ctx context.Context, protocol, sessionID string, remaining time.Duration) error {
	if f.onRevoke != nil {
		f.onRevoke(sessionID)
	}
	f.revokeCalls++
	f.revokedSessions = append(f.revokedSessions, sessionID)
	f.revokedFor = append(f.revokedFor, remaining)
	return f.revokeErr
}

func (f *fakeProxyClient) EstablishSession(ctx context.Context, sessionID, protocol, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool, clipboard domain.ClipboardRights) (string, string, error) {
	f.calls++
	f.lastClipboard = clipboard
	f.lastBreakGlass = breakGlass
	f.lastScopeToken = scopeToken
	f.lastTargetHost = targetHost
	f.lastTargetUser = targetUser
	if f.establishErr != nil {
		return "", "", f.establishErr
	}
	ticket := f.connectionTicket
	if ticket == "" {
		ticket = "connection-ticket-fake"
	}
	endpoint := f.proxyEndpoint
	if endpoint == "" {
		endpoint = "127.0.0.1:2222"
	}
	return endpoint, ticket, nil
}

func newTestBroker(authz *fakeAuthz, vault *fakeVaultAuthorizer, audit *fakeAudit, accounts *fakeAccountLookup, proxy *fakeProxyClient) *application.SessionBrokerService {
	store := infrastructure.NewInMemoryStore()
	return application.NewSessionBrokerService(store, authz, vault, audit, accounts, proxy)
}

func newDefaultTestBroker(authz *fakeAuthz, vault *fakeVaultAuthorizer, audit *fakeAudit) *application.SessionBrokerService {
	return newTestBroker(authz, vault, audit, &fakeAccountLookup{}, &fakeProxyClient{})
}

func TestCreateSession_DeniedWhenAuthorizationRefuses(t *testing.T) {
	authz := &fakeAuthz{allowed: false, reason: "no policy matches"}
	audit := &fakeAudit{}
	broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)

	_, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "investigate incident", "", 60)
	if err == nil {
		t.Fatal("expected CreateSession to fail when Authorization denies")
	}
	if len(audit.events) != 1 || audit.events[0] != "session.create" {
		t.Fatalf("expected exactly one session.create audit event (failure), got %v", audit.events)
	}
}

func TestCreateSession_GrantsImmediatelyWhenAllowed(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	audit := &fakeAudit{}
	broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)

	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "investigate incident", "", 60)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.Status != domain.StatusActive {
		t.Fatalf("expected immediate grant (MVP, no Workflow Service), got status %q", sess.Status)
	}
	if len(audit.events) != 1 || audit.events[0] != "session.create" {
		t.Fatalf("expected exactly one session.create audit event, got %v", audit.events)
	}
}

func TestCreateSession_FailClosedWhenAuditUnreachable(t *testing.T) {
	// docs/deployment/high-availability.md §1: audit is fail-closed. An unauditable grant must not
	// leave the session active.
	authz := &fakeAuthz{allowed: true}
	audit := &fakeAudit{failing: true}
	broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)

	_, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "investigate incident", "", 60)
	if err == nil {
		t.Fatal("expected CreateSession to fail closed when audit emission fails")
	}
}

func TestGetSession_ReflectsExpiryWithoutMutatingStoredStatus(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	audit := &fakeAudit{}
	broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)

	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "short-lived", "", -1) // already expired
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := broker.GetSession(context.Background(), sess.ID, "user1", nil) // its requester
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Status != domain.StatusExpired {
		t.Fatalf("expected EffectiveStatus to report expired, got %q", got.Status)
	}
}

func TestTerminateSession_EmitsAuditAndRejectsDoubleTermination(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	audit := &fakeAudit{}
	broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)

	sess, _ := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "justification", "", 60)

	if _, err := broker.TerminateSession(context.Background(), sess.ID, sess.RequestedBy, []string{"dba"}); err != nil {
		t.Fatalf("TerminateSession: %v", err)
	}
	if _, err := broker.TerminateSession(context.Background(), sess.ID, sess.RequestedBy, []string{"dba"}); err == nil {
		t.Fatal("expected terminating an already-terminated session to fail")
	}
	if len(audit.events) != 2 || audit.events[1] != "session.terminate" {
		t.Fatalf("expected [session.create, session.terminate], got %v", audit.events)
	}
}

func TestConnect_ResolvesAccountThenVaultThenProxy_ReturnsOnlyTheTicket(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	vault := &fakeVaultAuthorizer{}
	audit := &fakeAudit{}
	accounts := &fakeAccountLookup{targetHost: "10.0.4.12:22", targetUser: "root"}
	proxy := &fakeProxyClient{connectionTicket: "tix-abc", proxyEndpoint: "127.0.0.1:2222"}
	broker := newTestBroker(authz, vault, audit, accounts, proxy)

	sess, _ := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "justification", "", 60)

	proxyEndpoint, ticket, _, err := broker.Connect(context.Background(), sess.ID, sess.RequestedBy)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if ticket != "tix-abc" {
		t.Fatalf("expected the connection ticket returned by the proxy, got %q", ticket)
	}
	if proxyEndpoint != "127.0.0.1:2222" {
		t.Fatalf("expected the proxy endpoint returned by the proxy, got %q", proxyEndpoint)
	}
	if vault.calls != 1 || vault.lastProxyID != "ssh-proxy" {
		t.Fatalf("expected exactly one AuthorizeScope call scoped to ssh-proxy, got calls=%d lastProxyID=%q", vault.calls, vault.lastProxyID)
	}
	if proxy.calls != 1 || proxy.lastTargetHost != "10.0.4.12:22" || proxy.lastTargetUser != "root" {
		t.Fatalf("expected EstablishSession called once with the resolved account metadata, got calls=%d host=%q user=%q",
			proxy.calls, proxy.lastTargetHost, proxy.lastTargetUser)
	}
	if proxy.lastScopeToken != vault.scopeToken {
		t.Fatalf("expected the proxy to receive the exact scope token Vault issued, got %q want %q", proxy.lastScopeToken, vault.scopeToken)
	}
}

func TestConnect_NeverReturnsTheScopeTokenItself(t *testing.T) {
	// The whole point of splitting VaultAuthorizer and ProxyClient into
	// separate steps is that the scope token stays inside this method —
	// this test asserts that property directly, not just indirectly via
	// field names.
	authz := &fakeAuthz{allowed: true}
	vault := &fakeVaultAuthorizer{scopeToken: "super-secret-scope-token"}
	audit := &fakeAudit{}
	accounts := &fakeAccountLookup{}
	proxy := &fakeProxyClient{connectionTicket: "tix-xyz"}
	broker := newTestBroker(authz, vault, audit, accounts, proxy)

	sess, _ := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "justification", "", 60)
	_, ticket, _, err := broker.Connect(context.Background(), sess.ID, sess.RequestedBy)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if ticket == vault.scopeToken {
		t.Fatal("Connect must never return the raw Vault scope token to its caller")
	}
}

func TestConnect_RejectsTerminatedSession(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, &fakeAudit{})

	sess, _ := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "justification", "", 60)
	_, _ = broker.TerminateSession(context.Background(), sess.ID, sess.RequestedBy, []string{"dba"})

	if _, _, _, err := broker.Connect(context.Background(), sess.ID, sess.RequestedBy); err == nil {
		t.Fatal("expected Connect to reject a terminated session")
	}
}

func TestConnect_RejectsUnsupportedProtocol(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	accounts := &fakeAccountLookup{protocol: "rdp"}
	broker := newTestBroker(authz, &fakeVaultAuthorizer{}, &fakeAudit{}, accounts, &fakeProxyClient{})

	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "rdp", "justification", "", 60)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	vault, proxy := &fakeVaultAuthorizer{}, &fakeProxyClient{}
	broker = newTestBroker(authz, vault, &fakeAudit{}, accounts, proxy)
	sess, err = broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "rdp", "justification", "", 60)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// RDP off (ADR-0088, the default): refused before any Vault scope, and nothing asked of a proxy.
	if _, _, _, err := broker.Connect(context.Background(), sess.ID, sess.RequestedBy); !errors.Is(err, domain.ErrUnsupportedProtocol) {
		t.Fatalf("Connect with RDP off = %v, want ErrUnsupportedProtocol", err)
	}
	if vault.calls != 0 || proxy.calls != 0 {
		t.Fatalf("RDP off: %d Vault scope(s), %d proxy call(s) before the refusal", vault.calls, proxy.calls)
	}
}

// RDP on (ADR-0088): the session goes the way of a VNC one, a scope for the screen proxies.
func TestConnect_RDPWhenEnabled(t *testing.T) {
	vault, proxy := &fakeVaultAuthorizer{}, &fakeProxyClient{}
	broker := newTestBroker(&fakeAuthz{allowed: true}, vault, &fakeAudit{}, &fakeAccountLookup{protocol: "rdp"}, proxy).WithRDP(true)
	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "rdp", "justification", "", 60)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, _, protocol, _, err := broker.ConnectDetails(context.Background(), sess.ID, sess.RequestedBy)
	if err != nil {
		t.Fatalf("Connect with RDP on: %v", err)
	}
	if protocol != "rdp" || vault.calls != 1 || vault.lastProxyID != "rdp-vnc-proxy" || proxy.calls != 1 {
		t.Fatalf("protocol %q, %d scope(s) for %q, %d proxy call(s)", protocol, vault.calls, vault.lastProxyID, proxy.calls)
	}
}

func TestConnect_PropagatesProxyEstablishError(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	proxy := &fakeProxyClient{establishErr: errors.New("proxy unreachable")}
	broker := newTestBroker(authz, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{}, proxy)

	sess, _ := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "justification", "", 60)
	if _, _, _, err := broker.Connect(context.Background(), sess.ID, sess.RequestedBy); err == nil {
		t.Fatal("expected Connect to fail when the proxy cannot establish the session")
	}
}

func TestCreateSessionRefusesProtocolMismatchBeforeIssuingScope(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	vault := &fakeVaultAuthorizer{}
	audit := &fakeAudit{}
	accounts := &fakeAccountLookup{}
	proxy := &fakeProxyClient{}
	svc := newTestBroker(authz, vault, audit, accounts, proxy)
	_, err := svc.CreateSession(context.Background(), "operator", []string{"operator"}, "account-1", "vnc", "test", "", 30)
	if !errors.Is(err, domain.ErrProtocolMismatch) {
		t.Fatalf("CreateSession(protocol mismatch) error=%v", err)
	}
	if authz.calls != 1 || vault.calls != 0 || proxy.calls != 0 {
		t.Fatalf("protocol mismatch reached scope/proxy: authz=%d vault=%d proxy=%d", authz.calls, vault.calls, proxy.calls)
	}
}

func TestCreateSessionAllowsVNCOnlyWhenAccountProtocolMatches(t *testing.T) {
	accounts := &fakeAccountLookup{protocol: "vnc"}
	svc := newTestBroker(&fakeAuthz{allowed: true}, &fakeVaultAuthorizer{}, &fakeAudit{}, accounts, &fakeProxyClient{})
	sess, err := svc.CreateSession(context.Background(), "operator", []string{"operator"}, "vnc-account", "vnc", "test", "", 30)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Protocol != "vnc" || sess.Status != domain.StatusActive {
		t.Fatalf("session=%#v", sess)
	}
}

// A graphical session's recording cannot be waived (ADR-0069 rule 5, ADR-0071 §8): a break-glass
// request on an RDP or VNC account is refused at creation, recorded and audited, before anybody is
// asked to approve a session that could never start (ADR-0043). SSH keeps its break-glass.
func TestCreateBreakGlassSessionRefusesGraphicalProtocols(t *testing.T) {
	for _, protocol := range []string{"rdp", "vnc"} {
		t.Run(protocol, func(t *testing.T) {
			vault, audit, proxy := &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeProxyClient{}
			broker := newTestBroker(&fakeAuthz{allowed: true}, vault, audit, &fakeAccountLookup{protocol: protocol}, proxy).WithBreakGlass(60)
			sess, err := broker.CreateBreakGlassSession(context.Background(), "user1", []string{"dba"}, "acc1", protocol, "incident 42", 30)
			if !errors.Is(err, domain.ErrBreakGlassNotForScreens) || sess != nil {
				t.Fatalf("CreateBreakGlassSession(%s) = %v, %v; want ErrBreakGlassNotForScreens", protocol, sess, err)
			}
			if vault.calls != 0 || proxy.calls != 0 {
				t.Fatalf("%d Vault scope(s), %d proxy call(s) for a refused request", vault.calls, proxy.calls)
			}
			if len(audit.events) != 1 || audit.events[0] != "session.breakglass_requested" {
				t.Fatalf("audit events %v, want one refused session.breakglass_requested", audit.events)
			}
		})
	}
	// The same request on an SSH account is granted: only screens lose break-glass.
	broker := newTestBroker(&fakeAuthz{allowed: true}, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{protocol: "ssh"}, &fakeProxyClient{}).WithBreakGlass(60)
	if _, err := broker.CreateBreakGlassSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "incident 42", 30); err != nil {
		t.Fatalf("SSH break-glass: %v", err)
	}
}

// The clipboard of an RDP session (ADR-0096 §1, §4): each direction is its own right, asked of
// the Authorization Service at creation, refused unless granted, kept with the session and
// carried to the proxy at connect.
func TestCreateSession_RDPClipboardRightsPerDirection(t *testing.T) {
	to, from := application.ClipboardToTargetResourcePrefix+"acc1", application.ClipboardFromTargetResourcePrefix+"acc1"
	for name, c := range map[string]struct {
		grant map[string]bool
		want  domain.ClipboardRights
	}{
		"none":      {map[string]bool{to: false, from: false}, domain.ClipboardRights{}},
		"to only":   {map[string]bool{to: true, from: false}, domain.ClipboardRights{ToTarget: true}},
		"from only": {map[string]bool{to: false, from: true}, domain.ClipboardRights{FromTarget: true}},
		"both":      {map[string]bool{to: true, from: true}, domain.ClipboardRights{ToTarget: true, FromTarget: true}},
	} {
		t.Run(name, func(t *testing.T) {
			authz := &fakeAuthz{allowed: true, byResource: c.grant}
			proxy := &fakeProxyClient{}
			broker := newTestBroker(authz, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{protocol: "rdp"}, proxy).WithRDP(true)
			sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "rdp", "justification", "", 60)
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			if got := (domain.ClipboardRights{ToTarget: sess.ClipboardToTarget, FromTarget: sess.ClipboardFromTarget}); got != c.want {
				t.Fatalf("session rights %+v, want %+v", got, c.want)
			}
			for _, r := range []string{to, from} {
				if !contains(authz.asked, "session:clipboard "+r) {
					t.Fatalf("the Authorization Service was not asked for %q: %v", r, authz.asked)
				}
			}
			if _, _, _, _, err := broker.ConnectDetails(context.Background(), sess.ID, sess.RequestedBy); err != nil {
				t.Fatalf("Connect: %v", err)
			}
			if proxy.lastClipboard != c.want {
				t.Fatalf("the proxy received %+v, want %+v", proxy.lastClipboard, c.want)
			}
		})
	}
}

// An Authorization Service that cannot answer grants nothing, even if it says yes alongside its
// error; the session opens all the same, without the clipboard (ADR-0096 §1, fail closed).
func TestCreateSession_RDPClipboardRefusedWhenAuthorizationFails(t *testing.T) {
	for _, failing := range []string{application.ClipboardToTargetResourcePrefix + "acc1", application.ClipboardFromTargetResourcePrefix + "acc1"} {
		authz := &fakeAuthz{allowed: true, errFor: map[string]error{failing: errors.New("authz unreachable")}}
		proxy := &fakeProxyClient{}
		broker := newTestBroker(authz, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{protocol: "rdp"}, proxy).WithRDP(true)
		sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "rdp", "justification", "", 60)
		if err != nil {
			t.Fatalf("%s failing: CreateSession: %v", failing, err)
		}
		toFails := failing == application.ClipboardToTargetResourcePrefix+"acc1"
		if sess.ClipboardToTarget == toFails || sess.ClipboardFromTarget != toFails {
			t.Fatalf("%s failing: rights to=%v from=%v; the failed direction must be refused, the other granted", failing, sess.ClipboardToTarget, sess.ClipboardFromTarget)
		}
	}
}

// Only RDP has a clipboard channel (ADR-0096): an SSH or VNC session is never granted one, and the
// Authorization Service is not asked.
func TestCreateSession_NoClipboardOutsideRDP(t *testing.T) {
	for _, protocol := range []string{"ssh", "vnc"} {
		authz := &fakeAuthz{allowed: true}
		proxy := &fakeProxyClient{}
		broker := newTestBroker(authz, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{protocol: protocol}, proxy)
		sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", protocol, "justification", "", 60)
		if err != nil {
			t.Fatalf("%s: CreateSession: %v", protocol, err)
		}
		if sess.ClipboardToTarget || sess.ClipboardFromTarget {
			t.Fatalf("%s: clipboard granted: %+v", protocol, sess)
		}
		for _, a := range authz.asked {
			if strings.HasPrefix(a, "session:clipboard ") {
				t.Fatalf("%s: the clipboard was asked about: %v", protocol, authz.asked)
			}
		}
		if _, _, _, _, err := broker.ConnectDetails(context.Background(), sess.ID, sess.RequestedBy); err != nil {
			t.Fatalf("%s: Connect: %v", protocol, err)
		}
		if proxy.lastClipboard != (domain.ClipboardRights{}) {
			t.Fatalf("%s: the proxy received %+v", protocol, proxy.lastClipboard)
		}
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
