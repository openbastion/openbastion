// Finding the break-glass requests that wait, and being told of them (ADR-0012), proved on
// FIVE real processes — Authorization, Authentication, Audit, the Session Broker and the
// API Gateway — with a webhook that this test plays from the outside, as Slack would.
//
// The claims that matter are the negative ones: the list shows a person only what he may
// decide and says nothing to anyone else, the channel is told of what happened and nothing
// more, a refused decision is not announced, and a messaging service that is down, slow or
// hostile changes nothing about a request — nor ever reads, in the Broker's log, the URL
// that is the secret of the channel.
package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type hookDelivery struct {
	Path      string
	Raw       string
	Body      map[string]any
	Timestamp string // X-OpenBastion-Timestamp, empty when the delivery is not signed (ADR-0013)
	Signature string // X-OpenBastion-Signature
}

// hookSpy is the messaging service. It records what it is sent, and can be made to
// refuse, to hang, or to disappear.
type hookSpy struct {
	srv     *httptest.Server
	mu      sync.Mutex
	got     []hookDelivery
	mode    atomic.Int32 // 0 answers 200, 1 answers 500, 2 never answers
	release chan struct{}
}

const (
	hookOK int32 = iota
	hookRefuses
	hookHangs
)

func newHookSpy(t *testing.T) *hookSpy {
	t.Helper()
	h := &hookSpy{release: make(chan struct{})}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		h.mu.Lock()
		h.got = append(h.got, hookDelivery{Path: r.URL.Path, Raw: string(raw), Body: body,
			Timestamp: r.Header.Get("X-OpenBastion-Timestamp"), Signature: r.Header.Get("X-OpenBastion-Signature")})
		h.mu.Unlock()
		switch h.mode.Load() {
		case hookRefuses:
			http.Error(w, "channel archived", http.StatusInternalServerError)
		case hookHangs:
			select {
			case <-h.release:
			case <-r.Context().Done():
			}
		}
	}))
	t.Cleanup(func() {
		select {
		case <-h.release:
		default:
			close(h.release)
		}
		h.srv.Close()
	})
	return h
}

func (h *hookSpy) deliveries(event, sessionID string) []hookDelivery {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []hookDelivery
	for _, d := range h.got {
		if (event == "" || d.Body["event"] == event) && (sessionID == "" || d.Body["sessionId"] == sessionID) {
			out = append(out, d)
		}
	}
	return out
}

func (h *hookSpy) waitFor(t *testing.T, event, sessionID string) hookDelivery {
	t.Helper()
	var found hookDelivery
	waitUntil(t, 5*time.Second, "the webhook to receive "+event+" for "+sessionID, func() bool {
		if ds := h.deliveries(event, sessionID); len(ds) > 0 {
			found = ds[0]
			return true
		}
		return false
	})
	return found
}

// gatewayList asks the Gateway for the requests the caller may decide. query is the
// client's own query string — forged parameters included.
func gatewayList(t *testing.T, baseURL, token, query string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/sessions?"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway list: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

type pendingList struct {
	Items []struct {
		ID                  string `json:"id"`
		Status              string `json:"status"`
		RequestedBy         string `json:"requestedBy"`
		PrivilegedAccountID string `json:"privilegedAccountId"`
		Justification       string `json:"justification"`
	} `json:"items"`
	Page       int  `json:"page"`
	PageSize   int  `json:"pageSize"`
	TotalItems int  `json:"totalItems"`
	Truncated  bool `json:"truncated"`
}

func (p *pendingList) ids() []string {
	out := []string{}
	for _, it := range p.Items {
		out = append(out, it.ID)
	}
	return out
}

func TestBreakGlassDiscovery_TheApproverFindsTheRequestAndTheChannelIsToldOfIt_AcrossFiveRealProcesses(t *testing.T) {
	root := repoRoot(t)

	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-9")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-9")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-9")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-9")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-9")

	audit := startService(t, root, auditBin, "18722")
	authz := startService(t, root, authzBin, "18723")
	authn := startService(t, root, authnBin, "18727", "SKIP_DEMO_SEED=1")
	spy := startAuditSpy(t, audit.baseURL)

	hook := newHookSpy(t)
	const secretToken = "SECRETHOOK-7f3a91"
	hookURL := hook.srv.URL + "/services/T0000/" + secretToken

	// The Vault is not part of this scenario: a request is judged by the Authorization
	// Service and audited; the target account is only looked up at connect time.
	broker := startService(t, root, brokerBin, "18724",
		"AUTHORIZATION_URL=http://127.0.0.1:18723", "VAULT_URL=http://127.0.0.1:18721", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18725", "BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_NOTIFY_URL="+hookURL)
	gateway := startService(t, root, gatewayBin, "18728",
		"AUTHENTICATION_URL=http://127.0.0.1:18727", "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:18729")

	const acc1, acc2 = "acc_disc_1", "acc_disc_2"
	const reason = "SECRET-JUSTIFICATION recorder down during INC-9999"
	for _, acc := range []string{acc1, acc2} {
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+acc, "allow")
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+acc, "allow")
	}
	// Two leads, each holding the approval authority of ONE account.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead-one", "breakglass-approve:account:"+acc1, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead-two", "breakglass-approve:account:"+acc2, "allow")
	authCreateUser(t, authn.baseURL, "sre-oncall", "On-call SRE", "oncall-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "lead-bob", "Lead of account one", "bob-password-123", []string{"lead-one"})
	authCreateUser(t, authn.baseURL, "lead-dana", "Lead of account two", "dana-password-1", []string{"lead-two"})
	authCreateUser(t, authn.baseURL, "dba-alice", "Alice (DBA)", "alice-password-1", []string{"dba"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gateway.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: status %d", user, status)
		}
		return tok
	}
	oncall := login("sre-oncall", "oncall-password-1")
	bob := login("lead-bob", "bob-password-123")
	dana := login("lead-dana", "dana-password-1")
	alice := login("dba-alice", "alice-password-1")
	oncallID, bobID, danaID := userIDOf(t, oncall), userIDOf(t, bob), userIDOf(t, dana)

	request := func(t *testing.T, token, account string) string {
		t.Helper()
		status, body, sess := gatewayCreateWith(t, gateway.baseURL, token, account, true, reason, 10)
		if status != http.StatusCreated || sess.Status != "pending_approval" {
			t.Fatalf("request on %s: %d %s", account, status, body)
		}
		return sess.ID
	}
	list := func(t *testing.T, token, query string) *pendingList {
		t.Helper()
		status, body := gatewayList(t, gateway.baseURL, token, query)
		if status != http.StatusOK {
			t.Fatalf("list: %d %s", status, body)
		}
		var out pendingList
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("list is not JSON: %v: %s", err, body)
		}
		return &out
	}
	const pending = "status=pending_approval"
	settle := func() { time.Sleep(500 * time.Millisecond) } // for assertions that something did NOT happen

	var s1, s2 string

	t.Run("a request is announced to the channel — and the announcement says nothing the channel should not read", func(t *testing.T) {
		s1 = request(t, oncall, acc1)
		d := hook.waitFor(t, "breakglass.requested", s1)
		if !strings.HasSuffix(d.Path, secretToken) {
			t.Fatalf("delivered to %q, which is not the configured URL", d.Path)
		}
		if d.Body["accountId"] != acc1 || d.Body["requestedBy"] != oncallID || d.Body["durationMinutes"] != float64(10) || d.Body["decidedBy"] != nil {
			t.Fatalf("message = %s", d.Raw)
		}
		if text, _ := d.Body["text"].(string); !strings.Contains(text, s1) || !strings.Contains(text, acc1) {
			t.Fatalf("the human text does not name the request: %q", text)
		}
		if d.Timestamp != "" || d.Signature != "" {
			t.Fatalf("a Broker given no secret signed its delivery: %q %q", d.Timestamp, d.Signature)
		}
		for _, leak := range []string{"SECRET-JUSTIFICATION", "INC-9999", "justification", "Justification"} {
			if strings.Contains(d.Raw, leak) {
				t.Fatalf("the channel was told %q: %s", leak, d.Raw)
			}
		}
	})

	t.Run("the approver finds the request, with its justification, without being given its identifier", func(t *testing.T) {
		got := list(t, bob, pending)
		if len(got.Items) != 1 || got.Items[0].ID != s1 || got.TotalItems != 1 || got.Page != 1 || got.PageSize != 20 || got.Truncated {
			t.Fatalf("bob's list = %+v", got)
		}
		it := got.Items[0]
		if it.Status != "pending_approval" || it.RequestedBy != oncallID || it.PrivilegedAccountID != acc1 || it.Justification != reason {
			t.Fatalf("the request in the list is not whole: %+v", it)
		}
	})

	t.Run("each person sees what he may decide, and the others learn nothing — not even that requests exist", func(t *testing.T) {
		s2 = request(t, oncall, acc2)
		hook.waitFor(t, "breakglass.requested", s2)

		if got := list(t, bob, pending); fmt.Sprint(got.ids()) != fmt.Sprint([]string{s1}) {
			t.Fatalf("bob (authority on account one) sees %v, want only %s", got.ids(), s1)
		}
		if got := list(t, dana, pending); fmt.Sprint(got.ids()) != fmt.Sprint([]string{s2}) {
			t.Fatalf("dana (authority on account two) sees %v, want only %s", got.ids(), s2)
		}

		// The author, and a DBA with no approval policy, get the same empty answer, byte for byte.
		_, own := gatewayList(t, gateway.baseURL, oncall, pending)
		_, stranger := gatewayList(t, gateway.baseURL, alice, pending)
		const empty = `{"items":[],"page":1,"pageSize":20,"totalItems":0}`
		if strings.TrimSpace(own) != empty || strings.TrimSpace(stranger) != empty {
			t.Fatalf("the author gets %q and a stranger %q; both must get %q", own, stranger, empty)
		}
	})

	t.Run("a client cannot list as somebody else, nor with roles it does not hold", func(t *testing.T) {
		forged := pending + fmt.Sprintf("&callerId=%s&actorRoles=lead-one,lead-two&requestedBy=%s", bobID, bobID)
		if got := list(t, alice, forged); len(got.Items) != 0 {
			t.Fatalf("a forged query listed %v for a DBA", got.ids())
		}
		if got := list(t, oncall, forged); len(got.Items) != 0 {
			t.Fatalf("a forged query listed %v for the requester", got.ids())
		}
		// And the control: the same forged parameters change nothing for the person who may see.
		if got := list(t, bob, pending+"&callerId="+oncallID+"&actorRoles=sre"); fmt.Sprint(got.ids()) != fmt.Sprint([]string{s1}) {
			t.Fatalf("forged parameters changed what bob sees: %v", got.ids())
		}
	})

	t.Run("the edges: no token, another status, no status, other methods", func(t *testing.T) {
		if st, _ := gatewayList(t, gateway.baseURL, "", pending); st != http.StatusUnauthorized {
			t.Fatalf("no token: %d, want 401", st)
		}
		for _, q := range []string{"status=active", "status=denied", ""} {
			if st, body := gatewayList(t, gateway.baseURL, bob, q); st != http.StatusBadRequest {
				t.Fatalf("query %q: %d %s, want 400", q, st, body)
			}
		}
		req, _ := http.NewRequest(http.MethodDelete, gateway.baseURL+"/sessions?"+pending, nil)
		req.Header.Set("Authorization", "Bearer "+bob)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("DELETE /sessions: %d, want 405", resp.StatusCode)
		}
	})

	t.Run("a refused decision is not announced, a taken one is — with the name of whoever took it", func(t *testing.T) {
		// Refused: the author, and a DBA.
		if st, _ := gatewayDecide(t, gateway.baseURL, oncall, s2, "approve", `{}`); st != http.StatusForbidden {
			t.Fatalf("self-approval: %d", st)
		}
		if st, _ := gatewayDecide(t, gateway.baseURL, alice, s2, "reject", `{}`); st != http.StatusForbidden {
			t.Fatalf("a stranger's rejection: %d", st)
		}
		settle()
		if n := len(hook.deliveries("breakglass.approved", s2)) + len(hook.deliveries("breakglass.rejected", s2)); n != 0 {
			t.Fatalf("a decision that was refused was announced %d time(s)", n)
		}

		// Taken: Bob approves the first, Dana rejects the second.
		if st, body := gatewayDecide(t, gateway.baseURL, bob, s1, "approve", `{}`); st != http.StatusOK {
			t.Fatalf("approve: %d %s", st, body)
		}
		d := hook.waitFor(t, "breakglass.approved", s1)
		if d.Body["decidedBy"] != bobID || d.Body["requestedBy"] != oncallID || d.Body["accountId"] != acc1 {
			t.Fatalf("approval message = %s", d.Raw)
		}
		if st, body := gatewayDecide(t, gateway.baseURL, dana, s2, "reject", `{}`); st != http.StatusOK {
			t.Fatalf("reject: %d %s", st, body)
		}
		if d := hook.waitFor(t, "breakglass.rejected", s2); d.Body["decidedBy"] != danaID {
			t.Fatalf("rejection message = %s", d.Raw)
		}

		// Once decided, a request is no longer something to decide.
		if got := list(t, bob, pending); len(got.Items) != 0 {
			t.Fatalf("bob still sees %v after the decision", got.ids())
		}
		if got := list(t, dana, pending); len(got.Items) != 0 {
			t.Fatalf("dana still sees %v after the decision", got.ids())
		}
		// A decision is announced once, not once per attempt.
		if st, _ := gatewayDecide(t, gateway.baseURL, bob, s1, "approve", `{}`); st != http.StatusConflict {
			t.Fatalf("a second approval: %d, want 409", st)
		}
		settle()
		if n := len(hook.deliveries("breakglass.approved", s1)); n != 1 {
			t.Fatalf("the approval was announced %d times, want once", n)
		}
	})

	t.Run("a messaging service that refuses changes nothing: the request waits, is listed, and is decided", func(t *testing.T) {
		hook.mode.Store(hookRefuses)
		s3 := request(t, oncall, acc1)
		hook.waitFor(t, "breakglass.requested", s3) // it tried

		if got := list(t, bob, pending); fmt.Sprint(got.ids()) != fmt.Sprint([]string{s3}) {
			t.Fatalf("the list lacks the request when the channel is down: %v", got.ids())
		}
		if st, body := gatewayDecide(t, gateway.baseURL, bob, s3, "approve", `{}`); st != http.StatusOK {
			t.Fatalf("the approval depends on the channel: %d %s", st, body)
		}
		waitUntil(t, 5*time.Second, "the Broker to say that the channel refused", func() bool {
			return strings.Contains(broker.out.String(), "status 500")
		})
	})

	t.Run("a messaging service that never answers does not make an emergency wait", func(t *testing.T) {
		hook.mode.Store(hookHangs)
		start := time.Now()
		s4 := request(t, oncall, acc1)
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("the request took %v with a channel that never answers", took)
		}
		start = time.Now()
		if st, body := gatewayDecide(t, gateway.baseURL, bob, s4, "approve", `{}`); st != http.StatusOK {
			t.Fatalf("approve: %d %s", st, body)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("the approval took %v with a channel that never answers", took)
		}
	})

	t.Run("a messaging service that is gone does not either", func(t *testing.T) {
		close(hook.release)
		hook.srv.Close()
		s5 := request(t, oncall, acc1)
		if got := list(t, bob, pending); fmt.Sprint(got.ids()) != fmt.Sprint([]string{s5}) {
			t.Fatalf("list = %v, want %s", got.ids(), s5)
		}
		waitUntil(t, 5*time.Second, "the Broker to say that it could not deliver", func() bool {
			return strings.Contains(broker.out.String(), "not delivered")
		})
	})

	t.Run("the URL of the channel — its secret — is nowhere in the Broker's log, and the host is", func(t *testing.T) {
		logged := broker.out.String()
		for _, secret := range []string{secretToken, "/services/T0000", "T0000"} {
			if strings.Contains(logged, secret) {
				t.Fatalf("the secret URL leaked into the Broker's log (%q):\n%s", secret, logged)
			}
		}
		if !strings.Contains(logged, "break-glass notifications are sent to "+hook.srv.URL) {
			t.Fatalf("the Broker did not say where it notifies:\n%s", logged)
		}
	})

	t.Run("the audit chain is intact after all of it", func(t *testing.T) {
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatalf("verify-chain: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: status %d", resp.StatusCode)
		}
	})
}

// An account identifier the platform would not have issued is not a request for a
// real account, and is not carried to the people who decide — nor to their channel.
func TestBreakGlassDiscovery_AnAccountIdentifierThatIsNotOneIsRefusedBeforeItReachesAnyone(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-9b")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-9b")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-9b")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-9b")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-9b")

	audit := startService(t, root, auditBin, "18732")
	authz := startService(t, root, authzBin, "18733")
	authn := startService(t, root, authnBin, "18737", "SKIP_DEMO_SEED=1")
	spy := startAuditSpy(t, audit.baseURL)
	hook := newHookSpy(t)
	broker := startService(t, root, brokerBin, "18734",
		"AUTHORIZATION_URL=http://127.0.0.1:18733", "VAULT_URL=http://127.0.0.1:18731", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18735", "BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_NOTIFY_URL="+hook.srv.URL+"/hook")
	gateway := startService(t, root, gatewayBin, "18738",
		"AUTHENTICATION_URL=http://127.0.0.1:18737", "SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:18739")

	// A pattern policy: the requester is allowed on EVERY account — so the policies are
	// not what stops a hostile identifier.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:*", "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:*", "allow")
	authCreateUser(t, authn.baseURL, "sre-oncall", "On-call SRE", "oncall-password-1", []string{"sre"})
	tok, st := gatewayLogin(t, gateway.baseURL, "sre-oncall", "oncall-password-1")
	if st != http.StatusOK {
		t.Fatalf("login: %d", st)
	}

	for _, hostile := range []string{"<!channel> approve now", "acc\nINJECTED", "https://evil.example/x", strings.Repeat("a", 200)} {
		status, body, _ := gatewayCreateWith(t, gateway.baseURL, tok, hostile, true, "recorder down during INC-9999", 10)
		if status != http.StatusForbidden || !strings.Contains(body, "not well-formed") {
			t.Fatalf("account %q: %d %s, want a refusal that says it is not well-formed", hostile, status, body)
		}
	}
	// The control: a well-formed identifier on the same pattern policy is a request that waits.
	status, body, sess := gatewayCreateWith(t, gateway.baseURL, tok, "acc_fine", true, "recorder down during INC-9999", 10)
	if status != http.StatusCreated || sess.Status != "pending_approval" {
		t.Fatalf("the control request: %d %s", status, body)
	}
	hook.waitFor(t, "breakglass.requested", sess.ID)
	time.Sleep(300 * time.Millisecond)
	if n := len(hook.deliveries("", "")); n != 1 {
		t.Fatalf("the channel received %d messages, want only the one for the real request: %+v", n, hook.got)
	}
}

// The webhook URL is a secret and is read strictly: a value that cannot be used stops the
// Broker, and the message that says so does not repeat it.
func TestBreakGlassNotifyConfig_TheBrokerRefusesToStartOnAnUnusableURL_WithoutRepeatingIt(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-notify-check")
	for _, bad := range []string{
		"http://hooks.example.com/services/SECRETVALUE", "ftp://hooks.example.com/SECRETVALUE",
		"https://user:SECRETVALUE@hooks.example.com/x", "not a url SECRETVALUE", "https:///SECRETVALUE",
	} {
		out := runUntilExit(t, root, bin, "PORT=18796", "BREAKGLASS_NOTIFY_URL="+bad)
		if !strings.Contains(out, "BREAKGLASS_NOTIFY_URL") {
			t.Fatalf("BREAKGLASS_NOTIFY_URL=%q: expected an error naming the variable, got:\n%s", bad, out)
		}
		if strings.Contains(out, "SECRETVALUE") {
			t.Fatalf("BREAKGLASS_NOTIFY_URL=%q: the error repeats the secret:\n%s", bad, out)
		}
	}
}

// The Broker says whether anybody will be told — where, and never with what secret.
func TestBreakGlassNotifyConfig_TheBrokerSaysWhereItNotifies_OrThatItDoesNot(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-notify-announce")

	for _, c := range []struct {
		name, port string
		env        []string
		want       []string
		notWant    []string
	}{
		{"a channel is given", "18797", []string{"BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_NOTIFY_URL=https://hooks.example.com/services/SECRETPATH?token=SECRETQUERY"},
			[]string{"notifications are sent to https://hooks.example.com ", "is a secret"}, []string{"SECRETPATH", "SECRETQUERY", "no notification channel"}},
		{"no channel, approvers have to look", "18794", []string{"BREAKGLASS_MAX_MINUTES=30"},
			[]string{"no notification channel", "GET /sessions?status=pending_approval"}, []string{"notifications are sent"}},
		{"break-glass off: nothing to say", "18793", nil,
			nil, []string{"no notification channel", "notifications are sent"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := execCommandWithEnv(bin, root, append([]string{"PORT=" + c.port}, c.env...))
			var out syncBuffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			waitUntil(t, 5*time.Second, "the Broker to be listening", func() bool {
				return strings.Contains(out.String(), "session-broker listening")
			})
			for _, w := range c.want {
				if !strings.Contains(out.String(), w) {
					t.Fatalf("the Broker did not say %q:\n%s", w, out.String())
				}
			}
			for _, nw := range c.notWant {
				if strings.Contains(out.String(), nw) {
					t.Fatalf("the Broker said %q:\n%s", nw, out.String())
				}
			}
		})
	}
}

func execCommandWithEnv(bin, root string, env []string) *exec.Cmd {
	cmd := exec.Command(bin)
	cmd.Env = append(buildEnv(root), env...)
	return cmd
}
