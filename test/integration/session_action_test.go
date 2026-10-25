// The per-user budget of approve, reject and connect at the Gateway (ADR-0016), on real
// processes: Authorization, Authentication, Audit, the Session Broker and three API Gateways
// with different settings.
//
// What it pins is what the ADR measured and the reason for the budget: an approval or a
// rejection that is refused writes an audit event EACH TIME (the control below counts them),
// so a user who holds a token and a session of its own could make the platform write without
// limit. With the budget, only the allowance reaches the Broker — and so only the allowance
// is written — and the rest is refused at the Gateway with a Retry-After that tells the truth.
package integration_test

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSessionAction_AUserWithASessionOfItsOwnCannotMakeTheBrokerWriteMoreThanItsBudget_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-16")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-16")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-16")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-16")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-16")

	audit := startService(t, root, auditBin, "18779")
	authz := startService(t, root, authzBin, "18780")
	authn := startService(t, root, authnBin, "18781", "SKIP_DEMO_SEED=1")
	spy := startAuditSpy(t, audit.baseURL)
	broker := startService(t, root, brokerBin, "18782",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:18786", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18787", "BREAKGLASS_MAX_MINUTES=30")
	gatewayEnv := func(extra ...string) []string {
		return append([]string{"AUTHENTICATION_URL=" + authn.baseURL, "SESSION_BROKER_URL=" + broker.baseURL,
			"COMMAND_RECORDER_URL=http://127.0.0.1:18787"}, extra...)
	}
	// Control: a budget so large that it never intervenes — what the Broker would be made to write.
	control := startService(t, root, gatewayBin, "18783", gatewayEnv("SESSION_ACTION_BURST=1000", "SESSION_ACTION_RATE_PER_MINUTE=600")...)
	// A: three at once, then one every ten seconds — slow enough that nothing refills during a test.
	gwA := startService(t, root, gatewayBin, "18784", gatewayEnv("SESSION_ACTION_BURST=3", "SESSION_ACTION_RATE_PER_MINUTE=6")...)
	// B: two at once, then one every second — fast enough to wait for it in real time.
	gwB := startService(t, root, gatewayBin, "18785", gatewayEnv("SESSION_ACTION_BURST=2", "SESSION_ACTION_RATE_PER_MINUTE=60")...)

	const acc = "acc_action_1"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+acc, "allow")
	// Nobody has the authority to approve: every decision on it is refused — and written.
	authCreateUser(t, authn.baseURL, "mallory", "Mallory", "mallory-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "eve", "Eve", "eve-password-12345", []string{"sre"})
	login := func(gw, user, pw string) string {
		tok, status := gatewayLogin(t, gw, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	malloryControl := login(control.baseURL, "mallory", "mallory-password-1")
	status, body, sess := gatewayCreateWith(t, control.baseURL, malloryControl, acc, true, "INC-16 recorder down, database saturated", 10)
	if status != http.StatusCreated || sess == nil || sess.Status != "pending_approval" {
		t.Fatalf("Mallory's break-glass request: %d %s", status, body)
	}
	id := sess.ID
	settle := func() { time.Sleep(500 * time.Millisecond) } // for assertions that something did NOT happen
	action := func(gw, token, what string) (int, http.Header, string) {
		return rawRequest(t, http.MethodPost, gw+"/sessions/"+id+"/"+what, token, "{}")
	}

	// The premise, measured: without a budget, every refused approval is an audit event.
	t.Run("control: with a budget that never intervenes, each refused approval and rejection is an audit event", func(t *testing.T) {
		approvedBefore, rejectedBefore := spy.anyEvent("session.breakglass_approved", false), spy.anyEvent("session.breakglass_rejected", false)
		for i := 0; i < 6; i++ {
			if code, _, text := action(control.baseURL, malloryControl, "approve"); code != http.StatusForbidden {
				t.Fatalf("approve %d: %d %s, want the Broker's 403", i+1, code, text)
			}
			if code, _, text := action(control.baseURL, malloryControl, "reject"); code != http.StatusForbidden {
				t.Fatalf("reject %d: %d %s, want the Broker's 403", i+1, code, text)
			}
		}
		settle()
		if n := spy.anyEvent("session.breakglass_approved", false) - approvedBefore; n != 6 {
			t.Fatalf("%d refused approvals audited out of 6, want 6: the premise of the budget is that each one is written", n)
		}
		if n := spy.anyEvent("session.breakglass_rejected", false) - rejectedBefore; n != 6 {
			t.Fatalf("%d refused rejections audited out of 6, want 6", n)
		}
	})

	malloryA := login(gwA.baseURL, "mallory", "mallory-password-1")

	t.Run("eight approvals in a row: the budget reaches the Broker, the rest does not — and leaves no audit event", func(t *testing.T) {
		before := spy.anyEvent("session.breakglass_approved", false)
		var codes []int
		var retryAfter, text429 string
		for i := 0; i < 8; i++ {
			code, h, text := action(gwA.baseURL, malloryA, "approve")
			codes = append(codes, code)
			if code == http.StatusTooManyRequests && retryAfter == "" {
				retryAfter, text429 = h.Get("Retry-After"), text
			}
		}
		if fmt.Sprint(codes) != "[403 403 403 429 429 429 429 429]" {
			t.Fatalf("eight approvals with a budget of 3 gave %v, want three refusals by the Broker and five by the budget", codes)
		}
		if n, err := strconv.Atoi(retryAfter); err != nil || n < 1 || n > 10 {
			t.Fatalf("Retry-After = %q, want a whole number of seconds between 1 and 10 (one token every 10 s)", retryAfter)
		}
		if !strings.Contains(text429, "too many session actions from this user") || !strings.Contains(text429, "at most 3 at once") {
			t.Fatalf("the refusal does not name its budget and its limit: %q", text429)
		}
		settle()
		if n := spy.anyEvent("session.breakglass_approved", false) - before; n != 3 {
			t.Fatalf("%d refused approvals audited out of 8, want 3: an action refused by the budget must write nothing", n)
		}
	})

	t.Run("the budget is one for the three: reject and connect are refused too, without reaching the Broker", func(t *testing.T) {
		rejectedBefore := spy.anyEvent("session.breakglass_rejected", false)
		if code, _, text := action(gwA.baseURL, malloryA, "reject"); code != http.StatusTooManyRequests {
			t.Fatalf("reject once the approvals spent the budget: %d %s, want 429", code, text)
		}
		if code, _, text := action(gwA.baseURL, malloryA, "connect"); code != http.StatusTooManyRequests {
			t.Fatalf("connect once the approvals spent the budget: %d %s, want 429", code, text)
		}
		settle()
		if n := spy.anyEvent("session.breakglass_rejected", false) - rejectedBefore; n != 0 {
			t.Fatalf("%d rejections reached the audit, want 0", n)
		}
	})

	t.Run("somebody else's budget is their own, from the same address — and connect is charged like the others", func(t *testing.T) {
		eve := login(gwA.baseURL, "eve", "eve-password-12345")
		var codes []int
		for i := 0; i < 4; i++ {
			// Eve is not the requester: the Broker refuses (403) before it says anything about the session.
			code, _, _ := action(gwA.baseURL, eve, "connect")
			codes = append(codes, code)
		}
		if fmt.Sprint(codes) != "[403 403 403 429]" {
			t.Fatalf("four connects by another user gave %v, want her own budget of 3 and then 429", codes)
		}
	})

	t.Run("what does not write on every call is not slowed by it", func(t *testing.T) {
		if code, _, text := rawRequest(t, http.MethodGet, gwA.baseURL+"/sessions/"+id, malloryA, ""); code != http.StatusOK {
			t.Fatalf("reading the session of a user whose action budget is spent: %d %s, want 200", code, text)
		}
		if code, _, text := rawRequest(t, http.MethodGet, gwA.baseURL+"/sessions?status=pending_approval", malloryA, ""); code == http.StatusTooManyRequests {
			t.Fatalf("listing the pending requests was refused for the action budget: %s", text)
		}
		if code, _, text := rawRequest(t, http.MethodDelete, gwA.baseURL+"/sessions/"+id, malloryA, ""); code == http.StatusTooManyRequests {
			t.Fatalf("terminating was refused for the action budget: %s", text)
		}
	})

	t.Run("Retry-After is the truth: waiting that long is enough", func(t *testing.T) {
		// A fresh request of Mallory's own, since the previous one was just terminated.
		status, body, s2 := gatewayCreateWith(t, control.baseURL, malloryControl, acc, true, "INC-16b second request", 10)
		if status != http.StatusCreated || s2 == nil {
			t.Fatalf("second request: %d %s", status, body)
		}
		malloryB := login(gwB.baseURL, "mallory", "mallory-password-1")
		do := func() (int, http.Header, string) {
			return rawRequest(t, http.MethodPost, gwB.baseURL+"/sessions/"+s2.ID+"/approve", malloryB, "{}")
		}
		for i := 0; i < 2; i++ {
			if code, _, text := do(); code != http.StatusForbidden {
				t.Fatalf("approve %d: %d %s, want the Broker's 403", i+1, code, text)
			}
		}
		code, h, _ := do()
		if code != http.StatusTooManyRequests {
			t.Fatalf("third approval with a budget of 2: %d, want 429", code)
		}
		if h.Get("Retry-After") != "1" {
			t.Fatalf("Retry-After = %q with SESSION_ACTION_RATE_PER_MINUTE=60, want 1: the configured rate is not the one applied", h.Get("Retry-After"))
		}
		time.Sleep(1150 * time.Millisecond)
		if code, _, text := do(); code != http.StatusForbidden {
			t.Fatalf("after waiting the second that was announced: %d %s, want the Broker's 403", code, text)
		}
	})
}

// A limit that is wrong is found when the Gateway starts, and what it says it applies is what
// it applies — for this budget as for the one of POST /sessions, and neither moves the other.
func TestSessionActionConfig_AWrongLimitStopsTheGateway_AndWhatIsSaidAtStartIsTrue(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-16c")

	t.Run("the burst and the rate must be numbers within their bounds", func(t *testing.T) {
		for _, c := range []struct{ name, value string }{
			{"SESSION_ACTION_BURST", "0"}, {"SESSION_ACTION_BURST", "-1"}, {"SESSION_ACTION_BURST", "1001"},
			{"SESSION_ACTION_BURST", "abc"}, {"SESSION_ACTION_BURST", "2.5"},
			{"SESSION_ACTION_RATE_PER_MINUTE", "0"}, {"SESSION_ACTION_RATE_PER_MINUTE", "601"},
			{"SESSION_ACTION_RATE_PER_MINUTE", "six"}, {"SESSION_ACTION_RATE_PER_MINUTE", "-5"},
		} {
			out := runUntilExit(t, root, bin, "PORT=18788", c.name+"="+c.value)
			if !strings.Contains(out, c.name) {
				t.Fatalf("%s=%s: expected an error naming the variable, got:\n%s", c.name, c.value, out)
			}
		}
	})

	t.Run("the Gateway says what it applies, and says it truly", func(t *testing.T) {
		const actions, requests = "approve, reject, connect: at most ", "POST /sessions: at most "
		for _, c := range []struct {
			name    string
			env     []string
			want    []string
			notWant []string
		}{
			{"the defaults", nil,
				[]string{actions + "10 at once per user, then 6 per minute", requests + "10 at once per user, then 6 per minute"}, nil},
			{"a custom budget", []string{"SESSION_ACTION_BURST=4", "SESSION_ACTION_RATE_PER_MINUTE=30"},
				[]string{actions + "4 at once per user, then 30 per minute", requests + "10 at once per user, then 6 per minute"},
				[]string{actions + "10"}},
			{"the smallest", []string{"SESSION_ACTION_BURST=1", "SESSION_ACTION_RATE_PER_MINUTE=1"},
				[]string{actions + "1 at once per user, then 1 per minute"}, []string{actions + "10"}},
			{"the largest", []string{"SESSION_ACTION_BURST=1000", "SESSION_ACTION_RATE_PER_MINUTE=600"},
				[]string{actions + "1000 at once per user, then 600 per minute"}, []string{actions + "10 "}},
			{"the budget of POST /sessions does not move this one", []string{"SESSION_REQUEST_BURST=4", "SESSION_REQUEST_RATE_PER_MINUTE=30"},
				[]string{actions + "10 at once per user, then 6 per minute", requests + "4 at once per user, then 30 per minute"},
				[]string{actions + "4"}},
		} {
			t.Run(c.name, func(t *testing.T) {
				cmd := execCommandWithEnv(bin, root, append([]string{"PORT=18788"}, c.env...))
				var out syncBuffer
				cmd.Stdout, cmd.Stderr = &out, &out
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				waitUntil(t, 5*time.Second, "the Gateway to be listening", func() bool {
					return strings.Contains(out.String(), "api-gateway listening")
				})
				for _, w := range c.want {
					if !strings.Contains(out.String(), w) {
						t.Fatalf("the Gateway did not say %q:\n%s", w, out.String())
					}
				}
				for _, w := range c.notWant {
					if strings.Contains(out.String(), w) {
						t.Fatalf("the Gateway said %q:\n%s", w, out.String())
					}
				}
			})
		}
	})
}
