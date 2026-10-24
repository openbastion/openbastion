// The per-user budget of POST /sessions at the Gateway (ADR-0014), on real processes:
// Authorization, Authentication, Audit, the Session Broker and three API Gateways with
// different settings.
//
// The claims that matter: a user who has no right at all cannot make the Broker write more
// than the budget — each refused attempt that does reach the Broker is a row and an audit
// event, and a request refused by the budget is neither; the budget is the user's own;
// Retry-After tells the truth in real time; and the units of the limiter for authenticated
// traffic are what they say (they were not).
package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rawRequest is a request whose headers the test needs to read.
func rawRequest(t *testing.T, method, url, token, body string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(raw)
}

func TestSessionRate_AUserWithNoRightCannotMakeTheBrokerWriteMoreThanItsBudget_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-14")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-14")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-14")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-14")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-14")

	audit := startService(t, root, auditBin, "18761")
	startService(t, root, authzBin, "18762")
	authn := startService(t, root, authnBin, "18764", "SKIP_DEMO_SEED=1")
	spy := startAuditSpy(t, audit.baseURL)
	broker := startService(t, root, brokerBin, "18763",
		"AUTHORIZATION_URL=http://127.0.0.1:18762", "VAULT_URL=http://127.0.0.1:18760", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18769")
	gatewayEnv := func(extra ...string) []string {
		return append([]string{"AUTHENTICATION_URL=http://127.0.0.1:18764", "SESSION_BROKER_URL=" + broker.baseURL,
			"COMMAND_RECORDER_URL=http://127.0.0.1:18769"}, extra...)
	}
	// A: three at once, then one every ten seconds — slow enough that nothing refills during a test.
	gwA := startService(t, root, gatewayBin, "18765", gatewayEnv("SESSION_REQUEST_BURST=3", "SESSION_REQUEST_RATE_PER_MINUTE=6")...)
	// B: three at once, then one every second — fast enough to wait for it in real time.
	gwB := startService(t, root, gatewayBin, "18766", gatewayEnv("SESSION_REQUEST_BURST=3", "SESSION_REQUEST_RATE_PER_MINUTE=60")...)

	// Neither user has a policy on anything: every request they make is refused.
	authCreateUser(t, authn.baseURL, "nobody-one", "Nobody one", "nobody-one-password-1", []string{"nobody"})
	authCreateUser(t, authn.baseURL, "nobody-two", "Nobody two", "nobody-two-password-1", []string{"nobody"})
	login := func(gw, user, pw string) string {
		tok, status := gatewayLogin(t, gw, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	oneA, twoA := login(gwA.baseURL, "nobody-one", "nobody-one-password-1"), login(gwA.baseURL, "nobody-two", "nobody-two-password-1")
	const body = `{"targetAccountId":"acc_rate_1","protocol":"ssh","justification":"INC-9 recorder down","durationMinutes":10}`
	settle := func() { time.Sleep(500 * time.Millisecond) } // for assertions that something did NOT happen

	t.Run("eight attempts in a row: the budget reaches the Broker, the rest does not — and leaves no audit event", func(t *testing.T) {
		var codes []int
		var retryAfter string
		for i := 0; i < 8; i++ {
			status, h, _ := rawRequest(t, http.MethodPost, gwA.baseURL+"/sessions", oneA, body)
			codes = append(codes, status)
			if status == http.StatusTooManyRequests && retryAfter == "" {
				retryAfter = h.Get("Retry-After")
			}
		}
		if fmt.Sprint(codes) != "[403 403 403 429 429 429 429 429]" {
			t.Fatalf("eight attempts with a budget of 3 gave %v, want three refusals by the Broker and five by the budget", codes)
		}
		if n, err := strconv.Atoi(retryAfter); err != nil || n < 1 || n > 10 {
			t.Fatalf("Retry-After = %q, want a whole number of seconds between 1 and 10 (one token every 10 s)", retryAfter)
		}
		settle()
		if n := spy.anyEvent("session.create", false); n != 3 {
			t.Fatalf("%d refusals audited, want 3: a request refused by the budget must write no audit event", n)
		}
	})

	t.Run("somebody else's budget is their own, even from the same address", func(t *testing.T) {
		status, _, text := rawRequest(t, http.MethodPost, gwA.baseURL+"/sessions", twoA, body)
		if status != http.StatusForbidden || !strings.Contains(text, "access denied") {
			t.Fatalf("another user: %d %q, want the Broker's own refusal (403)", status, text)
		}
		settle()
		if n := spy.anyEvent("session.create", false); n != 4 {
			t.Fatalf("%d refusals audited, want 4", n)
		}
	})

	t.Run("what is not about creating a session is not slowed by it", func(t *testing.T) {
		status, _, text := rawRequest(t, http.MethodGet, gwA.baseURL+"/sessions?status=pending_approval", oneA, "")
		if status != http.StatusOK {
			t.Fatalf("listing for a user whose session budget is spent: %d %q, want 200", status, text)
		}
	})

	t.Run("Retry-After is the truth: waiting that long is enough", func(t *testing.T) {
		oneB := login(gwB.baseURL, "nobody-one", "nobody-one-password-1")
		var wait string
		for i := 0; i < 8 && wait == ""; i++ {
			status, h, _ := rawRequest(t, http.MethodPost, gwB.baseURL+"/sessions", oneB, body)
			if status == http.StatusTooManyRequests {
				wait = h.Get("Retry-After")
			}
		}
		n, err := strconv.Atoi(wait)
		if err != nil || n < 1 {
			t.Fatalf("eight attempts with a budget of 3 were never refused, or Retry-After = %q", wait)
		}
		if n != 1 {
			t.Fatalf("Retry-After = %d s with SESSION_REQUEST_RATE_PER_MINUTE=60, want 1: the configured rate is not the one applied", n)
		}
		time.Sleep(time.Duration(n)*time.Second + 150*time.Millisecond)
		if status, _, text := rawRequest(t, http.MethodPost, gwB.baseURL+"/sessions", oneB, body); status != http.StatusForbidden {
			t.Fatalf("after waiting the %d s that were announced: %d %q, want the Broker's 403", n, status, text)
		}
	})
}

// The limiter of authenticated traffic was a burst of 60 and then ONE request a minute under
// a comment that said sixty a minute. What a real process lets through is what pins it.
func TestSessionRate_TheLimiterOfAuthenticatedTrafficIsSixtyAMinute_NotOneAMinuteAfterTheBurst(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-14b")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-14b")
	authn := startService(t, root, authnBin, "18764", "SKIP_DEMO_SEED=1")
	gw := startService(t, root, gatewayBin, "18767", "AUTHENTICATION_URL="+authn.baseURL,
		"SESSION_BROKER_URL=http://127.0.0.1:18769", "COMMAND_RECORDER_URL=http://127.0.0.1:18769")
	authCreateUser(t, authn.baseURL, "steady", "Steady", "steady-password-123", []string{"nobody"})
	tok, status := gatewayLogin(t, gw.baseURL, "steady", "steady-password-123")
	if status != http.StatusOK {
		t.Fatalf("login: %d", status)
	}

	passed, refused := 0, 0
	var retryAfter []string
	for i := 0; i < 70; i++ {
		code, h, _ := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/s-none", tok, "")
		if code == http.StatusTooManyRequests {
			refused++
			retryAfter = append(retryAfter, h.Get("Retry-After"))
		} else {
			passed++
		}
	}
	// 60 at once, and at most a couple more that were refilled while the loop ran (a token a second).
	if passed < 60 || passed > 63 || refused != 70-passed {
		t.Fatalf("%d of 70 requests passed and %d were refused, want 60 to 63 and the rest refused", passed, refused)
	}
	for _, ra := range retryAfter {
		if ra != "1" {
			t.Fatalf("Retry-After = %q, want 1: a token comes back every second", ra)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if code, _, _ := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/s-none", tok, ""); code == http.StatusTooManyRequests {
		t.Fatal("still refused a second after the burst was spent: the refill is not a token a second")
	}
}

// ADR-0014 repaired the limiter that login shares, and kept what login has always done: a
// burst of five and then ONE attempt a minute (its comment said "5 per minute"). It is
// stricter than what was written, and it is a protection against brute force: it must not
// be relaxed to look like its comment.
func TestLoginRate_AFailedPasswordIsAFiveAttemptBurstThenOneAMinute_NotFivePerMinute(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-14d")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-14d")
	authn := startService(t, root, authnBin, "18764", "SKIP_DEMO_SEED=1")
	gw := startService(t, root, gatewayBin, "18768", "AUTHENTICATION_URL="+authn.baseURL,
		"SESSION_BROKER_URL=http://127.0.0.1:18769", "COMMAND_RECORDER_URL=http://127.0.0.1:18769")
	authCreateUser(t, authn.baseURL, "patient", "Patient", "patient-password-123", []string{"nobody"})

	var codes []int
	var waits []string
	for i := 0; i < 8; i++ {
		body := `{"username":"patient","password":"not-the-password"}`
		status, h, _ := rawRequest(t, http.MethodPost, gw.baseURL+"/auth/login", "", body)
		codes = append(codes, status)
		if status == http.StatusTooManyRequests {
			waits = append(waits, h.Get("Retry-After"))
		}
	}
	if fmt.Sprint(codes) != "[401 401 401 401 401 429 429 429]" {
		t.Fatalf("eight wrong passwords gave %v, want five that reached Authentication (401) and three that did not (429)", codes)
	}
	for _, w := range waits {
		if n, err := strconv.Atoi(w); err != nil || n < 55 || n > 60 {
			t.Fatalf("Retry-After = %q, want about a minute (55 to 60): one attempt a minute once the burst is spent", w)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if status, _, _ := rawRequest(t, http.MethodPost, gw.baseURL+"/auth/login", "", `{"username":"patient","password":"not-the-password"}`); status != http.StatusTooManyRequests {
		t.Fatalf("a second after the burst: %d, want still 429", status)
	}
}

// A limit that is wrong is found when the Gateway starts, and what it says it applies is
// what it applies.
func TestSessionRateConfig_AWrongLimitStopsTheGateway_AndWhatIsSaidAtStartIsTrue(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-14c")

	t.Run("the burst and the rate must be numbers within their bounds", func(t *testing.T) {
		for _, c := range []struct{ name, value string }{
			{"SESSION_REQUEST_BURST", "0"}, {"SESSION_REQUEST_BURST", "-1"}, {"SESSION_REQUEST_BURST", "1001"},
			{"SESSION_REQUEST_BURST", "abc"}, {"SESSION_REQUEST_BURST", "2.5"},
			{"SESSION_REQUEST_RATE_PER_MINUTE", "0"}, {"SESSION_REQUEST_RATE_PER_MINUTE", "601"},
			{"SESSION_REQUEST_RATE_PER_MINUTE", "six"}, {"SESSION_REQUEST_RATE_PER_MINUTE", "-5"},
		} {
			out := runUntilExit(t, root, bin, "PORT=18768", c.name+"="+c.value)
			if !strings.Contains(out, c.name) {
				t.Fatalf("%s=%s: expected an error naming the variable, got:\n%s", c.name, c.value, out)
			}
		}
	})

	t.Run("the Gateway says what it applies, and says it truly", func(t *testing.T) {
		for _, c := range []struct {
			name    string
			env     []string
			want    string
			notWant string
		}{
			{"the defaults", nil, "at most 10 at once per user, then 6 per minute", "at most 4"},
			{"a custom budget", []string{"SESSION_REQUEST_BURST=4", "SESSION_REQUEST_RATE_PER_MINUTE=30"}, "at most 4 at once per user, then 30 per minute", "at most 10"},
			{"the smallest", []string{"SESSION_REQUEST_BURST=1", "SESSION_REQUEST_RATE_PER_MINUTE=1"}, "at most 1 at once per user, then 1 per minute", "at most 10"},
			{"the largest", []string{"SESSION_REQUEST_BURST=1000", "SESSION_REQUEST_RATE_PER_MINUTE=600"}, "at most 1000 at once per user, then 600 per minute", "at most 10 "},
		} {
			t.Run(c.name, func(t *testing.T) {
				cmd := execCommandWithEnv(bin, root, append([]string{"PORT=18768"}, c.env...))
				var out syncBuffer
				cmd.Stdout, cmd.Stderr = &out, &out
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				waitUntil(t, 5*time.Second, "the Gateway to be listening", func() bool {
					return strings.Contains(out.String(), "api-gateway listening")
				})
				if !strings.Contains(out.String(), c.want) {
					t.Fatalf("the Gateway did not say %q:\n%s", c.want, out.String())
				}
				if strings.Contains(out.String(), c.notWant) {
					t.Fatalf("the Gateway said %q:\n%s", c.notWant, out.String())
				}
			})
		}
	})
}
