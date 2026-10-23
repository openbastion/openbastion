// The quota of break-glass requests waiting per requester, and the signed webhook
// (ADR-0013), proved on FIVE real processes — Authorization, Authentication, Audit, the
// Session Broker and the API Gateway — with a webhook that this test plays from the
// outside, and verifies the way a receiver would.
//
// The claims that matter: one identity cannot hold more places than the platform gives it,
// not even by sending its requests all at once; nobody can use that to block somebody else;
// a place frees itself when a request is decided; a refusal is audited and announced to no
// one; and what the channel is sent carries a signature that only the Broker could make.
package integration_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// receiverVerifies is a receiver's check of a delivery, written from the description of
// the contract in ADR-0013 and not from the Broker's code.
func receiverVerifies(secret string, d hookDelivery, tolerance time.Duration) bool {
	ts, err := strconv.ParseInt(d.Timestamp, 10, 64)
	if err != nil {
		return false
	}
	if age := time.Since(time.Unix(ts, 0)); age < -tolerance || age > tolerance {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(d.Timestamp + "."))
	mac.Write([]byte(d.Raw))
	return hmac.Equal([]byte("v1="+hex.EncodeToString(mac.Sum(nil))), []byte(d.Signature))
}

func TestBreakGlassQuota_ARequesterCannotDrownTheListNorTheChannel_AcrossFiveRealProcesses(t *testing.T) {
	root := repoRoot(t)

	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-10")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-10")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-10")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-10")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-10")

	audit := startService(t, root, auditBin, "18742")
	authz := startService(t, root, authzBin, "18743")
	authn := startService(t, root, authnBin, "18747", "SKIP_DEMO_SEED=1")
	spy := startAuditSpy(t, audit.baseURL)

	hook := newHookSpy(t)
	const channelSecret = "quota-test-HMAC-KEY-0123456789abcdef-NEVERLOG"
	broker := startService(t, root, brokerBin, "18744",
		"AUTHORIZATION_URL=http://127.0.0.1:18743", "VAULT_URL=http://127.0.0.1:18741", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18745", "BREAKGLASS_MAX_MINUTES=30",
		"BREAKGLASS_MAX_PENDING_PER_REQUESTER=2",
		"BREAKGLASS_NOTIFY_URL="+hook.srv.URL+"/hook", "BREAKGLASS_NOTIFY_SECRET="+channelSecret)
	gateway := startService(t, root, gatewayBin, "18748",
		"AUTHENTICATION_URL=http://127.0.0.1:18747", "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:18749")

	const acc = "acc_quota_1"
	const reason = "recorder down during INC-4242, database saturated"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead", "breakglass-approve:account:"+acc, "allow")
	authCreateUser(t, authn.baseURL, "sre-one", "SRE one", "sre-one-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "sre-two", "SRE two", "sre-two-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "lead-bob", "Lead", "bob-password-123", []string{"lead"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gateway.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: status %d", user, status)
		}
		return tok
	}
	one, two, bob := login("sre-one", "sre-one-password-1"), login("sre-two", "sre-two-password-1"), login("lead-bob", "bob-password-123")

	request := func(token string) (int, string, string) {
		status, body, sess := gatewayCreateWith(t, gateway.baseURL, token, acc, true, reason, 10)
		if sess != nil {
			return status, body, sess.ID
		}
		return status, body, ""
	}
	pendingFor := func(token string) *pendingList {
		status, body := gatewayList(t, gateway.baseURL, token, "status=pending_approval")
		if status != http.StatusOK {
			t.Fatalf("list: %d %s", status, body)
		}
		var out pendingList
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("list is not JSON: %v: %s", err, body)
		}
		return &out
	}
	settle := func() { time.Sleep(500 * time.Millisecond) } // for assertions that something did NOT happen

	var first, second string

	t.Run("a requester has the places the platform gives, and each request is announced with a signature only the Broker could make", func(t *testing.T) {
		for i, dst := range []*string{&first, &second} {
			status, body, id := request(one)
			if status != http.StatusCreated {
				t.Fatalf("request %d: %d %s", i+1, status, body)
			}
			*dst = id
			d := hook.waitFor(t, "breakglass.requested", id)
			if d.Timestamp == "" || !strings.HasPrefix(d.Signature, "v1=") {
				t.Fatalf("the delivery is not signed: %q %q", d.Timestamp, d.Signature)
			}
			if !receiverVerifies(channelSecret, d, 5*time.Minute) {
				t.Fatalf("a receiver cannot verify the delivery: %+v", d)
			}
			if strings.Contains(d.Raw, "NEVERLOG") || strings.Contains(d.Signature, "NEVERLOG") {
				t.Fatalf("the secret is in what was sent: %s", d.Raw)
			}
			// Control: the same check fails on a changed body, and on another secret.
			forged := d
			forged.Raw = strings.Replace(d.Raw, id, "session_forged", 1)
			if receiverVerifies(channelSecret, forged, 5*time.Minute) || receiverVerifies(channelSecret+"x", d, 5*time.Minute) {
				t.Fatal("the receiver's check accepts what it must refuse")
			}
		}
	})

	t.Run("the next request is refused as the requester's own quota — audited, announced to nobody, and absent from the list", func(t *testing.T) {
		refusedBefore := spy.anyEvent("session.breakglass_requested", false)
		announcedBefore := len(hook.deliveries("breakglass.requested", ""))

		status, body, _ := request(one)
		if status != http.StatusTooManyRequests {
			t.Fatalf("third request: %d %s, want 429", status, body)
		}
		if !strings.Contains(body, "at most 2") {
			t.Fatalf("the refusal does not say the limit: %s", body)
		}
		waitUntil(t, 5*time.Second, "the refusal to be audited", func() bool {
			return spy.anyEvent("session.breakglass_requested", false) == refusedBefore+1
		})
		settle()
		if n := len(hook.deliveries("breakglass.requested", "")); n != announcedBefore {
			t.Fatalf("a refused request was announced to the channel (%d deliveries, was %d)", n, announcedBefore)
		}
		if got := pendingFor(bob); fmt.Sprint(got.ids()) != fmt.Sprint([]string{first, second}) || got.TotalItems != 2 {
			t.Fatalf("the approver's list = %v (%d), want only the two that were accepted", got.ids(), got.TotalItems)
		}
	})

	t.Run("somebody else is not blocked by the first one's full queue", func(t *testing.T) {
		status, body, id := request(two)
		if status != http.StatusCreated {
			t.Fatalf("another requester: %d %s, want 201", status, body)
		}
		hook.waitFor(t, "breakglass.requested", id)
	})

	t.Run("a decision frees a place", func(t *testing.T) {
		if status, body := gatewayDecide(t, gateway.baseURL, bob, first, "approve", ""); status != http.StatusOK {
			t.Fatalf("approve: %d %s", status, body)
		}
		status, body, id := request(one)
		if status != http.StatusCreated {
			t.Fatalf("after a decision: %d %s, want 201", status, body)
		}
		hook.waitFor(t, "breakglass.requested", id)
		if status, _, _ := request(one); status != http.StatusTooManyRequests {
			t.Fatalf("the place that was freed was taken: want 429 again, got %d", status)
		}
	})

	t.Run("requests sent all at once take exactly the places that are left — not one more", func(t *testing.T) {
		// "sre-two" has 1 waiting and a quota of 2: one place. Twelve requests at once.
		const burst = 12
		var wg sync.WaitGroup
		var mu sync.Mutex
		codes := map[int]int{}
		start := make(chan struct{})
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				status, _, _ := request(two)
				mu.Lock()
				codes[status]++
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()
		if codes[http.StatusCreated] != 1 || codes[http.StatusTooManyRequests] != burst-1 || len(codes) != 2 {
			t.Fatalf("a burst of %d with one place left gave %v, want one 201 and %d 429", burst, codes, burst-1)
		}
		mine := 0
		for _, it := range pendingFor(bob).Items {
			if it.RequestedBy == userIDOf(t, two) {
				mine++
			}
		}
		if mine != 2 {
			t.Fatalf("%d of sre-two's requests wait, want exactly its quota of 2", mine)
		}
	})

	t.Run("the audit says who was refused, and the secret of the channel is nowhere in the Broker's log", func(t *testing.T) {
		// One refusal for the third request, one after the freed place was taken, eleven in
		// the burst: one refusal event per refused request, whether the early count or the
		// atomic save said no.
		if n := spy.anyEvent("session.breakglass_requested", false); n != 13 {
			t.Fatalf("%d refusals audited, want 13 — one for each refused request", n)
		}
		if strings.Contains(broker.out.String(), "NEVERLOG") {
			t.Fatalf("the Broker wrote the secret in its log:\n%s", broker.out.String())
		}
	})
}

// A secret and a limit that are wrong are found at start-up — not on the day an incident
// needs them — and the refusal never repeats what is secret.
func TestBreakGlassQuotaConfig_AWrongLimitOrSecretStopsTheBroker_AndWhatIsSaidAtStartIsTrue(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-quota-config")

	t.Run("the limit must be a number between 1 and 100", func(t *testing.T) {
		for _, bad := range []string{"0", "-1", "101", "abc", "3.5", "1e1"} {
			out := runUntilExit(t, root, bin, "PORT=18755", "BREAKGLASS_MAX_PENDING_PER_REQUESTER="+bad)
			if !strings.Contains(out, "BREAKGLASS_MAX_PENDING_PER_REQUESTER") {
				t.Fatalf("limit %q: expected an error naming the variable, got:\n%s", bad, out)
			}
		}
	})

	t.Run("a secret needs a channel, and enough bytes — and is never repeated", func(t *testing.T) {
		const shortSecret = "SECRETVALUE-0123456789-abcdefg" // 30 bytes: too short
		out := runUntilExit(t, root, bin, "PORT=18756", "BREAKGLASS_NOTIFY_SECRET=SECRETVALUE-0123456789-abcdefghijklmnopqrstuvwxyz")
		if !strings.Contains(out, "BREAKGLASS_NOTIFY_SECRET") || !strings.Contains(out, "BREAKGLASS_NOTIFY_URL") || strings.Contains(out, "SECRETVALUE") {
			t.Fatalf("a secret without a channel: expected an error naming both variables and not repeating the secret, got:\n%s", out)
		}
		out = runUntilExit(t, root, bin, "PORT=18756", "BREAKGLASS_NOTIFY_URL=https://hooks.example.com/services/X", "BREAKGLASS_NOTIFY_SECRET="+shortSecret)
		if !strings.Contains(out, "BREAKGLASS_NOTIFY_SECRET") || strings.Contains(out, "SECRETVALUE") || strings.Contains(out, "hooks.example.com/services") {
			t.Fatalf("a short secret: expected an error naming the variable and repeating neither the secret nor the URL, got:\n%s", out)
		}
	})

	t.Run("the Broker says what protects the requests, and says it truly", func(t *testing.T) {
		for _, c := range []struct {
			name, port string
			env        []string
			want       []string
			notWant    []string
		}{
			{"the defaults", "18757", []string{"BREAKGLASS_MAX_MINUTES=30"},
				[]string{"at most 3 waiting"}, []string{"SECRET"}},
			{"a limit of 5", "18758", []string{"BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_MAX_PENDING_PER_REQUESTER=5"},
				[]string{"at most 5 waiting"}, []string{"at most 3 waiting"}},
			{"a channel without a secret", "18759", []string{"BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_NOTIFY_URL=https://hooks.example.com/services/SECRETPATH"},
				[]string{"notifications are sent to https://hooks.example.com ", "not signed"}, []string{"SECRETPATH", "is a v1 HMAC"}},
			{"a channel with a secret", "18752", []string{"BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_NOTIFY_URL=https://hooks.example.com/services/SECRETPATH",
				"BREAKGLASS_NOTIFY_SECRET=SECRETKEY-0123456789abcdef0123456789abcdef"},
				[]string{"notifications are sent to https://hooks.example.com ", "is a v1 HMAC-SHA256"}, []string{"SECRETPATH", "SECRETKEY", "not signed"}},
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
	})
}
