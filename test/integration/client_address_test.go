// The per-address limits of the Gateway and who "the client" is behind a reverse proxy
// (ADR-0015), on real processes: Authentication and API Gateways with different settings.
// The test plays the reverse proxy: it connects from the loopback and writes
// X-Forwarded-For.
//
// The claims that matter: behind a declared proxy each client has its own login bucket (it
// was one bucket for everybody); and nobody can choose its own key by writing the header —
// not from a peer that is not a declared proxy, and not on the left of what the proxy added.
package integration_test

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

const wrongLogin = `{"username":"patient","password":"not-the-password"}`

// loginVia is a login attempt, from the loopback, that carries the given X-Forwarded-For lines.
func loginVia(t *testing.T, gatewayURL string, xff ...string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/auth/login", strings.NewReader(wrongLogin))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header
}

func attempts(t *testing.T, gatewayURL string, n int, xff func(i int) []string) string {
	t.Helper()
	var codes []int
	for i := 0; i < n; i++ {
		code, _ := loginVia(t, gatewayURL, xff(i)...)
		codes = append(codes, code)
	}
	return fmt.Sprint(codes)
}

func same(v ...string) func(int) []string { return func(int) []string { return v } }

func TestClientAddress_BehindADeclaredProxy_EachClientHasItsOwnLoginBucket_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-15a")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-15a")
	authn := startService(t, root, authnBin, "18764", "SKIP_DEMO_SEED=1")
	authCreateUser(t, authn.baseURL, "patient", "Patient", "patient-password-123", []string{"nobody"})
	upstream := []string{"AUTHENTICATION_URL=" + authn.baseURL, "SESSION_BROKER_URL=http://127.0.0.1:18769", "COMMAND_RECORDER_URL=http://127.0.0.1:18769"}

	t.Run("without a declared proxy, one client drains the burst of everybody (what ADR-0014 measured)", func(t *testing.T) {
		gw := startService(t, root, gatewayBin, "18770", upstream...)
		if got := attempts(t, gw.baseURL, 5, same("203.0.113.9")); got != "[401 401 401 401 401]" {
			t.Fatalf("the first client's five attempts: %s", got)
		}
		if code, _ := loginVia(t, gw.baseURL, "198.51.100.4"); code != http.StatusTooManyRequests {
			t.Fatalf("a second client got %d, want 429: with no proxy declared the Gateway sees one client", code)
		}
	})

	t.Run("with the proxy declared, each client has a burst of five and then one a minute", func(t *testing.T) {
		gw := startService(t, root, gatewayBin, "18771", append(upstream, "TRUSTED_PROXY_CIDRS=127.0.0.1/32")...)
		if got := attempts(t, gw.baseURL, 7, same("203.0.113.9")); got != "[401 401 401 401 401 429 429]" {
			t.Fatalf("the first client: %s, want five that reached Authentication and two that did not", got)
		}
		if got := attempts(t, gw.baseURL, 7, same("198.51.100.4")); got != "[401 401 401 401 401 429 429]" {
			t.Fatalf("the second client: %s, want the same, untouched by the first", got)
		}
		code, h := loginVia(t, gw.baseURL, "203.0.113.9")
		if n, err := strconv.Atoi(h.Get("Retry-After")); code != http.StatusTooManyRequests || err != nil || n < 55 || n > 60 {
			t.Fatalf("%d, Retry-After %q, want 429 and about a minute", code, h.Get("Retry-After"))
		}
		// Two addresses of one IPv6 /64 are one client; the next /64 is another.
		if got := attempts(t, gw.baseURL, 6, func(i int) []string { return []string{fmt.Sprintf("2001:db8:1:2:%x::1", i+1)} }); got != "[401 401 401 401 401 429]" {
			t.Fatalf("six addresses of one /64: %s, want one client: five attempts, then refused", got)
		}
		if code, _ := loginVia(t, gw.baseURL, "2001:db8:1:3::1"); code != http.StatusUnauthorized {
			t.Fatalf("the next /64: %d, want its own bucket (401)", code)
		}
	})
}

// The header is written by whoever sends the request. If a limit believed it, the sender
// would have a new key with every request and the brute-force protection would be gone.
func TestClientAddress_NobodyChoosesItsOwnKey_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-15b")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-15b")
	authn := startService(t, root, authnBin, "18764", "SKIP_DEMO_SEED=1")
	authCreateUser(t, authn.baseURL, "patient", "Patient", "patient-password-123", []string{"nobody"})
	upstream := []string{"AUTHENTICATION_URL=" + authn.baseURL, "SESSION_BROKER_URL=http://127.0.0.1:18769", "COMMAND_RECORDER_URL=http://127.0.0.1:18769"}
	const wantFiveThenRefused = "[401 401 401 401 401 429 429 429 429 429]"

	t.Run("from a peer that is not a declared proxy, a new X-Forwarded-For each time gives nothing", func(t *testing.T) {
		// Declared: some other address. The test connects from the loopback.
		gw := startService(t, root, gatewayBin, "18772", append(upstream, "TRUSTED_PROXY_CIDRS=10.99.99.99/32")...)
		got := attempts(t, gw.baseURL, 10, func(i int) []string { return []string{fmt.Sprintf("6.6.6.%d", i+1)} })
		if got != wantFiveThenRefused {
			t.Fatalf("ten attempts, each with another address in the header: %s, want %s", got, wantFiveThenRefused)
		}
	})

	t.Run("behind a declared proxy, what the client wrote on the left of the proxy's address gives nothing", func(t *testing.T) {
		gw := startService(t, root, gatewayBin, "18773", append(upstream, "TRUSTED_PROXY_CIDRS=127.0.0.1")...)
		// The proxy appended 203.0.113.9, the address it saw, to what the client sent.
		got := attempts(t, gw.baseURL, 10, func(i int) []string { return []string{fmt.Sprintf("6.6.6.%d, 203.0.113.9", i+1)} })
		if got != wantFiveThenRefused {
			t.Fatalf("ten attempts, each with a forged left side: %s, want %s", got, wantFiveThenRefused)
		}
		// The same over several header lines, and with a forged proxy next to the real client.
		more := attempts(t, gw.baseURL, 2, func(i int) []string { return []string{fmt.Sprintf("1.2.3.%d", i+1), "203.0.113.9, 127.0.0.1"} })
		if more != "[429 429]" {
			t.Fatalf("two more with forged lines: %s, want both refused", more)
		}
	})

	t.Run("a client that writes someone else's address spends nothing of theirs", func(t *testing.T) {
		// The proxy is 127.0.0.1. The attacker reaches the Gateway directly, from 127.0.0.2,
		// and writes the address of somebody who comes through the proxy.
		gw := startService(t, root, gatewayBin, "18774", append(upstream, "TRUSTED_PROXY_CIDRS=127.0.0.1/32")...)
		attacker := &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext}}
		var codes []int
		for i := 0; i < 8; i++ {
			req, _ := http.NewRequest(http.MethodPost, gw.baseURL+"/auth/login", strings.NewReader(wrongLogin))
			req.Header.Set("X-Forwarded-For", "198.51.100.4")
			resp, err := attacker.Do(req)
			if err != nil {
				t.Skipf("this sandbox cannot connect from 127.0.0.2: %v", err)
			}
			resp.Body.Close()
			codes = append(codes, resp.StatusCode)
		}
		if fmt.Sprint(codes) != "[401 401 401 401 401 429 429 429]" {
			t.Fatalf("the attacker's eight attempts: %v, want its own burst of five and then refused", codes)
		}
		// The real owner of 198.51.100.4 comes through the proxy and has a bucket that is untouched.
		if got := attempts(t, gw.baseURL, 5, same("198.51.100.4")); got != "[401 401 401 401 401]" {
			t.Fatalf("the owner of the address, through the proxy: %s, want its own full burst: the attacker was charged to itself", got)
		}
	})
}

// The per-address limits are adjustable, within bounds, and never "unlimited".
func TestClientAddress_TheLimitsAreAdjustable_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-15c")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-15c")
	authn := startService(t, root, authnBin, "18764", "SKIP_DEMO_SEED=1")
	authCreateUser(t, authn.baseURL, "patient", "Patient", "patient-password-123", []string{"nobody"})
	authCreateUser(t, authn.baseURL, "steady", "Steady", "steady-password-123", []string{"nobody"})
	upstream := []string{"AUTHENTICATION_URL=" + authn.baseURL, "SESSION_BROKER_URL=http://127.0.0.1:18769", "COMMAND_RECORDER_URL=http://127.0.0.1:18769"}

	t.Run("login: two at once, then sixty a minute (one a second)", func(t *testing.T) {
		gw := startService(t, root, gatewayBin, "18776", append(upstream, "CLIENT_LOGIN_BURST=2", "CLIENT_LOGIN_RATE_PER_MINUTE=60")...)
		if got := attempts(t, gw.baseURL, 4, same("203.0.113.9")); got != "[401 401 429 429]" {
			t.Fatalf("%s, want a burst of two", got)
		}
		if _, h := loginVia(t, gw.baseURL, "203.0.113.9"); h.Get("Retry-After") != "1" {
			t.Fatalf("Retry-After = %q, want 1: a token comes back every second", h.Get("Retry-After"))
		}
		time.Sleep(1100 * time.Millisecond)
		if code, _ := loginVia(t, gw.baseURL, "203.0.113.9"); code != http.StatusUnauthorized {
			t.Fatalf("a second later: %d, want a token back (401)", code)
		}
	})

	t.Run("authenticated requests: three at once, then six a minute", func(t *testing.T) {
		gw := startService(t, root, gatewayBin, "18777", append(upstream, "CLIENT_REQUEST_BURST=3", "CLIENT_REQUEST_RATE_PER_MINUTE=6")...)
		tok, status := gatewayLogin(t, gw.baseURL, "steady", "steady-password-123")
		if status != http.StatusOK {
			t.Fatalf("login: %d", status)
		}
		// The login above went through the login limiter, not this one. Now spend the burst.
		var got []int
		for i := 0; i < 5; i++ {
			code, _, _ := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/s-none", tok, "")
			if code == http.StatusTooManyRequests {
				code = 429
			} else {
				code = 0 // reached the upstream, whatever it said
			}
			got = append(got, code)
		}
		if fmt.Sprint(got) != "[0 0 0 429 429]" {
			t.Fatalf("five authenticated requests with a burst of three: %v, want three through and two refused", got)
		}
		// Six a minute is a token every ten seconds — not the default, which is one a second.
		code, h, _ := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/s-none", tok, "")
		if n, err := strconv.Atoi(h.Get("Retry-After")); code != http.StatusTooManyRequests || err != nil || n < 9 || n > 10 {
			t.Fatalf("%d, Retry-After %q, want 429 and about ten seconds", code, h.Get("Retry-After"))
		}
	})
}

// A setting that is wrong is found when the Gateway starts, and what it says it applies is
// what it applies.
func TestClientAddressConfig_AWrongValueStopsTheGateway_AndWhatIsSaidAtStartIsTrue(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-15d")

	t.Run("a trust that is doubtful stops the Gateway, naming the variable and the entry", func(t *testing.T) {
		for _, c := range []struct{ value, mentions string }{
			{"0.0.0.0/0", "trusts every address"},
			{"::/0", "trusts every address"},
			{"::ffff:0.0.0.0/96", "trusts every address"},
			{"10.0.0.0/8,,172.16.0.0/12", "entry 2 is empty"},
			{"banana", `"banana"`},
			{"192.168.1.5/24", "has host bits set"},
			{"10.0.0.0/33", "is not a CIDR network"},
		} {
			out := runUntilExit(t, root, bin, "PORT=18778", "TRUSTED_PROXY_CIDRS="+c.value)
			if !strings.Contains(out, "TRUSTED_PROXY_CIDRS") || !strings.Contains(out, c.mentions) {
				t.Fatalf("TRUSTED_PROXY_CIDRS=%q: expected an error naming the variable and saying %q, got:\n%s", c.value, c.mentions, out)
			}
		}
	})

	t.Run("a limit must be a number within its bounds", func(t *testing.T) {
		for _, c := range []struct{ name, value string }{
			{"CLIENT_LOGIN_BURST", "0"}, {"CLIENT_LOGIN_BURST", "101"}, {"CLIENT_LOGIN_BURST", "five"},
			{"CLIENT_LOGIN_RATE_PER_MINUTE", "0"}, {"CLIENT_LOGIN_RATE_PER_MINUTE", "61"}, {"CLIENT_LOGIN_RATE_PER_MINUTE", "-1"},
			{"CLIENT_REQUEST_BURST", "0"}, {"CLIENT_REQUEST_BURST", "10001"}, {"CLIENT_REQUEST_BURST", "1.5"},
			{"CLIENT_REQUEST_RATE_PER_MINUTE", "0"}, {"CLIENT_REQUEST_RATE_PER_MINUTE", "6001"}, {"CLIENT_REQUEST_RATE_PER_MINUTE", "many"},
		} {
			out := runUntilExit(t, root, bin, "PORT=18778", c.name+"="+c.value)
			if !strings.Contains(out, c.name) {
				t.Fatalf("%s=%s: expected an error naming the variable, got:\n%s", c.name, c.value, out)
			}
		}
	})

	t.Run("the Gateway says what it applies, and says it truly", func(t *testing.T) {
		for _, c := range []struct {
			name    string
			env     []string
			want    []string
			notWant []string
		}{
			{"the defaults", nil,
				[]string{"the address of the peer (TRUSTED_PROXY_CIDRS is not set)", "login 5 at once, then 1 per minute; authenticated requests 60 at once, then 60 per minute"},
				[]string{"X-Forwarded-For is believed"}},
			{"a declared proxy", []string{"TRUSTED_PROXY_CIDRS=10.0.0.0/8, 192.168.5.7"},
				[]string{"X-Forwarded-For is believed only from 10.0.0.0/8, 192.168.5.7/32"},
				[]string{"TRUSTED_PROXY_CIDRS is not set"}},
			{"custom limits", []string{"CLIENT_LOGIN_BURST=3", "CLIENT_LOGIN_RATE_PER_MINUTE=2", "CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=300"},
				[]string{"login 3 at once, then 2 per minute; authenticated requests 500 at once, then 300 per minute"},
				[]string{"login 5 at once"}},
			{"the largest", []string{"CLIENT_LOGIN_BURST=100", "CLIENT_LOGIN_RATE_PER_MINUTE=60", "CLIENT_REQUEST_BURST=10000", "CLIENT_REQUEST_RATE_PER_MINUTE=6000"},
				[]string{"login 100 at once, then 60 per minute; authenticated requests 10000 at once, then 6000 per minute"}, nil},
			{"the smallest", []string{"CLIENT_LOGIN_BURST=1", "CLIENT_LOGIN_RATE_PER_MINUTE=1", "CLIENT_REQUEST_BURST=1", "CLIENT_REQUEST_RATE_PER_MINUTE=1"},
				[]string{"login 1 at once, then 1 per minute; authenticated requests 1 at once, then 1 per minute"}, nil},
		} {
			t.Run(c.name, func(t *testing.T) {
				cmd := execCommandWithEnv(bin, root, append([]string{"PORT=18778"}, c.env...))
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
