package integration_test

// ADR-0078 on real processes, under PostgreSQL and a real Audit Service: an OIDC provider keeps its
// issuer. Another issuer under the same provider refuses the start, by the three ways measured
// before (the variables, an entry of the file, an entry that adopts the accounts of the variables);
// a change is declared from the exact issuer bound, written to the audit before the binding
// changes, and refused with the audit down; two starts together keep one issuer.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIssuerBinding_AnotherIssuerRefusesTheStart_AChangeIsDeclaredAndAuditedFirst(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() }) // after the bindings are forgotten: cleanups run last first
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-78")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-78")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-78")
	const clientID, secret = "openbastion-it", "client-secret-it-0123456789"
	idpA, idpB := startTestIdP(t, clientID, secret), startTestIdP(t, clientID, secret)
	issuerA, issuerB := idpA.srv.URL, idpB.srv.URL

	audit := startService(t, root, auditBin, "19840")
	spy := startAuditSpy(t, audit.baseURL)
	// What the binding of a provider was when its change reached the audit: the audit comes first.
	var seenMu sync.Mutex
	boundWhenWritten := map[string]string{}
	target, _ := url.Parse(spy.baseURL)
	forward := httputil.NewSingleHostReverseProxy(target)
	auditURL := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/emit-event") {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var ev spiedEvent
			if bytes.Contains(body, []byte("auth.identity_provider_rebound")) && json.Unmarshal(body, &ev) == nil {
				provider := ev.ResourceID
				if provider == "(variables)" {
					provider = ""
				}
				seenMu.Lock()
				boundWhenWritten[ev.ResourceID] = boundIssuer(t, db, provider)
				seenMu.Unlock()
			}
		}
		forward.ServeHTTP(w, r)
	}))

	conf := t.TempDir()
	roleMap := writeFile(t, conf, "roles.json", `{"authors": ["dba"]}`, 0o600)
	secretFile := writeFile(t, conf, "client-secret", secret, 0o600)
	signing := testKMSKeyHex(t)
	base := []string{"DATABASE_URL=" + dsn, "TOKEN_SIGNING_KEY_HEX=" + signing, "SKIP_DEMO_SEED=1", "AUDIT_URL=" + auditURL, "PORT=19841"}
	run := fmt.Sprint(time.Now().UnixNano())
	sub := "sub-" + run
	idpA.as(sub, "authors")
	idpB.as(sub, "authors")
	// The ids of this run: rows left by an earlier run against the same database never match.
	corp, other, fresh, race := "corp-"+run, "other-"+run, "fresh-"+run, "race-"+run
	forgetIssuerBindings(t, db, "")
	t.Cleanup(func() { forgetIssuerBindings(t, db, "") })

	vars := func(issuer, previous string) []string {
		env := []string{"OIDC_ISSUER=" + issuer, "OIDC_CLIENT_ID=" + clientID, "OIDC_CLIENT_SECRET=" + secret,
			"OIDC_REDIRECT_URL=http://127.0.0.1:5173/oidc/callback", "OIDC_ROLE_MAP_FILE=" + roleMap}
		if previous != "" {
			env = append(env, "OIDC_PREVIOUS_ISSUER="+previous)
		}
		return env
	}
	type entry struct {
		id, issuer, previous string
		adopt                bool
	}
	file := func(entries ...entry) []string {
		var parts []string
		for _, e := range entries {
			parts = append(parts, fmt.Sprintf(`{"id": %q, "label": %q, "issuer": %q, "client_id": %q, "client_secret_file": %q, "redirect_url": "http://127.0.0.1:5173/oidc/callback", "role_map_file": %q, "previous_issuer": %q, "adopt_legacy_accounts": %v}`,
				e.id, e.id, e.issuer, clientID, secretFile, roleMap, e.previous, e.adopt))
		}
		name := fmt.Sprintf("providers-%d.json", time.Now().UnixNano())
		return []string{"IDENTITY_PROVIDERS_FILE=" + writeFile(t, conf, name, `{"oidc": [`+strings.Join(parts, ", ")+`]}`, 0o644)}
	}
	env := func(extra []string) []string { return append(append([]string{}, base...), extra...) }
	// login starts the service, logs sub in at the provider named (or the only one), and stops it.
	login := func(extra []string, provider string) (username, out string) {
		t.Helper()
		authn := startService(t, root, authnBin, "19841", env(extra)...)
		gw := startService(t, root, gatewayBin, "19842", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
		var status int
		var body string
		if provider == "" {
			status, body, _, _ = federatedLogin(t, gw.baseURL)
		} else {
			status, body = federatedLoginAt(t, gw.baseURL, provider)
		}
		out = authn.out.String()
		stopService(t, gw)
		stopService(t, authn)
		if status != http.StatusOK {
			t.Fatalf("login: %d %s\n%s", status, body, out)
		}
		username, _ = tokenClaims(t, body)
		return username, out
	}
	refused := func(extra []string, says ...string) string {
		t.Helper()
		out := runUntilExit(t, root, authnBin, env(extra)...)
		for _, s := range append([]string{"refusing to start"}, says...) {
			if !strings.Contains(out, s) {
				t.Fatalf("the refusal does not say %q:\n%s", s, out)
			}
		}
		if strings.Contains(out, secret) {
			t.Fatal("the client secret is in the output")
		}
		return out
	}

	var account string
	t.Run("the variables: another OIDC_ISSUER refuses the start, and says how to get out", func(t *testing.T) {
		account, _ = login(vars(issuerA, ""), "")
		refused(vars(issuerB, ""), "OIDC_ISSUER is bound to the issuer "+issuerA, "configured with "+issuerB, "OIDC_PREVIOUS_ISSUER = "+issuerA)
		if got := boundIssuer(t, db, ""); got != issuerA {
			t.Fatalf("bound to %q after a refusal, want %q", got, issuerA)
		}
	})

	t.Run("a change declared from another issuer is refused", func(t *testing.T) {
		refused(vars(issuerB, "https://idp-c.example"), "declares a change from https://idp-c.example")
	})

	t.Run("the audit down, a declared change is not made", func(t *testing.T) {
		spy.setDown(true)
		refused(vars(issuerB, issuerA), "audit")
		spy.setDown(false)
		if got := boundIssuer(t, db, ""); got != issuerA {
			t.Fatalf("bound to %q with the audit down, want %q", got, issuerA)
		}
	})

	t.Run("a change declared from the issuer bound: written first, then the same account at the new issuer", func(t *testing.T) {
		username, out := login(vars(issuerB, issuerA), "")
		if username != account {
			t.Fatalf("after the declared change, %s, want the same account %s", username, account)
		}
		if !strings.Contains(out, "changed from the issuer "+issuerA+" to "+issuerB) {
			t.Fatalf("the start does not say the change:\n%s", out)
		}
		if !spyHasRebind(spy, "(variables)", issuerA, issuerB) {
			t.Fatalf("no auth.identity_provider_rebound from %s to %s reached the Audit Service", issuerA, issuerB)
		}
		seenMu.Lock()
		when := boundWhenWritten["(variables)"]
		seenMu.Unlock()
		if when != issuerA {
			t.Fatalf("when the change reached the audit, the binding was %q: the audit comes first", when)
		}
		if got := boundIssuer(t, db, ""); got != issuerB {
			t.Fatalf("bound to %q, want %q", got, issuerB)
		}
	})

	t.Run("an entry of the file: another issuer under its id refuses the start", func(t *testing.T) {
		login(file(entry{id: corp, issuer: issuerA}), corp)
		refused(file(entry{id: corp, issuer: issuerB}), fmt.Sprintf("oidc %q is bound to the issuer %s", corp, issuerA), fmt.Sprintf("oidc %q: previous_issuer = %s", corp, issuerA))
	})

	t.Run("an entry that adopts the accounts of the variables, at another issuer than theirs, refuses the start", func(t *testing.T) {
		// The variables' accounts are now issuer B's (declared above): an entry of issuer A may not take them.
		refused(file(entry{id: other, issuer: issuerA, adopt: true}), "adopt_legacy_accounts", "bound to the issuer "+issuerB)
		if username, _ := login(file(entry{id: other, issuer: issuerB, adopt: true}), other); username != account {
			t.Fatalf("the entry of their issuer adopting them: %s, want %s", username, account)
		}
	})

	t.Run("an id removed from the file is not freed", func(t *testing.T) {
		login(file(entry{id: fresh, issuer: issuerB}), fresh) // corp is gone from the file
		refused(file(entry{id: corp, issuer: issuerB}), fmt.Sprintf("oidc %q is bound to the issuer %s", corp, issuerA))
	})

	t.Run("one entry refused, nothing is recorded for the others", func(t *testing.T) {
		newcomer := "newcomer-" + run
		refused(file(entry{id: newcomer, issuer: issuerA}, entry{id: corp, issuer: issuerB}), fmt.Sprintf("oidc %q", corp))
		if got := boundIssuer(t, db, newcomer); got != "" {
			t.Fatalf("%s was bound to %q by a start that was refused", newcomer, got)
		}
	})

	t.Run("two starts together with two issuers for one new id: one issuer kept, the other start refused", func(t *testing.T) {
		results := make(chan string, 2)
		for i, issuer := range []string{issuerA, issuerB} {
			go func(port, issuer string) {
				results <- startAndSettle(t, root, authnBin, append(env(file(entry{id: race, issuer: issuer})), "PORT="+port)...)
			}(fmt.Sprint(19843+i), issuer)
		}
		got := []string{<-results, <-results}
		running, refusedStarts := 0, 0
		for _, g := range got {
			switch {
			case g == "running":
				running++
			case strings.Contains(g, "is bound to the issuer"):
				refusedStarts++
			}
		}
		if running != 1 || refusedStarts != 1 {
			t.Fatalf("two starts together: %q, want one running and one refused", got)
		}
	})
}

// federatedLoginAt is federatedLogin at the provider named (ADR-0076).
func federatedLoginAt(t *testing.T, gatewayURL, provider string) (int, string) {
	t.Helper()
	resp, err := http.Post(gatewayURL+"/auth/oidc/start", "application/json", strings.NewReader(fmt.Sprintf(`{"provider": %q}`, provider)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var started struct {
		AuthorizationURL string `json:"authorizationUrl"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &started) != nil || started.AuthorizationURL == "" {
		t.Fatalf("start at %s: %d %s", provider, resp.StatusCode, raw)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noFollow.Get(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %v", resp.StatusCode, err)
	}
	return oidcCallback(t, gatewayURL, back.Query().Get("code"), back.Query().Get("state"))
}

// boundIssuer is the issuer provider is bound to, "" if none.
func boundIssuer(t *testing.T, db *sql.DB, provider string) string {
	t.Helper()
	var issuer string
	if err := db.QueryRow(`SELECT issuer FROM identity_provider_bindings WHERE provider = $1`, provider).Scan(&issuer); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return issuer
}

func spyHasRebind(spy *auditSpy, resource, from, to string) bool {
	spy.mu.Lock()
	defer spy.mu.Unlock()
	for _, e := range spy.events {
		if e.Action == "auth.identity_provider_rebound" && e.ResourceType == "identity_provider" && e.ResourceID == resource &&
			e.Details["previous_issuer"] == from && e.Details["issuer"] == to && e.Success {
			return true
		}
	}
	return false
}

// startAndSettle starts a process and says what became of it within 15 s: "running" once it
// answers /healthz (then it is stopped), or what it wrote if it exited.
func startAndSettle(t *testing.T, root, bin string, env ...string) string {
	cmd := exec.Command(bin)
	cmd.Env = append(buildEnv(root), env...)
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return "start: " + err.Error()
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	port := ""
	for _, e := range env {
		if strings.HasPrefix(e, "PORT=") {
			port = strings.TrimPrefix(e, "PORT=")
		}
	}
	// Each try bounded: a port not yet open may hang rather than refuse on some hosts.
	probe := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return out.String()
		default:
		}
		if resp, err := probe.Get("http://127.0.0.1:" + port + "/healthz"); err == nil {
			resp.Body.Close()
			_ = cmd.Process.Kill()
			<-done
			return "running"
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	<-done
	return "neither running nor exited:\n" + out.String()
}

// forgetIssuerBindings removes what an earlier test bound for these providers (ADR-0078): the tests
// start IdPs on new ports, so the issuer of a fixed id, or of the variables, changes at each run.
// Before the Authentication Service has migrated, there is no table and nothing to forget.
func forgetIssuerBindings(t *testing.T, db *sql.DB, providers ...string) {
	t.Helper()
	for _, p := range providers {
		if _, err := db.Exec(`DO $$ BEGIN IF to_regclass('identity_provider_bindings') IS NOT NULL THEN
			DELETE FROM identity_provider_bindings WHERE provider = '` + p + `'; END IF; END $$`); err != nil {
			t.Fatal(err)
		}
	}
}
