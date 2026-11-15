package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const reconciliationFixture = `{"outcomes":[{"injection_id":"0123456789abcdef0123456789abcdef","session_id":"session-123","account_id":"account-prod","protocol":"ssh","emitter":"ssh-proxy","status":"outcome_unknown","reason":"missing_terminal_event","started_at":"2026-11-15T10:00:00Z","start_event_id":"audit-event-id"}],"coverage":"verified_archives_and_retained_chain","archived_history_excluded":false,"scanned_events":142,"archived_events":100,"has_more":true,"next_before":"0123456789abcdef0123456789abcdef"}`

func TestFetchSecretInjections_RendersVerifiedPageAndCursor(t *testing.T) {
	for _, output := range []string{"table", "json"} {
		t.Run(output, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/audit/v1/secret-injections" {
					t.Errorf("request = %s %s", r.Method, r.URL)
				}
				if r.URL.Query().Get("limit") != "3" || r.URL.Query().Get("before") != "0123456789abcdef0123456789abcdef" {
					t.Errorf("query = %s", r.URL.RawQuery)
				}
				w.Header().Set("Cache-Control", "private, no-store")
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, reconciliationFixture)
			}))
			defer server.Close()
			var out strings.Builder
			if err := fetchSecretInjections(context.Background(), server.Client(), server.URL, 3, "0123456789abcdef0123456789abcdef", output, &out); err != nil {
				t.Fatal(err)
			}
			got := out.String()
			for _, want := range []string{"outcome_unknown", "verified_archives_and_retained_chain", "0123456789abcdef0123456789abcdef"} {
				if !strings.Contains(got, want) {
					t.Fatalf("%s output does not contain %q: %s", output, want, got)
				}
			}
			if strings.Contains(got, "credential") || strings.Contains(got, "scope") {
				t.Fatalf("output contains secret-bearing fields: %s", got)
			}
			if output == "json" && (!strings.Contains(got, `"archived_history_excluded": false`) || !strings.Contains(got, `"archived_events": 100`)) {
				t.Fatalf("JSON output is not the typed reconciliation: %s", got)
			}
			if output == "table" && !strings.Contains(got, "archived_events=100") {
				t.Fatalf("table output omits archive coverage: %s", got)
			}
		})
	}
}

func TestFetchSecretInjections_FailsClosedOnUntrustedResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body, cacheControl string
		status                   int
		want                     string
	}{
		{name: "upstream unavailable", body: "internal path /var/lib/audit", cacheControl: "no-store", status: http.StatusServiceUnavailable, want: "HTTP 503"},
		{name: "cacheable response", body: reconciliationFixture, status: http.StatusOK, want: "Cache-Control"},
		{name: "malformed response", body: "{bad", cacheControl: "no-store", status: http.StatusOK, want: "invalid response"},
		{name: "partial archive coverage", body: strings.Replace(reconciliationFixture, `"archived_history_excluded":false`, `"archived_history_excluded":true`, 1), cacheControl: "no-store", status: http.StatusOK, want: "complete archive coverage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.cacheControl != "" {
					w.Header().Set("Cache-Control", tc.cacheControl)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			var out strings.Builder
			err := fetchSecretInjections(context.Background(), server.Client(), server.URL, 100, "", "table", &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "/var/lib/audit") {
				t.Fatalf("upstream body leaked in error: %v", err)
			}
		})
	}
}

func TestFetchSecretInjections_RejectsOversizedBodyAndNonHTTPSURL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, strings.Repeat("x", maxSecretInjectionResponseBytes+1))
	}))
	defer server.Close()
	if err := fetchSecretInjections(context.Background(), server.Client(), server.URL, 100, "", "json", &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized response error = %v", err)
	}
	plain := strings.Replace(server.URL, "https://", "http://", 1)
	if err := fetchSecretInjections(context.Background(), server.Client(), plain, 100, "", "json", &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("plain HTTP error = %v", err)
	}
}

func TestValidateSecretInjectionReconciliation_RejectsInvalidIDsStatusesAndCursors(t *testing.T) {
	base := secretInjectionReconciliation{
		Outcomes: []secretInjectionOutcome{{InjectionID: "0123456789abcdef0123456789abcdef", Status: "completed"}},
		Coverage: "retained_audit_chain",
	}
	for _, mutate := range []func(*secretInjectionReconciliation){
		func(r *secretInjectionReconciliation) { r.Outcomes[0].InjectionID = "not-an-id" },
		func(r *secretInjectionReconciliation) { r.Outcomes[0].Status = "retry" },
		func(r *secretInjectionReconciliation) { r.HasMore = true },
		func(r *secretInjectionReconciliation) { r.ArchivedEvents = 1 },
	} {
		got := base
		got.Outcomes = append([]secretInjectionOutcome(nil), base.Outcomes...)
		mutate(&got)
		if err := validateSecretInjectionReconciliation(got); err == nil {
			t.Fatalf("invalid reconciliation accepted: %+v", got)
		}
	}
	if validReconciliationCursor("0123456789ABCDEF0123456789ABCDEF") || validReconciliationCursor("short") {
		t.Fatal("non-canonical cursor accepted")
	}
}

func TestSecretInjections_ValidatesArgumentsBeforeTLS(t *testing.T) {
	t.Setenv("INTERNAL_TLS", "disabled")
	for _, tc := range []struct {
		name, audit, before, output, want string
		limit                             int
	}{
		{name: "missing URL", limit: 100, output: "table", want: "needs -audit"},
		{name: "limit out of range", audit: "https://audit-service:8082", limit: 501, output: "table", want: "between 1 and 500"},
		{name: "invalid cursor", audit: "https://audit-service:8082", limit: 100, before: "short", output: "table", want: "32-character"},
		{name: "invalid output", audit: "https://audit-service:8082", limit: 100, output: "yaml", want: "table or json"},
		{name: "TLS disabled", audit: "https://audit-service:8082", limit: 100, output: "table", want: "INTERNAL_TLS must be required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := secretInjections(context.Background(), tc.audit, tc.limit, tc.before, tc.output, &strings.Builder{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFetchSecretInjections_EncodesCursorAsQueryParameter(t *testing.T) {
	cursor := "0123456789abcdef0123456789abcdef"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("before"); got != cursor {
			t.Errorf("before = %q", got)
		}
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, reconciliationFixture)
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	parsed.Path = "/base"
	if err := fetchSecretInjections(context.Background(), server.Client(), parsed.String(), 100, cursor, "table", &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
}

func TestWriteSecretInjectionTable_DoesNotAllowTerminalOrRowInjection(t *testing.T) {
	var out strings.Builder
	result := secretInjectionReconciliation{
		Outcomes: []secretInjectionOutcome{{
			InjectionID: "0123456789abcdef0123456789abcdef",
			SessionID:   "session\nforged-row",
			AccountID:   "account\tforged-column\x1b[31m",
			Protocol:    "ssh",
			Status:      "outcome_unknown",
		}},
		Coverage: "retained_audit_chain",
	}
	if err := writeSecretInjectionTable(&out, result); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 3 || strings.Contains(out.String(), "\x1b") {
		t.Fatalf("terminal control or row injection was preserved: %q", out.String())
	}
	if !strings.Contains(out.String(), "session�forged-row") || !strings.Contains(out.String(), "account�forged-column�[31m") {
		t.Fatalf("unsafe fields were not visibly replaced: %q", out.String())
	}
}

func TestHasNoStore_RequiresAnExactDirective(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{header: "private, no-store", want: true},
		{header: "NO-STORE", want: true},
		{header: "no-storex", want: false},
		{header: "private, max-age=0", want: false},
	} {
		if got := hasNoStore(tc.header); got != tc.want {
			t.Errorf("hasNoStore(%q) = %t, want %t", tc.header, got, tc.want)
		}
	}
}

func TestFetchSecretInjections_DoesNotFollowRedirects(t *testing.T) {
	redirectReached := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			redirectReached = true
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, reconciliationFixture)
			return
		}
		http.Redirect(w, r, "/redirect", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	if err := fetchSecretInjections(context.Background(), server.Client(), server.URL, 100, "", "table", &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect response error = %v, want HTTP 307", err)
	}
	if redirectReached {
		t.Fatal("the CLI followed an Audit Service redirect")
	}
}
