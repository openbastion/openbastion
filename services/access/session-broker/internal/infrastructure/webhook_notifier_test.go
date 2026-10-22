package infrastructure_test

// The webhook that tells an on-call channel that a break-glass request waits
// (ADR-0012). It is a courtesy, and what is proved here is how it behaves when the
// courtesy cannot be paid: it never blocks, never fails, and never writes the URL —
// which is a secret — anywhere.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

const secretPath = "/services/T0000/B0000/SECRETTOKEN"

type delivery struct {
	method, contentType, userAgent, path string
	body                                 map[string]any
	raw                                  string
}

// receiver is an endpoint that hands each delivery to a channel.
func receiver(t *testing.T) (*httptest.Server, chan delivery) {
	t.Helper()
	got := make(chan delivery, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		got <- delivery{r.Method, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), r.URL.Path, body, string(raw)}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func wait(t *testing.T, ch chan delivery) delivery {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(3 * time.Second):
		t.Fatal("nothing was delivered")
		return delivery{}
	}
}

// logLines collects what the notifier writes to its log.
type logLines struct {
	mu    sync.Mutex
	lines []string
	ch    chan string
}

func newLogLines() *logLines { return &logLines{ch: make(chan string, 64)} }

func (l *logLines) logf(format string, args ...any) {
	line := strings.TrimSpace(fmt.Sprintf(format, args...))
	l.mu.Lock()
	l.lines = append(l.lines, line)
	l.mu.Unlock()
	l.ch <- line
}

func (l *logLines) next(t *testing.T) string {
	t.Helper()
	select {
	case line := <-l.ch:
		return line
	case <-time.After(3 * time.Second):
		t.Fatal("the failure was not logged")
		return ""
	}
}

func (l *logLines) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

var requested = domain.ApprovalNotification{
	Event: domain.NotifyBreakGlassRequested, SessionID: "session_ab12", AccountID: "acc-prod-db", RequestedBy: "user-oncall",
	DurationMinutes: 20, ExpiresAt: time.Date(2026, 10, 22, 14, 32, 0, 0, time.UTC), At: time.Date(2026, 10, 22, 14, 17, 0, 0, time.UTC),
}

func TestWebhook_PostsAMessageThatNamesTheRequest_AndNothingElse(t *testing.T) {
	srv, got := receiver(t)
	n, err := infrastructure.NewWebhookNotifier(srv.URL + secretPath)
	if err != nil {
		t.Fatal(err)
	}
	n.Notify(context.Background(), requested)
	d := wait(t, got)

	if d.method != http.MethodPost || d.path != secretPath || !strings.HasPrefix(d.contentType, "application/json") || d.userAgent == "" {
		t.Fatalf("delivery = %+v", d)
	}
	// The exact set of keys: a field added to the message is a decision, not an accident.
	keys := map[string]bool{}
	for k := range d.body {
		keys[k] = true
	}
	for _, k := range []string{"event", "sessionId", "accountId", "requestedBy", "durationMinutes", "expiresAt", "at", "text"} {
		if !keys[k] {
			t.Errorf("the message lacks %q: %s", k, d.raw)
		}
		delete(keys, k)
	}
	if len(keys) != 0 {
		t.Fatalf("the message carries more than it should: %v in %s", keys, d.raw)
	}
	if d.body["event"] != "breakglass.requested" || d.body["sessionId"] != "session_ab12" || d.body["accountId"] != "acc-prod-db" ||
		d.body["requestedBy"] != "user-oncall" || d.body["durationMinutes"] != float64(20) ||
		d.body["expiresAt"] != "2026-10-22T14:32:00Z" || d.body["at"] != "2026-10-22T14:17:00Z" {
		t.Fatalf("message = %s", d.raw)
	}
	text, _ := d.body["text"].(string)
	for _, want := range []string{"session_ab12", "acc-prod-db", "user-oncall", "20 min", "14:32 UTC"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text %q does not say %q", text, want)
		}
	}
	if strings.Contains(strings.ToLower(d.raw), "justif") {
		t.Fatalf("something about a justification travels in the message: %s", d.raw)
	}
}

func TestWebhook_ADecisionNamesWhoTookIt(t *testing.T) {
	for event, word := range map[string]string{domain.NotifyBreakGlassApproved: "APPROVED", domain.NotifyBreakGlassRejected: "REJECTED"} {
		srv, got := receiver(t)
		n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")
		decided := requested
		decided.Event, decided.DecidedBy = event, "user-lead"
		n.Notify(context.Background(), decided)
		d := wait(t, got)
		text, _ := d.body["text"].(string)
		if d.body["event"] != event || d.body["decidedBy"] != "user-lead" || !strings.Contains(text, word) || !strings.Contains(text, "user-lead") {
			t.Fatalf("%s: %s", event, d.raw)
		}
	}
	// A request has no decider: the key is absent, not empty.
	srv, got := receiver(t)
	n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")
	n.Notify(context.Background(), requested)
	if d := wait(t, got); d.body["decidedBy"] != nil {
		t.Fatalf("a request carries a decider: %s", d.raw)
	}
}

// The account identifier is the requester's own input. Whatever reaches a chat service
// as text must not be able to make a mention, a link or a line break.
func TestWebhook_TheTextCannotCarryWhatChatServicesTurnIntoAMentionOrALink(t *testing.T) {
	srv, got := receiver(t)
	n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")
	hostile := requested
	hostile.AccountID = "<!channel> approve now: https://evil.example/x\nline two"
	hostile.RequestedBy = strings.Repeat("a", 500)
	n.Notify(context.Background(), hostile)
	d := wait(t, got)
	text, _ := d.body["text"].(string)
	for _, bad := range []string{"<", ">", "!channel", "https://", "\n", " approve now", strings.Repeat("a", 65)} {
		if strings.Contains(text, bad) {
			t.Errorf("the text carries %q: %q", bad, text)
		}
	}
	if !strings.Contains(text, "??channel") {
		t.Errorf("the replaced characters should show as '?': %q", text)
	}
	if len(text) > 400 {
		t.Errorf("a hostile identifier made the text %d characters long", len(text))
	}
}

func TestWebhook_NotifyReturnsAtOnce_WhateverTheEndpointDoes(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")

	start := time.Now()
	n.Notify(context.Background(), requested)
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("Notify took %v with an endpoint that does not answer: a request for an emergency access would wait for it", took)
	}
}

// The request that caused the notification ends long before the delivery does.
func TestWebhook_AnEndedRequestDoesNotCancelTheDelivery(t *testing.T) {
	srv, got := receiver(t)
	n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")
	ctx, cancel := context.WithCancel(context.Background())
	n.Notify(ctx, requested)
	cancel() // the HTTP handler returned
	wait(t, got)
}

func TestWebhook_AFailureIsALogLine_NeverTheURL_AndNeverAnEffect(t *testing.T) {
	// 1. nobody listens
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	// 2. the endpoint refuses
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusInternalServerError) }))
	defer refusing.Close()

	// 3. the endpoint redirects somewhere else — which must not be visited
	var visited atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { visited.Add(1) }))
	defer elsewhere.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/internal/metadata", http.StatusFound)
	}))
	defer redirecting.Close()

	// 4. the endpoint is too slow
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer slow.Close()
	defer close(release)

	for name, c := range map[string]struct{ base, expect string }{
		"nobody listens": {closedURL, "not delivered"},
		"refused":        {refusing.URL, "status 500"},
		"redirected":     {redirecting.URL, "status 302"},
		"too slow":       {slow.URL, "not delivered"},
	} {
		t.Run(name, func(t *testing.T) {
			n, err := infrastructure.NewWebhookNotifier(c.base + secretPath + "?token=SECRETQUERY")
			if err != nil {
				t.Fatal(err)
			}
			logs := newLogLines()
			n.WithLogf(logs.logf).WithTimeout(300 * time.Millisecond)

			n.Notify(context.Background(), requested) // returns, and says nothing to its caller
			line := logs.next(t)
			if !strings.Contains(line, c.expect) || !strings.Contains(line, "breakglass.requested") || !strings.Contains(line, "session_ab12") {
				t.Fatalf("log line = %q, want it to say %q for this event and session", line, c.expect)
			}
			if !strings.Contains(line, n.Where()) {
				t.Fatalf("log line = %q, want it to say where (%s)", line, n.Where())
			}
			for _, secret := range []string{"SECRETTOKEN", "SECRETQUERY", "/services", "T0000"} {
				if strings.Contains(logs.all(), secret) {
					t.Fatalf("the secret URL leaked into the log (%q): %s", secret, logs.all())
				}
			}
		})
	}
	if visited.Load() != 0 {
		t.Fatalf("the redirect was followed: the other address was visited %d time(s)", visited.Load())
	}
}

func TestWebhook_ASuccessSaysNothing(t *testing.T) {
	srv, got := receiver(t)
	n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")
	logs := newLogLines()
	n.WithLogf(logs.logf)
	n.Notify(context.Background(), requested)
	wait(t, got)
	time.Sleep(50 * time.Millisecond)
	if out := logs.all(); out != "" {
		t.Fatalf("a delivery that worked wrote to the log: %q", out)
	}
}

// Deliveries are bounded: a dead endpoint cannot make the Broker pile up goroutines.
func TestWebhook_DropsWhatExceedsTheDeliveriesInFlight_AndSaysSo(t *testing.T) {
	var arrived atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Add(1)
		<-release
	}))
	defer srv.Close()
	defer open() // runs first: a failing test must free the handlers, or srv.Close() waits for them forever
	n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")
	logs := newLogLines()
	n.WithLogf(logs.logf)

	const limit = 16
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < limit; i++ {
			n.Notify(context.Background(), requested)
		}
	}()
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatalf("Notify blocked on the endpoint: %d of %d notifications handed over in 2 s", arrived.Load(), limit)
	}
	deadline := time.Now().Add(3 * time.Second)
	for arrived.Load() < limit && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if arrived.Load() != limit {
		t.Fatalf("%d of the first %d deliveries reached the endpoint", arrived.Load(), limit)
	}

	n.Notify(context.Background(), requested) // one too many
	if line := logs.next(t); !strings.Contains(line, "dropped") {
		t.Fatalf("log line = %q, want a notification dropped", line)
	}
	time.Sleep(100 * time.Millisecond)
	if arrived.Load() != limit {
		t.Fatalf("the notification past the limit was delivered anyway (%d arrived)", arrived.Load())
	}

	// Once the endpoint answers, the room is back.
	open()
	deadline = time.Now().Add(3 * time.Second)
	for {
		n.Notify(context.Background(), requested)
		time.Sleep(50 * time.Millisecond)
		if arrived.Load() > limit || time.Now().After(deadline) {
			break
		}
	}
	if arrived.Load() <= limit {
		t.Fatal("deliveries never resumed after the endpoint answered")
	}
}

func TestNewWebhookNotifier_AcceptsOnlyAURLItCanTrust(t *testing.T) {
	for _, ok := range []string{
		"https://hooks.slack.example/services/T/B/X", "https://hooks.example.com:8443/h", "http://127.0.0.1:8080/hook",
		"http://localhost/hook", "http://[::1]:9/hook",
	} {
		if _, err := infrastructure.NewWebhookNotifier(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "   ", "hooks.example.com/x", "http://hooks.example.com/SECRETPATH", "http://10.0.0.5/SECRETPATH", "ftp://hooks.example.com/SECRETPATH",
		"https://user:SECRETPASS@hooks.example.com/x", "https:///SECRETPATH", "https://", "https://%zz/SECRETPATH",
		"http://127.0.0.1.evil.example/SECRETPATH", "http://localhost.evil.example/SECRETPATH", "file:///etc/passwd?SECRETPATH",
		"javascript:SECRETPATH",
	} {
		_, err := infrastructure.NewWebhookNotifier(bad)
		if err == nil {
			t.Errorf("%q was accepted", bad)
			continue
		}
		// The error is written to the Broker's log by main: it must not repeat the secret.
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("the error for %q repeats the URL: %v", bad, err)
		}
	}
}

func TestWebhook_WhereIsSchemeAndHostOnly(t *testing.T) {
	n, err := infrastructure.NewWebhookNotifier("https://hooks.example.com:8443/services/SECRET/PATH?token=SECRETQUERY#frag")
	if err != nil {
		t.Fatal(err)
	}
	if n.Where() != "https://hooks.example.com:8443" {
		t.Fatalf("Where() = %q", n.Where())
	}
}
