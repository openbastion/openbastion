package infrastructure_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/webhook"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

const alertSecret = "0123456789abcdef0123456789abcdef-alerts"

// receiver answers each delivery with the next status of its script (the last one repeated)
// and keeps what it received and when.
type receiver struct {
	mu       sync.Mutex
	statuses []int
	bodies   [][]byte
	headers  []http.Header
	at       []time.Time
	srv      *httptest.Server
	hold     chan struct{} // when set, every delivery waits on it
}

func newReceiver(t *testing.T, statuses ...int) *receiver {
	r := &receiver{statuses: statuses}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.hold != nil {
			<-r.hold
		}
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		n := len(r.bodies)
		r.bodies, r.headers, r.at = append(r.bodies, body), append(r.headers, req.Header.Clone()), append(r.at, time.Now())
		status := r.statuses[len(r.statuses)-1]
		if n < len(r.statuses) {
			status = r.statuses[n]
		}
		r.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// logs collects what the notifier writes.
type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logs) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func alertWebhook(t *testing.T, rawURL string, retry time.Duration) (*infrastructure.AlertWebhook, *logs) {
	t.Helper()
	e, err := webhook.New(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WithSecret(alertSecret); err != nil {
		t.Fatal(err)
	}
	a, err := infrastructure.NewAlertWebhook(e, retry)
	if err != nil {
		t.Fatal(err)
	}
	l := &logs{}
	return a.WithLogf(l.logf), l
}

func overdue(id, account string) domain.Event {
	return domain.Event{ID: id, Timestamp: time.Date(2026, 10, 31, 9, 0, 0, 123000, time.UTC), Action: "vault.rotation_overdue",
		ResourceType: "account", ResourceID: account, Emitter: "password-vault", Hash: []byte("h"), KeyID: "k1"}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAlertWebhook_AnAlertIsDeliveredSigned_WithWhatTheChainHolds_AndNothingElse(t *testing.T) {
	r := newReceiver(t, 204)
	a, _ := alertWebhook(t, r.srv.URL+"/hook", time.Second)
	a.Notify(context.Background(), overdue("evt_1", "acc_db"))
	eventually(t, "one delivery", func() bool { return r.count() == 1 })

	r.mu.Lock()
	body, h := r.bodies[0], r.headers[0]
	r.mu.Unlock()
	if got, want := h.Get(webhook.SignatureHeader), webhook.Signature([]byte(alertSecret), h.Get(webhook.TimestampHeader), body); got != want || got == "" {
		t.Fatalf("signature %q, want %q", got, want)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"event": "vault.rotation_overdue", "eventId": "evt_1", "emitter": "password-vault", "resourceType": "account",
		"resourceId": "acc_db", "success": false, "at": "2026-10-31T09:00:00.000123Z"}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %v, want %v", k, m[k], v)
		}
	}
	// What the message holds is exactly that, and a sentence: no actor, no hash, no key.
	if len(m) != len(want)+1 || !strings.Contains(m["text"].(string), "acc_db") || !strings.Contains(m["text"].(string), "evt_1") {
		t.Fatalf("unexpected message %v", m)
	}
}

func TestAlertWebhook_AFailureIsRetried_TheWaitDoubling_UntilItIsDelivered(t *testing.T) {
	r := newReceiver(t, 500, 503, 429, 408, 200)
	base := 40 * time.Millisecond
	a, l := alertWebhook(t, r.srv.URL, base)
	a.Notify(context.Background(), overdue("evt_2", "acc_db"))
	eventually(t, "five attempts", func() bool { return r.count() == 5 })
	time.Sleep(4 * base)
	if n := r.count(); n != 5 {
		t.Fatalf("%d attempts after a delivery, want 5", n)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 1; i < len(r.at); i++ {
		if gap, min := r.at[i].Sub(r.at[i-1]), base<<(i-1); gap < min {
			t.Fatalf("attempt %d came %s after the previous one, want at least %s", i+1, gap, min)
		}
	}
	// Each attempt is the same alert: the receiver can tell a duplicate by its eventId.
	for _, b := range r.bodies[1:] {
		if string(b) != string(r.bodies[0]) {
			t.Fatalf("a retry is not the same message:\n%s\n%s", b, r.bodies[0])
		}
	}
	if !strings.Contains(l.all(), "attempt 5 of 5") || strings.Contains(l.all(), "given up") {
		t.Fatalf("log:\n%s", l.all())
	}
}

func TestAlertWebhook_ItGivesUpAfterFiveAttempts_AndSaysSo(t *testing.T) {
	r := newReceiver(t, 503)
	a, l := alertWebhook(t, r.srv.URL, 5*time.Millisecond)
	a.Notify(context.Background(), overdue("evt_3", "acc_db"))
	eventually(t, "the give-up", func() bool { return strings.Contains(l.all(), "given up") })
	time.Sleep(200 * time.Millisecond)
	if n := r.count(); n != infrastructure.AlertMaxAttempts {
		t.Fatalf("%d attempts, want %d", n, infrastructure.AlertMaxAttempts)
	}
	if !strings.Contains(l.all(), "evt_3") || !strings.Contains(l.all(), "after 5 attempt(s)") {
		t.Fatalf("the give-up does not name the event and the attempts:\n%s", l.all())
	}
}

func TestAlertWebhook_ARefusalIsFinal(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 410, 301} {
		r := newReceiver(t, status, 200)
		a, l := alertWebhook(t, r.srv.URL, 5*time.Millisecond)
		a.Notify(context.Background(), overdue("evt_4", "acc_db"))
		eventually(t, "the give-up", func() bool { return strings.Contains(l.all(), "given up") })
		time.Sleep(50 * time.Millisecond)
		if n := r.count(); n != 1 {
			t.Fatalf("status %d: %d attempts, want 1", status, n)
		}
	}
}

func TestAlertWebhook_TheURLIsNeverWritten_EvenWhenNothingAnswers(t *testing.T) {
	r := newReceiver(t, 200)
	url := r.srv.URL + "/services/T000/B000/s3cr3t-path"
	r.srv.Close() // nothing listens any more: transport errors, whose text net/http prefixes with the URL
	a, l := alertWebhook(t, url, 5*time.Millisecond)
	a.Notify(context.Background(), overdue("evt_5", "acc_db"))
	eventually(t, "the give-up", func() bool { return strings.Contains(l.all(), "given up") })
	if strings.Contains(l.all(), "s3cr3t-path") || strings.Contains(l.all(), alertSecret) {
		t.Fatalf("the log holds the URL or the secret:\n%s", l.all())
	}
	if !strings.Contains(l.all(), a.Where()) || !strings.Contains(l.all(), "attempt 2 of 5") {
		t.Fatalf("a transport error is retried, and the log names where:\n%s", l.all())
	}
}

func TestAlertWebhook_ADeadReceiverDoesNotMakeTheServiceGrow_NorWait(t *testing.T) {
	r := newReceiver(t, 200)
	r.hold = make(chan struct{})
	defer close(r.hold)
	a, l := alertWebhook(t, r.srv.URL, time.Second)
	start := time.Now()
	for i := 0; i < infrastructure.AlertMaxOutstanding+10; i++ {
		a.Notify(context.Background(), overdue(fmt.Sprintf("evt_%d", i), "acc_db"))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Notify waited %s behind a receiver that does not answer", d)
	}
	if n := strings.Count(l.all(), "not pushed"); n != 10 {
		t.Fatalf("%d alerts dropped, want 10 past %d outstanding:\n%s", n, infrastructure.AlertMaxOutstanding, l.all())
	}
}

func TestAlertWebhook_TheSentenceCannotMentionAnyoneNorBreakALine(t *testing.T) {
	r := newReceiver(t, 200)
	a, _ := alertWebhook(t, r.srv.URL, time.Second)
	a.Notify(context.Background(), overdue("evt_6", "acc<!channel>\n<https://evil.example|click>"))
	eventually(t, "one delivery", func() bool { return r.count() == 1 })
	r.mu.Lock()
	defer r.mu.Unlock()
	var m map[string]any
	_ = json.Unmarshal(r.bodies[0], &m)
	text := m["text"].(string)
	if strings.ContainsAny(text, "<>|\n!") || strings.Contains(text, "https://") {
		t.Fatalf("the sentence carries what the chat would read as markup: %q", text)
	}
	// The field itself is the identifier as the chain holds it: a machine reads it, JSON-escaped.
	if m["resourceId"] != "acc<!channel>\n<https://evil.example|click>" {
		t.Fatalf("resourceId = %q", m["resourceId"])
	}
}

func TestAlertWebhook_AnUnsignedChannelOrABadRetryIsRefused(t *testing.T) {
	e, err := webhook.New("https://alerts.example/hook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := infrastructure.NewAlertWebhook(e, time.Second); err == nil {
		t.Fatal("an alert channel without a secret was accepted")
	}
	if _, err := e.WithSecret(alertSecret); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, -time.Second, infrastructure.MaxAlertRetry + time.Second} {
		if _, err := infrastructure.NewAlertWebhook(e, d); err == nil {
			t.Fatalf("a retry of %s was accepted", d)
		}
	}
}
