package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

const (
	// webhookTimeout bounds one delivery, connection and answer included.
	webhookTimeout = 5 * time.Second
	// webhookMaxInFlight bounds the deliveries under way at once. A notifier that
	// piled up goroutines behind a dead endpoint would be a way to exhaust the Broker;
	// past this number a notification is dropped, and said so in the log.
	webhookMaxInFlight = 16
)

// WebhookNotifier implements application.ApprovalNotifier by POSTing a small JSON
// message to one URL (ADR-0012): the smallest real way to tell an on-call channel —
// Slack, Teams, Mattermost, a generic receiver — that a break-glass request waits.
//
// It is a courtesy and is built as one. Notify never blocks (the delivery runs in
// its own goroutine, on a context cut loose from the request that caused it), never
// fails (it has no result), and does not retry. A refusal, an error or a silence from
// the endpoint is a line in the log and nothing else.
//
// The URL is a secret: Slack and Teams put theirs in the path. It is therefore never
// written anywhere — Where() is its scheme and host, which is all the log says — and
// transport errors are stripped of it before being logged (net/http puts the whole
// URL in them). Redirects are not followed: a hostile or hijacked endpoint must not
// be able to send the Broker, from inside the network, to another address.
type WebhookNotifier struct {
	url     string
	where   string
	client  *http.Client
	timeout time.Duration // bounds one delivery, through its context
	slots   chan struct{}
	logf    func(format string, args ...any)
}

// NewWebhookNotifier checks rawURL and returns a notifier for it. https is required,
// except towards a loopback address (development and tests); a URL that carries
// credentials, has no host, has another scheme or cannot be read is an error — whose
// text never repeats the URL, because the caller writes it into the log.
func NewWebhookNotifier(rawURL string) (*WebhookNotifier, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("not a valid URL")
	}
	if u.Hostname() == "" {
		return nil, errors.New("the URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("the URL must not carry credentials (user:password@)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, errors.New("http is only allowed towards a loopback address; use https")
		}
	default:
		return nil, errors.New("the URL scheme must be https")
	}
	w := &WebhookNotifier{
		url:     u.String(),
		where:   u.Scheme + "://" + u.Host,
		timeout: webhookTimeout,
		slots:   make(chan struct{}, webhookMaxInFlight),
		logf:    log.Printf,
		client: &http.Client{
			// A redirect is an answer, not an instruction: the Broker does not go where an
			// endpoint tells it to.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	return w, nil
}

// WithTimeout shortens or lengthens the bound of one delivery; for tests.
func (w *WebhookNotifier) WithTimeout(d time.Duration) *WebhookNotifier {
	w.timeout = d
	return w
}

// WithLogf replaces the logger; for tests.
func (w *WebhookNotifier) WithLogf(logf func(format string, args ...any)) *WebhookNotifier {
	w.logf = logf
	return w
}

// Where is the only part of the URL that may be written down: scheme and host.
func (w *WebhookNotifier) Where() string { return w.where }

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// webhookMessage is the body of a delivery. It is built from a
// domain.ApprovalNotification, which has no field for the justification or for
// anything about the target: there is nothing here to leave out by care.
type webhookMessage struct {
	Event           string `json:"event"`
	SessionID       string `json:"sessionId"`
	AccountID       string `json:"accountId"`
	RequestedBy     string `json:"requestedBy"`
	DecidedBy       string `json:"decidedBy,omitempty"`
	DurationMinutes int    `json:"durationMinutes"`
	ExpiresAt       string `json:"expiresAt"`
	At              string `json:"at"`
	// Text is the same message for a human, under the key that Slack-style incoming
	// webhooks read.
	Text string `json:"text"`
}

func toWebhookMessage(n domain.ApprovalNotification) webhookMessage {
	deadline := n.ExpiresAt.UTC().Format("15:04")
	id, acc, by, dec := safeText(n.SessionID), safeText(n.AccountID), safeText(n.RequestedBy), safeText(n.DecidedBy)
	var text string
	switch n.Event {
	case domain.NotifyBreakGlassRequested:
		text = fmt.Sprintf("OpenBastion break-glass request %s: %s asks for %d min on account %s. It waits for a second person until %s UTC.", id, by, n.DurationMinutes, acc, deadline)
	case domain.NotifyBreakGlassApproved:
		text = fmt.Sprintf("OpenBastion break-glass request %s APPROVED by %s: %s has %d min on account %s, until %s UTC.", id, dec, by, n.DurationMinutes, acc, deadline)
	case domain.NotifyBreakGlassRejected:
		text = fmt.Sprintf("OpenBastion break-glass request %s REJECTED by %s: %s asked for %d min on account %s.", id, dec, by, n.DurationMinutes, acc)
	default:
		text = fmt.Sprintf("OpenBastion break-glass event %s on request %s.", safeText(n.Event), id)
	}
	return webhookMessage{
		Event: n.Event, SessionID: n.SessionID, AccountID: n.AccountID, RequestedBy: n.RequestedBy, DecidedBy: n.DecidedBy,
		DurationMinutes: n.DurationMinutes, ExpiresAt: n.ExpiresAt.UTC().Format(time.RFC3339), At: n.At.UTC().Format(time.RFC3339),
		Text: text,
	}
}

// safeText makes an identifier fit to be read inside a sentence by a chat service:
// letters, digits and . _ : - survive, anything else — the characters that make a
// mention, a link or a line break — becomes "?", and it stops at 64 characters. The
// account identifier is supplied by the person who asks, so it is not trusted to be
// the plain word it normally is.
func safeText(s string) string {
	const max = 64
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if len(out) == max {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == ':', r == '-':
			out = append(out, r)
		default:
			out = append(out, '?')
		}
	}
	return string(out)
}

// Notify sends n in the background and returns at once.
func (w *WebhookNotifier) Notify(ctx context.Context, n domain.ApprovalNotification) {
	select {
	case w.slots <- struct{}{}:
	default:
		w.logf("session-broker: notification %s for %s dropped: %d deliveries are already in flight", n.Event, safeText(n.SessionID), webhookMaxInFlight)
		return
	}
	body, _ := json.Marshal(toWebhookMessage(n)) // strings and integers only: it cannot fail
	// The request that caused the notification will have ended long before the
	// delivery does; its cancellation is not the delivery's.
	ctx = context.WithoutCancel(ctx)
	go func() {
		defer func() { <-w.slots }()
		w.deliver(ctx, n, body)
	}()
}

func (w *WebhookNotifier) deliver(ctx context.Context, n domain.ApprovalNotification, body []byte) {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		w.logf("session-broker: notification %s for %s not sent to %s", n.Event, safeText(n.SessionID), w.where)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenBastion-Session-Broker")
	resp, err := w.client.Do(req)
	if err != nil {
		// net/http wraps the failure in a *url.Error whose text begins with the whole
		// URL — the secret. What is logged is the cause alone.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		w.logf("session-broker: notification %s for %s not delivered to %s: %v", n.Event, safeText(n.SessionID), w.where, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		w.logf("session-broker: notification %s for %s refused by %s: status %d", n.Event, safeText(n.SessionID), w.where, resp.StatusCode)
	}
}
