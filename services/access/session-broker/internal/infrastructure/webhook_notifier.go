package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/openbastion/openbastion/pkg/webhook"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

const (
	// webhookMaxInFlight bounds the deliveries under way at once. A notifier that
	// piled up goroutines behind a dead endpoint would be a way to exhaust the Broker;
	// past this number a notification is dropped, and said so in the log.
	webhookMaxInFlight = 16

	// WebhookMinSecretBytes is the shortest key the Broker will sign with (ADR-0013).
	WebhookMinSecretBytes = webhook.MinSecretBytes

	// The two headers of a signed delivery (ADR-0013), shared with the alerts of the
	// Audit Service (ADR-0045): see pkg/webhook.
	WebhookTimestampHeader = webhook.TimestampHeader
	WebhookSignatureHeader = webhook.SignatureHeader
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
// The transport — the URL checked, never written (it is a secret: Slack and Teams put
// theirs in the path), no redirect followed, the exact body signed — is pkg/webhook's.
type WebhookNotifier struct {
	endpoint *webhook.Endpoint
	slots    chan struct{}
	logf     func(format string, args ...any)
}

// NewWebhookNotifier checks rawURL (pkg/webhook.New) and returns a notifier for it; the
// error never repeats the URL, because the caller writes it into the log.
func NewWebhookNotifier(rawURL string) (*WebhookNotifier, error) {
	e, err := webhook.New(rawURL)
	if err != nil {
		return nil, err
	}
	return &WebhookNotifier{endpoint: e, slots: make(chan struct{}, webhookMaxInFlight), logf: log.Printf}, nil
}

// WithTimeout shortens or lengthens the bound of one delivery; for tests.
func (w *WebhookNotifier) WithTimeout(d time.Duration) *WebhookNotifier {
	w.endpoint.WithTimeout(d)
	return w
}

// WithSecret makes the notifier sign every delivery (ADR-0013). A secret shorter than
// WebhookMinSecretBytes is refused, with an error that does not repeat it.
func (w *WebhookNotifier) WithSecret(secret string) (*WebhookNotifier, error) {
	if _, err := w.endpoint.WithSecret(secret); err != nil {
		return nil, err
	}
	return w, nil
}

// Signed says whether deliveries carry a signature.
func (w *WebhookNotifier) Signed() bool { return w.endpoint.Signed() }

// WithClock replaces the clock that stamps a signed delivery; for tests.
func (w *WebhookNotifier) WithClock(now func() time.Time) *WebhookNotifier {
	w.endpoint.WithClock(now)
	return w
}

// WithLogf replaces the logger; for tests.
func (w *WebhookNotifier) WithLogf(logf func(format string, args ...any)) *WebhookNotifier {
	w.logf = logf
	return w
}

// Where is the only part of the URL that may be written down: scheme and host.
func (w *WebhookNotifier) Where() string { return w.endpoint.Where() }

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
	Ticket          string `json:"ticket,omitempty"` // ADR-0067
	ExpiresAt       string `json:"expiresAt"`
	At              string `json:"at"`
	// Text is the same message for a human, under the key that Slack-style incoming
	// webhooks read.
	Text string `json:"text"`
}

func toWebhookMessage(n domain.ApprovalNotification) webhookMessage {
	deadline := n.ExpiresAt.UTC().Format("15:04")
	id, acc, by, dec := webhook.SafeText(n.SessionID), webhook.SafeText(n.AccountID), webhook.SafeText(n.RequestedBy), webhook.SafeText(n.DecidedBy)
	ticket := webhook.SafeText(n.Ticket)
	var text string
	switch n.Event {
	case domain.NotifyBreakGlassRequested:
		text = fmt.Sprintf("OpenBastion break-glass request %s: %s asks for %d min on account %s. It waits for a second person until %s UTC.", id, by, n.DurationMinutes, acc, deadline)
	case domain.NotifyBreakGlassApproved:
		text = fmt.Sprintf("OpenBastion break-glass request %s APPROVED by %s: %s has %d min on account %s, until %s UTC.", id, dec, by, n.DurationMinutes, acc, deadline)
	case domain.NotifyBreakGlassRejected:
		text = fmt.Sprintf("OpenBastion break-glass request %s REJECTED by %s: %s asked for %d min on account %s.", id, dec, by, n.DurationMinutes, acc)
	case domain.NotifyApprovalRequested:
		text = fmt.Sprintf("OpenBastion access request %s: %s asks for %d min on account %s, ticket %s. It waits for an approver until %s UTC.", id, by, n.DurationMinutes, acc, ticket, deadline)
	case domain.NotifyApprovalApproved:
		text = fmt.Sprintf("OpenBastion access request %s APPROVED by %s: %s has %d min on account %s, ticket %s, until %s UTC.", id, dec, by, n.DurationMinutes, acc, ticket, deadline)
	case domain.NotifyApprovalRejected:
		text = fmt.Sprintf("OpenBastion access request %s REJECTED by %s: %s asked for %d min on account %s, ticket %s.", id, dec, by, n.DurationMinutes, acc, ticket)
	default:
		text = fmt.Sprintf("OpenBastion break-glass event %s on request %s.", webhook.SafeText(n.Event), id)
	}
	return webhookMessage{
		Event: n.Event, SessionID: n.SessionID, AccountID: n.AccountID, RequestedBy: n.RequestedBy, DecidedBy: n.DecidedBy,
		DurationMinutes: n.DurationMinutes, Ticket: n.Ticket, ExpiresAt: n.ExpiresAt.UTC().Format(time.RFC3339), At: n.At.UTC().Format(time.RFC3339),
		Text: text,
	}
}

// Notify sends n in the background and returns at once.
func (w *WebhookNotifier) Notify(ctx context.Context, n domain.ApprovalNotification) {
	select {
	case w.slots <- struct{}{}:
	default:
		w.logf("session-broker: notification %s for %s dropped: %d deliveries are already in flight", n.Event, webhook.SafeText(n.SessionID), webhookMaxInFlight)
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
	status, err := w.endpoint.Post(ctx, "OpenBastion-Session-Broker", body)
	switch {
	case err != nil:
		w.logf("session-broker: notification %s for %s not delivered to %s: %v", n.Event, webhook.SafeText(n.SessionID), w.Where(), err)
	case status < 200 || status > 299:
		w.logf("session-broker: notification %s for %s refused by %s: status %d", n.Event, webhook.SafeText(n.SessionID), w.Where(), status)
	}
}
