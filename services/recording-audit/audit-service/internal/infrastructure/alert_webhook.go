package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/openbastion/openbastion/pkg/webhook"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

const (
	// AlertMaxAttempts bounds the deliveries of one alert (ADR-0045).
	AlertMaxAttempts = 5
	// AlertMaxOutstanding bounds the alerts queued or waiting for a retry: a dead receiver
	// must not make the Audit Service grow. Past it, an alert is not pushed, and the log says so.
	AlertMaxOutstanding = 256
	// DefaultAlertRetry is the wait before the first retry; it doubles at each one.
	DefaultAlertRetry = 30 * time.Second
	// MaxAlertRetry bounds ALERT_NOTIFY_RETRY_SECONDS.
	MaxAlertRetry = 600 * time.Second
)

// AlertWebhook implements application.AlertNotifier (ADR-0045): each alert is POSTed, signed,
// to one URL, by one worker, and retried after a transport error, a 408, a 429 or a 5xx — up
// to AlertMaxAttempts, the wait doubling from the first. Any other answer that is not a 2xx
// is final. The queue lives in memory: an alert waiting for a retry is lost if the service
// stops — it stays in the chain, and the Vault writes it again N failures later (ADR-0041).
type AlertWebhook struct {
	endpoint *webhook.Endpoint
	retry    time.Duration
	slots    chan struct{} // one per alert outstanding, queued or waiting
	queue    chan alertDelivery
	logf     func(format string, args ...any)
	after    func(time.Duration, func())
}

type alertDelivery struct {
	event   domain.Event
	body    []byte
	attempt int // the attempt about to be made, from 1
}

// NewAlertWebhook returns a notifier that delivers to endpoint, whose secret must be set: an
// alert channel that anyone could imitate teaches its receiver to ignore alerts (ADR-0045).
func NewAlertWebhook(endpoint *webhook.Endpoint, retry time.Duration) (*AlertWebhook, error) {
	if !endpoint.Signed() {
		return nil, fmt.Errorf("an alert channel is signed: its secret is required")
	}
	if retry <= 0 || retry > MaxAlertRetry {
		return nil, fmt.Errorf("the wait before a retry is between 1s and %s, got %s", MaxAlertRetry, retry)
	}
	a := &AlertWebhook{
		endpoint: endpoint,
		retry:    retry,
		slots:    make(chan struct{}, AlertMaxOutstanding),
		// As many places as slots: a retry put back never waits for room.
		queue: make(chan alertDelivery, AlertMaxOutstanding),
		logf:  log.Printf,
		after: func(d time.Duration, f func()) { time.AfterFunc(d, f) },
	}
	go a.work()
	return a, nil
}

// WithLogf replaces the logger; for tests.
func (a *AlertWebhook) WithLogf(logf func(format string, args ...any)) *AlertWebhook {
	a.logf = logf
	return a
}

// Where is the only part of the URL that may be written down: scheme and host.
func (a *AlertWebhook) Where() string { return a.endpoint.Where() }

// alertMessage is the body of a delivery: what the chain holds of the event, nothing more — no
// actor (an alert is the system's), nothing of the target.
type alertMessage struct {
	Event        string `json:"event"`
	EventID      string `json:"eventId"`
	Emitter      string `json:"emitter"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
	Success      bool   `json:"success"`
	At           string `json:"at"`
	// Text is the same message for a human, under the key that Slack-style incoming webhooks read.
	Text string `json:"text"`
}

func alertText(e domain.Event) string {
	id, res := webhook.SafeText(e.ID), webhook.SafeText(e.ResourceID)
	switch e.Action {
	case "vault.rotation_overdue":
		return fmt.Sprintf("OpenBastion alert: the scheduled rotation of account %s keeps failing; its secret is older than its rotation policy (audit event %s).", res, id)
	default:
		return fmt.Sprintf("OpenBastion alert %s on %s %s (audit event %s).", webhook.SafeText(e.Action), webhook.SafeText(e.ResourceType), res, id)
	}
}

// Notify queues e and returns at once.
func (a *AlertWebhook) Notify(_ context.Context, e domain.Event) {
	select {
	case a.slots <- struct{}{}:
	default:
		a.logf("audit-service: alert %s (event %s) not pushed: %d alerts are already waiting", e.Action, webhook.SafeText(e.ID), AlertMaxOutstanding)
		return
	}
	body, _ := json.Marshal(alertMessage{ // strings and a boolean only: it cannot fail
		Event: e.Action, EventID: e.ID, Emitter: e.Emitter, ResourceType: e.ResourceType, ResourceID: e.ResourceID,
		Success: e.Success, At: e.Timestamp.UTC().Format(time.RFC3339Nano), Text: alertText(e),
	})
	a.queue <- alertDelivery{event: e, body: body, attempt: 1}
}

func (a *AlertWebhook) work() {
	for d := range a.queue {
		a.deliver(d)
	}
}

// retryable says whether an answer may change if asked again.
func retryable(status int) bool {
	return status == 0 || status == 408 || status == 429 || status >= 500
}

func (a *AlertWebhook) deliver(d alertDelivery) {
	// The request that wrote the alert has long ended: a delivery has its own bound only.
	status, err := a.endpoint.Post(context.Background(), "OpenBastion-Audit-Service", d.body)
	if err == nil && status >= 200 && status <= 299 {
		<-a.slots
		return
	}
	what := fmt.Sprintf("status %d", status)
	if err != nil {
		what, status = err.Error(), 0
	}
	if !retryable(status) || d.attempt >= AlertMaxAttempts {
		a.logf("audit-service: alert %s (event %s) given up after %d attempt(s) to %s: %s", d.event.Action, webhook.SafeText(d.event.ID), d.attempt, a.Where(), what)
		<-a.slots
		return
	}
	wait := a.retry << (d.attempt - 1)
	a.logf("audit-service: alert %s (event %s) not delivered to %s (%s): attempt %d of %d in %s", d.event.Action, webhook.SafeText(d.event.ID), a.Where(), what, d.attempt+1, AlertMaxAttempts, wait)
	d.attempt++
	a.after(wait, func() { a.queue <- d })
}
