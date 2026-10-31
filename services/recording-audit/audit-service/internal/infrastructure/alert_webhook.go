package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
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
	queue    AlertQueue    // where the alerts wait (ADR-0057)
	wake     chan struct{} // a new alert: look at the queue now
	logMu    sync.Mutex    // the worker may write before WithLogf returns: a queue kept in a database starts full
	logf     func(format string, args ...any)
	now      func() time.Time
}

// NewAlertWebhook returns a notifier that delivers to endpoint, its alerts waiting in memory
// (ADR-0045). The endpoint's secret must be set: an alert channel that anyone could imitate
// teaches its receiver to ignore alerts.
func NewAlertWebhook(endpoint *webhook.Endpoint, retry time.Duration) (*AlertWebhook, error) {
	return NewAlertWebhookWithQueue(endpoint, retry, NewMemoryAlertQueue())
}

// NewAlertWebhookWithQueue is NewAlertWebhook with the alerts waiting in queue — alert_outbox when
// the Audit Service has a database, so that a restart does not lose them (ADR-0057). What the
// queue already holds is delivered.
func NewAlertWebhookWithQueue(endpoint *webhook.Endpoint, retry time.Duration, queue AlertQueue) (*AlertWebhook, error) {
	if !endpoint.Signed() {
		return nil, fmt.Errorf("an alert channel is signed: its secret is required")
	}
	if retry <= 0 || retry > MaxAlertRetry {
		return nil, fmt.Errorf("the wait before a retry is between 1s and %s, got %s", MaxAlertRetry, retry)
	}
	a := &AlertWebhook{endpoint: endpoint, retry: retry, queue: queue, wake: make(chan struct{}, 1), logf: log.Printf, now: time.Now}
	go a.work()
	return a, nil
}

// WithLogf replaces the logger; for tests.
func (a *AlertWebhook) WithLogf(logf func(format string, args ...any)) *AlertWebhook {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	a.logf = logf
	return a
}

func (a *AlertWebhook) log(format string, args ...any) {
	a.logMu.Lock()
	logf := a.logf
	a.logMu.Unlock()
	logf(format, args...)
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

// Notify keeps e in the queue and returns at once.
func (a *AlertWebhook) Notify(ctx context.Context, e domain.Event) {
	body, _ := json.Marshal(alertMessage{ // strings and a boolean only: it cannot fail
		Event: e.Action, EventID: e.ID, Emitter: e.Emitter, ResourceType: e.ResourceType, ResourceID: e.ResourceID,
		Success: e.Success, At: e.Timestamp.UTC().Format(time.RFC3339Nano), Text: alertText(e),
	})
	kept, err := a.queue.Put(context.WithoutCancel(ctx), QueuedAlert{EventID: e.ID, Action: e.Action, Body: body, Attempt: 1, Due: a.now()})
	switch {
	case err != nil:
		a.log("audit-service: alert %s (event %s) not pushed: it could not be kept (%v)", e.Action, webhook.SafeText(e.ID), err)
		return
	case !kept:
		a.log("audit-service: alert %s (event %s) not pushed: %d alerts are already waiting", e.Action, webhook.SafeText(e.ID), AlertMaxOutstanding)
		return
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// work delivers what is due, then waits for the next one due, or a new alert.
func (a *AlertWebhook) work() {
	ctx := context.Background()
	for {
		due, err := a.queue.Due(ctx, a.now(), 16)
		if err != nil {
			a.log("audit-service: the alerts waiting cannot be read: %v", err)
		}
		for _, d := range due {
			a.deliver(ctx, d)
		}
		if len(due) == 16 {
			continue
		}
		wait := time.Minute
		if next, err := a.queue.Next(ctx); err == nil && !next.IsZero() {
			if wait = time.Until(next); wait < 0 {
				wait = 0
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-a.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// retryable says whether an answer may change if asked again.
func retryable(status int) bool {
	return status == 0 || status == 408 || status == 429 || status >= 500
}

func (a *AlertWebhook) deliver(ctx context.Context, d QueuedAlert) {
	status, err := a.endpoint.Post(ctx, "OpenBastion-Audit-Service", d.Body)
	if err == nil && status >= 200 && status <= 299 {
		a.forget(ctx, d)
		return
	}
	what := fmt.Sprintf("status %d", status)
	if err != nil {
		what, status = err.Error(), 0
	}
	if !retryable(status) || d.Attempt >= AlertMaxAttempts {
		a.log("audit-service: alert %s (event %s) given up after %d attempt(s) to %s: %s", d.Action, webhook.SafeText(d.EventID), d.Attempt, a.Where(), what)
		a.forget(ctx, d)
		return
	}
	wait := a.retry << (d.Attempt - 1)
	a.log("audit-service: alert %s (event %s) not delivered to %s (%s): attempt %d of %d in %s", d.Action, webhook.SafeText(d.EventID), a.Where(), what, d.Attempt+1, AlertMaxAttempts, wait)
	if err := a.queue.Later(ctx, d.EventID, d.Attempt+1, a.now().Add(wait)); err != nil {
		a.log("audit-service: alert %s (event %s) could not be put back: %v", d.Action, webhook.SafeText(d.EventID), err)
	}
}

func (a *AlertWebhook) forget(ctx context.Context, d QueuedAlert) {
	if err := a.queue.Done(ctx, d.EventID); err != nil {
		a.log("audit-service: alert %s (event %s) could not be removed from the queue: %v", d.Action, webhook.SafeText(d.EventID), err)
	}
}
