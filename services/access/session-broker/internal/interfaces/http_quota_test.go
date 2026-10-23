package interfaces_test

// The quota of break-glass requests waiting (ADR-0013) over HTTP: what a client is told
// when its own queue is full (429, with the limit), when the queue could not be counted
// (503, without the cause), and that every other refusal is still the 403 it was.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func bgPost(t *testing.T, svc *application.SessionBrokerService, by string) int {
	t.Helper()
	body := strings.Replace(fmt.Sprintf(bgBody, `,"breakGlass":true`), `"oncall"`, `"`+by+`"`, 1)
	return postSession(t, svc, body).Code
}

func TestPostSessions_AFullQuotaIsA429_WithTheLimit_AndOnlyForTheOneWhoIsFull(t *testing.T) {
	svc := approvalService(allowAuthz{}, quietAudit{}).WithMaxPendingPerRequester(2)

	for i := 0; i < 2; i++ {
		rec := postSession(t, svc, strings.Replace(fmt.Sprintf(bgBody, `,"breakGlass":true`), `"oncall"`, `"alpha"`, 1))
		if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "pending_approval") {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := postSession(t, svc, strings.Replace(fmt.Sprintf(bgBody, `,"breakGlass":true`), `"oncall"`, `"alpha"`, 1))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: %d %q, want 429", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at most 2") || !strings.Contains(rec.Body.String(), "waiting for a decision") {
		t.Fatalf("the 429 does not say why or how many: %q", rec.Body.String())
	}
	// Somebody else is not the one who is full.
	if code := bgPost(t, svc, "beta"); code != http.StatusCreated {
		t.Fatalf("another requester: %d, want 201", code)
	}
}

// The other refusals of a break-glass request are the 403 they always were, and an
// ordinary session is not counted at all.
func TestPostSessions_OtherRefusalsAreStillA403_AndAnOrdinarySessionIsNotCounted(t *testing.T) {
	svc := approvalService(allowAuthz{}, quietAudit{}).WithMaxPendingPerRequester(1)
	if code := bgPost(t, svc, "alpha"); code != http.StatusCreated {
		t.Fatalf("first request: %d", code)
	}
	// A refused request that is not about the quota: a justification that is too short.
	short := strings.Replace(fmt.Sprintf(bgBody, `,"breakGlass":true`), "recorder down, P1 incident", "short", 1)
	short = strings.Replace(short, `"oncall"`, `"beta"`, 1)
	if rec := postSession(t, svc, short); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "waiting for a decision") {
		t.Fatalf("a short justification: %d %q, want a 403 that is not about the quota", rec.Code, rec.Body.String())
	}
	// An ordinary session of the requester whose queue is full.
	ordinary := strings.Replace(fmt.Sprintf(bgBody, ``), `"oncall"`, `"alpha"`, 1)
	if rec := postSession(t, svc, ordinary); rec.Code != http.StatusCreated {
		t.Fatalf("an ordinary session of a requester with a full queue: %d %q", rec.Code, rec.Body.String())
	}
}

type countDownStore struct{ *infrastructure.InMemoryStore }

func (countDownStore) CountPending(context.Context, string, time.Time) (int, error) {
	return 0, errors.New(leak)
}

func TestPostSessions_AQueueThatCannotBeCountedIsA503_WithoutItsCause(t *testing.T) {
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	svc := application.NewSessionBrokerService(countDownStore{infrastructure.NewInMemoryStore()}, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
	rec := postSession(t, svc, fmt.Sprintf(bgBody, `,"breakGlass":true`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d %q, want 503", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.9.8.7") || strings.Contains(rec.Body.String(), "dial tcp") {
		t.Fatalf("the cause reached the client: %q", rec.Body.String())
	}
	if !strings.Contains(logged.String(), "10.9.8.7") {
		t.Fatalf("the cause is not in the Broker's own log: %q", logged.String())
	}
}
