package infrastructure_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/webhook"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

// queues gives each test the two AlertQueue, the PostgreSQL one emptied before and after (it is
// skipped without TEST_DATABASE_URL, like the other PostgreSQL tests of this package).
func queues(t *testing.T) map[string]func(t *testing.T) infrastructure.AlertQueue {
	return map[string]func(t *testing.T) infrastructure.AlertQueue{
		"memory": func(*testing.T) infrastructure.AlertQueue { return infrastructure.NewMemoryAlertQueue() },
		"postgres": func(t *testing.T) infrastructure.AlertQueue {
			db := testDB(t)
			empty := func() {
				if _, err := db.Exec(`DELETE FROM alert_outbox`); err != nil {
					t.Fatal(err)
				}
			}
			empty()
			t.Cleanup(empty)
			return infrastructure.NewPostgresAlertQueue(db)
		},
	}
}

func TestAlertQueue_WhatIsDueComesEarliestFirst_PutBackComesLater_DoneIsGone(t *testing.T) {
	for name, open := range queues(t) {
		t.Run(name, func(t *testing.T) {
			q, ctx := open(t), context.Background()
			t0 := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
			if next, err := q.Next(ctx); err != nil || !next.IsZero() {
				t.Fatalf("an empty queue: next %v, %v", next, err)
			}
			for i, at := range []time.Duration{3, 1, 2, 10} { // minutes after t0
				kept, err := q.Put(ctx, infrastructure.QueuedAlert{EventID: fmt.Sprintf("evt_%d", i), Action: "vault.rotation_overdue",
					Body: []byte(fmt.Sprintf(`{"n":%d}`, i)), Attempt: 1, Due: t0.Add(at * time.Minute)})
				if err != nil || !kept {
					t.Fatalf("put %d: %v, %v", i, kept, err)
				}
			}
			if next, err := q.Next(ctx); err != nil || !next.Equal(t0.Add(time.Minute)) {
				t.Fatalf("next %v, %v; want %v", next, err, t0.Add(time.Minute))
			}
			due, err := q.Due(ctx, t0.Add(3*time.Minute), 16)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, d := range due {
				ids = append(ids, d.EventID)
			}
			if fmt.Sprint(ids) != "[evt_1 evt_2 evt_0]" {
				t.Fatalf("due at +3m: %v, want the three due, the earliest first", ids)
			}
			if d := due[0]; d.Action != "vault.rotation_overdue" || string(d.Body) != `{"n":1}` || d.Attempt != 1 || !d.Due.Equal(t0.Add(time.Minute)) {
				t.Fatalf("a due alert is not what was put: %+v", d)
			}
			if due, _ := q.Due(ctx, t0.Add(3*time.Minute), 2); len(due) != 2 {
				t.Fatalf("at most n: %d", len(due))
			}

			if err := q.Later(ctx, "evt_1", 2, t0.Add(20*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if err := q.Done(ctx, "evt_2"); err != nil {
				t.Fatal(err)
			}
			due, _ = q.Due(ctx, t0.Add(10*time.Minute), 16)
			ids = nil
			for _, d := range due {
				ids = append(ids, d.EventID)
			}
			if fmt.Sprint(ids) != "[evt_0 evt_3]" {
				t.Fatalf("due at +10m after Later(evt_1) and Done(evt_2): %v", ids)
			}
			due, _ = q.Due(ctx, t0.Add(20*time.Minute), 16)
			if last := due[len(due)-1]; last.EventID != "evt_1" || last.Attempt != 2 || !last.Due.Equal(t0.Add(20*time.Minute)) {
				t.Fatalf("an alert put back keeps its attempt and its new time: %+v", last)
			}
		})
	}
}

func TestAlertQueue_AnEventIsKeptOnce_AndNoMoreThanTheBound(t *testing.T) {
	for name, open := range queues(t) {
		t.Run(name, func(t *testing.T) {
			q, ctx, now := open(t), context.Background(), time.Now()
			for i := 0; i < infrastructure.AlertMaxOutstanding; i++ {
				if kept, err := q.Put(ctx, infrastructure.QueuedAlert{EventID: fmt.Sprintf("evt_%03d", i), Action: "a", Body: []byte("{}"), Attempt: 1, Due: now}); err != nil || !kept {
					t.Fatalf("put %d: %v, %v", i, kept, err)
				}
			}
			// The same event again: already kept, so it says true, and it does not change what is kept.
			if kept, err := q.Put(ctx, infrastructure.QueuedAlert{EventID: "evt_000", Action: "other", Body: []byte(`{"x":1}`), Attempt: 1, Due: now}); err != nil || !kept {
				t.Fatalf("the same event again: %v, %v", kept, err)
			}
			if kept, err := q.Put(ctx, infrastructure.QueuedAlert{EventID: "evt_one_more", Action: "a", Body: []byte("{}"), Attempt: 1, Due: now}); err != nil || kept {
				t.Fatalf("one more than %d: kept %v, %v", infrastructure.AlertMaxOutstanding, kept, err)
			}
			due, err := q.Due(ctx, now, 1000)
			if err != nil || len(due) != infrastructure.AlertMaxOutstanding {
				t.Fatalf("kept %d, %v; want %d", len(due), err, infrastructure.AlertMaxOutstanding)
			}
			for _, d := range due {
				if d.EventID == "evt_000" && (d.Action != "a" || string(d.Body) != "{}") {
					t.Fatalf("an event put twice was changed: %+v", d)
				}
			}
			// Once one is done, there is room again.
			if err := q.Done(ctx, "evt_007"); err != nil {
				t.Fatal(err)
			}
			if kept, err := q.Put(ctx, infrastructure.QueuedAlert{EventID: "evt_one_more", Action: "a", Body: []byte("{}"), Attempt: 1, Due: now}); err != nil || !kept {
				t.Fatalf("after one is done: %v, %v", kept, err)
			}
		})
	}
}

// ADR-0057: what a queue in alert_outbox holds when the Audit Service stops — an alert waiting
// for a retry — is delivered by the next one, at the attempt it had reached; the process restart
// itself is played by TestPostgresFlow_AnAlertWaitingForARetryIsDeliveredAfterTheAuditServiceRestarts.
func TestAlertWebhook_WhatAQueueAlreadyHoldsIsDelivered_AtTheAttemptItHadReached(t *testing.T) {
	r := newReceiver(t, 503, 204)
	e, err := webhook.New(r.srv.URL + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WithSecret(alertSecret); err != nil {
		t.Fatal(err)
	}
	for name, open := range queues(t) {
		t.Run(name, func(t *testing.T) {
			q, ctx := open(t), context.Background()
			if _, err := q.Put(ctx, infrastructure.QueuedAlert{EventID: "evt_waiting", Action: "vault.rotation_overdue", Body: []byte(`{"eventId":"evt_waiting"}`),
				Attempt: 4, Due: time.Now()}); err != nil {
				t.Fatal(err)
			}
			before := r.count()
			a, err := infrastructure.NewAlertWebhookWithQueue(e, 10*time.Millisecond, q)
			if err != nil {
				t.Fatal(err)
			}
			l := &logs{}
			a.WithLogf(l.logf)
			eventually(t, "the alert waiting delivered", func() bool { return r.count() == before+2 })
			r.mu.Lock()
			body := string(r.bodies[before+1])
			r.mu.Unlock()
			if body != `{"eventId":"evt_waiting"}` {
				t.Fatalf("delivered %q", body)
			}
			eventually(t, "the queue emptied", func() bool { next, _ := q.Next(ctx); return next.IsZero() })
			r.mu.Lock()
			r.bodies, r.statuses = r.bodies[:0], []int{503, 204} // the next subtest starts the script again
			r.mu.Unlock()
		})
	}
}

// An alert written while the worker waits — the queue was empty, or its next retry is far — is
// pushed at once, not at the next look.
func TestAlertWebhook_AnAlertWrittenWhileTheWorkerWaitsIsPushedAtOnce(t *testing.T) {
	r := newReceiver(t, 204)
	a, _ := alertWebhook(t, r.srv.URL+"/hook", time.Second)
	time.Sleep(100 * time.Millisecond) // the worker has looked at the empty queue, and waits
	start := time.Now()
	a.Notify(context.Background(), overdue("evt_later", "acc_db"))
	eventually(t, "the delivery", func() bool { return r.count() == 1 })
	if d := time.Since(start); d > time.Second {
		t.Fatalf("delivered %s after it was written", d)
	}
}
