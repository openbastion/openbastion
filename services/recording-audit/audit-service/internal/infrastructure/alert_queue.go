package infrastructure

// Where the alerts wait to be pushed (ADR-0057): in memory without a database, in alert_outbox with one.

import (
	"context"
	"database/sql"
	"sort"
	"sync"
	"time"
)

// QueuedAlert is one alert waiting to be pushed.
type QueuedAlert struct {
	EventID, Action string
	Body            []byte
	Attempt         int       // the attempt about to be made, from 1
	Due             time.Time // when it is to be made
}

// AlertQueue keeps the alerts waiting to be pushed, at most AlertMaxOutstanding of them.
type AlertQueue interface {
	// Put keeps a new alert; false when AlertMaxOutstanding are already kept. An alert already
	// kept (the same event) is not kept twice, and Put says true.
	Put(ctx context.Context, a QueuedAlert) (bool, error)
	// Due returns up to n alerts whose time has come, the earliest first.
	Due(ctx context.Context, now time.Time, n int) ([]QueuedAlert, error)
	// Later puts an alert back, for attempt at due.
	Later(ctx context.Context, eventID string, attempt int, due time.Time) error
	// Done forgets an alert: delivered, or given up.
	Done(ctx context.Context, eventID string) error
	// Next is when the earliest kept alert is due; zero when none is kept.
	Next(ctx context.Context) (time.Time, error)
}

// MemoryAlertQueue is an AlertQueue in this process: what ADR-0045 had, lost at a restart.
type MemoryAlertQueue struct {
	mu     sync.Mutex
	alerts map[string]QueuedAlert
}

func NewMemoryAlertQueue() *MemoryAlertQueue {
	return &MemoryAlertQueue{alerts: map[string]QueuedAlert{}}
}

func (q *MemoryAlertQueue) Put(_ context.Context, a QueuedAlert) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, kept := q.alerts[a.EventID]; kept {
		return true, nil
	}
	if len(q.alerts) >= AlertMaxOutstanding {
		return false, nil
	}
	q.alerts[a.EventID] = a
	return true, nil
}

func (q *MemoryAlertQueue) Due(_ context.Context, now time.Time, n int) ([]QueuedAlert, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []QueuedAlert
	for _, a := range q.alerts {
		if !a.Due.After(now) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Due.Before(out[j].Due) })
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (q *MemoryAlertQueue) Later(_ context.Context, eventID string, attempt int, due time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if a, kept := q.alerts[eventID]; kept {
		a.Attempt, a.Due = attempt, due
		q.alerts[eventID] = a
	}
	return nil
}

func (q *MemoryAlertQueue) Done(_ context.Context, eventID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.alerts, eventID)
	return nil
}

func (q *MemoryAlertQueue) Next(_ context.Context) (time.Time, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var next time.Time
	for _, a := range q.alerts {
		if next.IsZero() || a.Due.Before(next) {
			next = a.Due
		}
	}
	return next, nil
}

// PostgresAlertQueue is an AlertQueue in alert_outbox (ADR-0057): what waits survives a restart.
type PostgresAlertQueue struct{ db *sql.DB }

func NewPostgresAlertQueue(db *sql.DB) *PostgresAlertQueue { return &PostgresAlertQueue{db: db} }

func (q *PostgresAlertQueue) Put(ctx context.Context, a QueuedAlert) (bool, error) {
	var kept, total int
	if err := q.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE event_id = $1), count(*) FROM alert_outbox`, a.EventID).Scan(&kept, &total); err != nil {
		return false, err
	}
	if kept > 0 {
		return true, nil
	}
	if total >= AlertMaxOutstanding {
		return false, nil
	}
	_, err := q.db.ExecContext(ctx, `INSERT INTO alert_outbox (event_id, action, body, attempt, due_at) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (event_id) DO NOTHING`, a.EventID, a.Action, a.Body, a.Attempt, a.Due.UTC())
	return err == nil, err
}

func (q *PostgresAlertQueue) Due(ctx context.Context, now time.Time, n int) ([]QueuedAlert, error) {
	rows, err := q.db.QueryContext(ctx, `SELECT event_id, action, body, attempt, due_at FROM alert_outbox
		WHERE due_at <= $1 ORDER BY due_at, event_id LIMIT $2`, now.UTC(), n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueuedAlert
	for rows.Next() {
		var a QueuedAlert
		if err := rows.Scan(&a.EventID, &a.Action, &a.Body, &a.Attempt, &a.Due); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (q *PostgresAlertQueue) Later(ctx context.Context, eventID string, attempt int, due time.Time) error {
	_, err := q.db.ExecContext(ctx, `UPDATE alert_outbox SET attempt = $2, due_at = $3 WHERE event_id = $1`, eventID, attempt, due.UTC())
	return err
}

func (q *PostgresAlertQueue) Done(ctx context.Context, eventID string) error {
	_, err := q.db.ExecContext(ctx, `DELETE FROM alert_outbox WHERE event_id = $1`, eventID)
	return err
}

func (q *PostgresAlertQueue) Next(ctx context.Context) (time.Time, error) {
	var next sql.NullTime
	if err := q.db.QueryRowContext(ctx, `SELECT min(due_at) FROM alert_outbox`).Scan(&next); err != nil {
		return time.Time{}, err
	}
	return next.Time, nil
}
