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
	"sync"
	"sync/atomic"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

// BatchSender delivers a batch of captured commands to the Command Recorder
// (proto/recording/v1/recording.proto, SessionRecording.StreamCommandEntries).
type BatchSender interface {
	SendBatch(ctx context.Context, entries []proxycore.CommandEntry) error
}

// SendError is a failed delivery, and says whether sending the SAME batch again
// is safe. That is not a detail: the Command Recorder appends, it does not
// deduplicate, so repeating a batch that did reach it records its commands
// twice. Retryable is true only when the batch provably was NOT stored:
//
//   - the connection could not be established (nothing was sent);
//   - the recorder answered 500 or 503. Its own contract makes both mean
//     "not stored": a batch is one transaction and 202 is returned only after
//     it commits. 502 and 504 are NOT in the list — those come from something
//     in front of the recorder, which may have given up while the recorder
//     went on to commit.
//
// Everything else (a timeout after the request was sent, a dropped
// connection, a 4xx) is ambiguous or permanent and is not retried. An
// ambiguous failure can therefore leave a command recorded that the caller
// believes was not — the safe direction for an audit trail — but never the
// other way round.
type SendError struct {
	Err       error
	Retryable bool
}

func (e *SendError) Error() string { return e.Err.Error() }
func (e *SendError) Unwrap() error { return e.Err }

func retryable(err error) bool {
	var se *SendError
	return errors.As(err, &se) && se.Retryable
}

// CommandRecorderHTTPClient is the HTTP/JSON form of that call — the same
// substitution every service-to-service call in this project makes for gRPC
// (see /NOTES_SANDBOX.md).
type CommandRecorderHTTPClient struct {
	BaseURL string
	Client  *http.Client // nil means http.DefaultClient
}

func (c *CommandRecorderHTTPClient) SendBatch(ctx context.Context, entries []proxycore.CommandEntry) error {
	type wireEntry struct {
		SessionID string    `json:"session_id"`
		Timestamp time.Time `json:"ts"`
		Command   string    `json:"command"`
	}
	wire := make([]wireEntry, 0, len(entries))
	for _, e := range entries {
		wire = append(wire, wireEntry{SessionID: e.SessionID, Timestamp: e.Timestamp, Command: e.Command})
	}
	body, err := json.Marshal(map[string]any{"entries": wire})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/recorder/v1/command-entries", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// A failed dial means the request never left; any other transport
		// error may have happened after the recorder received it.
		var op *net.OpError
		return &SendError{Err: err, Retryable: errors.As(err, &op) && op.Op == "dial"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &SendError{
			Err:       fmt.Errorf("command-recorder: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg)),
			Retryable: resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusServiceUnavailable,
		}
	}
	return nil
}

// Ready asks the Command Recorder whether it could take a recording right now
// (GET /readyz: its store is reachable and writable). It is the pre-flight of
// proxycore.RecordingGate; see there for what it does and does not guarantee.
func (c *CommandRecorderHTTPClient) Ready(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("command-recorder not ready: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// SyncRecorder is the proxycore.BatchRecorder for RecordingRequired: it
// returns only once the Command Recorder has accepted the batch, or has
// definitively failed to. It is what makes "recorded before executed" true —
// the Recording Tap holds the operator's Enter until RecordBatch returns.
//
// Two things keep that from being fragile. Each attempt has its own timeout,
// so an unresponsive recorder ends a session in seconds instead of freezing
// it. And a failed attempt is repeated only when the batch provably was not
// stored (SendError.Retryable), so a blip of the recorder's connection costs a
// retry, not a session, while a lost response never turns into a duplicated
// command.
type SyncRecorder struct {
	Sender   BatchSender
	Attempts int           // zero means 2
	Backoff  time.Duration // between attempts; zero means 100ms
	Timeout  time.Duration // per attempt; zero means 3s
}

func (r *SyncRecorder) RecordBatch(ctx context.Context, entries []proxycore.CommandEntry) error {
	attempts, backoff, timeout := r.Attempts, r.Backoff, r.Timeout
	if attempts <= 0 {
		attempts = 2
	}
	if backoff <= 0 {
		backoff = 100 * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		err = r.Sender.SendBatch(attemptCtx, entries)
		cancel()
		if err == nil {
			return nil
		}
		if !retryable(err) || attempt == attempts {
			break
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// AsyncRecorder is the proxycore.Recorder the proxy hands to each session's
// Recording Tap. It decouples the relay from the Command Recorder: Record
// only enqueues — it never blocks on the network — and one worker sends
// queued entries in batches, in order.
//
// If the Recorder is down long enough for the queue to fill, entries are
// DROPPED and counted rather than stalling a live session; every drop is
// logged. That is the existing, documented behaviour of the tap ("a slow or
// unavailable Recorder must never stall an active session"). That is the
// RecordingBestEffort policy. The default, RecordingRequired (ADR-0008),
// refuses sessions it cannot record and does not use this type at all — see
// SyncRecorder.
type AsyncRecorder struct {
	sender    BatchSender
	queue     chan proxycore.CommandEntry
	maxBatch  int
	attempts  int
	backoff   time.Duration
	sendLimit time.Duration

	closeOnce sync.Once
	closed    atomic.Bool
	done      chan struct{}
	dropped   atomic.Int64
}

// NewAsyncRecorder starts the sending worker. queueSize bounds how many
// entries can wait; maxBatch bounds one request.
func NewAsyncRecorder(sender BatchSender, queueSize, maxBatch int) *AsyncRecorder {
	a := &AsyncRecorder{
		sender:    sender,
		queue:     make(chan proxycore.CommandEntry, queueSize),
		maxBatch:  maxBatch,
		attempts:  3,
		backoff:   200 * time.Millisecond,
		sendLimit: 5 * time.Second,
		done:      make(chan struct{}),
	}
	go a.run()
	return a
}

// Record enqueues without blocking. It returns an error only when the entry
// was dropped (queue full, or the recorder is shutting down); the Recording
// Tap ignores that error by design, so the drop counter and log are what
// make a loss visible.
func (a *AsyncRecorder) Record(ctx context.Context, entry proxycore.CommandEntry) error {
	if a.closed.Load() {
		a.drop(1, "recorder is shutting down")
		return fmt.Errorf("async recorder closed")
	}
	select {
	case a.queue <- entry:
		return nil
	default:
		a.drop(1, "queue full")
		return fmt.Errorf("async recorder queue full")
	}
}

// Dropped reports how many entries were lost since start.
func (a *AsyncRecorder) Dropped() int64 { return a.dropped.Load() }

func (a *AsyncRecorder) drop(n int64, why string) {
	total := a.dropped.Add(n)
	// Log the first loss, then every 100th, so an outage is loud without
	// the log itself becoming the next problem.
	if total == n || total%100 < n {
		log.Printf("ssh-proxy: RECORDING GAP — %d command(s) not recorded (%s); %d lost in total", n, why, total)
	}
}

// Close stops accepting entries and waits for the ones already queued to be
// sent, until ctx is done. Call it on shutdown so the last commands of live
// sessions are not lost.
func (a *AsyncRecorder) Close(ctx context.Context) error {
	a.closeOnce.Do(func() {
		a.closed.Store(true)
		close(a.queue)
	})
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *AsyncRecorder) run() {
	defer close(a.done)
	for first := range a.queue {
		batch := []proxycore.CommandEntry{first}
	fill:
		for len(batch) < a.maxBatch {
			select {
			case e, ok := <-a.queue:
				if !ok {
					break fill
				}
				batch = append(batch, e)
			default:
				break fill
			}
		}
		a.send(batch)
	}
}

func (a *AsyncRecorder) send(batch []proxycore.CommandEntry) {
	var err error
	for attempt := 1; attempt <= a.attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), a.sendLimit)
		err = a.sender.SendBatch(ctx, batch)
		cancel()
		if err == nil {
			return
		}
		if attempt < a.attempts {
			time.Sleep(a.backoff * time.Duration(attempt))
		}
	}
	a.drop(int64(len(batch)), fmt.Sprintf("send failed after %d attempts: %v", a.attempts, err))
}
