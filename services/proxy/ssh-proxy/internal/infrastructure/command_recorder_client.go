package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("command-recorder: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// AsyncRecorder is the proxycore.Recorder the proxy hands to each session's
// Recording Tap. It decouples the relay from the Command Recorder: Record
// only enqueues — it never blocks on the network — and one worker sends
// queued entries in batches, in order.
//
// If the Recorder is down long enough for the queue to fill, entries are
// DROPPED and counted rather than stalling a live session; every drop is
// logged. That is the existing, documented behaviour of the tap ("a slow or
// unavailable Recorder must never stall an active session"). Whether the
// proxy should instead refuse sessions it cannot record — fail closed — is a
// policy decision, listed as open in NOTES_SANDBOX.md.
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
