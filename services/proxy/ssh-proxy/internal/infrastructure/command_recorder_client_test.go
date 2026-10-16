package infrastructure

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

type fakeSender struct {
	mu      sync.Mutex
	batches [][]proxycore.CommandEntry
	failFor int           // fail this many calls, then succeed
	block   chan struct{} // if non-nil, SendBatch waits for it to be closed
	calls   int
}

func (f *fakeSender) SendBatch(ctx context.Context, entries []proxycore.CommandEntry) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failFor > 0 {
		f.failFor--
		return errors.New("recorder unavailable")
	}
	f.batches = append(f.batches, append([]proxycore.CommandEntry(nil), entries...))
	return nil
}

func (f *fakeSender) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, b := range f.batches {
		for _, e := range b {
			out = append(out, e.Command)
		}
	}
	return out
}

func entryFor(cmd string) proxycore.CommandEntry {
	return proxycore.CommandEntry{SessionID: "s1", Timestamp: time.Now().UTC(), Command: cmd}
}

func closeWithin(t *testing.T, a *AsyncRecorder) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestAsyncRecorder_DeliversEveryEntryInOrderAndCloseDrains(t *testing.T) {
	sender := &fakeSender{}
	a := NewAsyncRecorder(sender, 100, 10)
	for _, c := range []string{"a", "b", "c", "d", "e"} {
		if err := a.Record(context.Background(), entryFor(c)); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	closeWithin(t, a)

	got := sender.all()
	if want := "abcde"; len(got) != 5 || got[0]+got[1]+got[2]+got[3]+got[4] != want {
		t.Fatalf("want %q in order, got %q", want, got)
	}
	if a.Dropped() != 0 {
		t.Fatalf("nothing should have been dropped, got %d", a.Dropped())
	}
}

func TestAsyncRecorder_BatchesQueuedEntries(t *testing.T) {
	// A blocked sender lets the queue build up; once released, what was
	// queued goes out in batches no larger than maxBatch.
	sender := &fakeSender{block: make(chan struct{})}
	a := NewAsyncRecorder(sender, 100, 3)
	for i := 0; i < 8; i++ {
		_ = a.Record(context.Background(), entryFor(string(rune('a'+i))))
	}
	close(sender.block)
	closeWithin(t, a)

	sender.mu.Lock()
	defer sender.mu.Unlock()
	total := 0
	for _, b := range sender.batches {
		if len(b) > 3 {
			t.Fatalf("batch of %d exceeds maxBatch 3", len(b))
		}
		total += len(b)
	}
	if total != 8 {
		t.Fatalf("expected 8 entries delivered, got %d", total)
	}
}

// The whole point of the async wrapper: a recorder that hangs must not make
// Record block, because Record runs inside a live session's relay.
func TestAsyncRecorder_RecordNeverBlocksWhenTheRecorderHangsAndCountsDrops(t *testing.T) {
	sender := &fakeSender{block: make(chan struct{})}
	a := NewAsyncRecorder(sender, 2, 1)
	defer func() { close(sender.block); closeWithin(t, a) }()

	finished := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			_ = a.Record(context.Background(), entryFor("x"))
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked on a hung recorder")
	}
	// The worker holds 1 (blocked in send) and the queue holds 2: the rest are lost, and counted.
	if a.Dropped() < 40 {
		t.Fatalf("expected most of 50 entries dropped and counted, got %d", a.Dropped())
	}
}

func TestAsyncRecorder_RetriesATransientFailure(t *testing.T) {
	sender := &fakeSender{failFor: 2}
	a := NewAsyncRecorder(sender, 10, 10)
	a.backoff = time.Millisecond
	_ = a.Record(context.Background(), entryFor("survives"))
	closeWithin(t, a)

	if got := sender.all(); len(got) != 1 || got[0] != "survives" {
		t.Fatalf("expected the entry delivered after retries, got %q", got)
	}
	if a.Dropped() != 0 {
		t.Fatalf("a recovered failure must not count as a loss, got %d", a.Dropped())
	}
}

func TestAsyncRecorder_ExhaustedRetriesDropAndCountThenRecover(t *testing.T) {
	sender := &fakeSender{failFor: 3} // exactly the 3 attempts for the first batch
	a := NewAsyncRecorder(sender, 10, 1)
	a.backoff = time.Millisecond
	_ = a.Record(context.Background(), entryFor("lost"))
	// Wait until the first batch has been given up on before sending the next.
	deadline := time.Now().Add(2 * time.Second)
	for a.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_ = a.Record(context.Background(), entryFor("kept"))
	closeWithin(t, a)

	if a.Dropped() != 1 {
		t.Fatalf("expected exactly the first entry counted as lost, got %d", a.Dropped())
	}
	if got := sender.all(); len(got) != 1 || got[0] != "kept" {
		t.Fatalf("the worker must keep going after a loss; delivered %q", got)
	}
}

func TestAsyncRecorder_RecordAfterCloseIsRefusedNotPanicking(t *testing.T) {
	a := NewAsyncRecorder(&fakeSender{}, 10, 10)
	closeWithin(t, a)
	if err := a.Record(context.Background(), entryFor("late")); err == nil {
		t.Fatal("expected an error recording after Close")
	}
	if a.Dropped() != 1 {
		t.Fatalf("the late entry should be counted as lost, got %d", a.Dropped())
	}
	closeWithin(t, a) // closing twice is harmless
}

func TestCommandRecorderHTTPClient_SendsTheContractShapeAndChecksTheStatus(t *testing.T) {
	var gotPath string
	var gotBody struct {
		Entries []struct {
			SessionID string    `json:"session_id"`
			Ts        time.Time `json:"ts"`
			Command   string    `json:"command"`
		} `json:"entries"`
	}
	status := http.StatusAccepted
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(status)
	}))
	defer srv.Close()

	c := &CommandRecorderHTTPClient{BaseURL: srv.URL}
	now := time.Now().UTC()
	if err := c.SendBatch(context.Background(), []proxycore.CommandEntry{{SessionID: "s9", Timestamp: now, Command: "uptime"}}); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if gotPath != "/recorder/v1/command-entries" || len(gotBody.Entries) != 1 ||
		gotBody.Entries[0].SessionID != "s9" || gotBody.Entries[0].Command != "uptime" || !gotBody.Entries[0].Ts.Equal(now) {
		t.Fatalf("unexpected request: path=%q body=%+v", gotPath, gotBody)
	}

	status = http.StatusBadRequest
	if err := c.SendBatch(context.Background(), []proxycore.CommandEntry{{SessionID: "s9", Timestamp: now, Command: "x"}}); err == nil {
		t.Fatal("a non-202 answer must be an error")
	}
}
