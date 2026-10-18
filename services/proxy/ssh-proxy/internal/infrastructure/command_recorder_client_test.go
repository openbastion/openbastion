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

// -- record-or-refuse (ADR-0008) ----------------------------------------------------

// classifiedSender returns scripted errors, in order, then succeeds.
type classifiedSender struct {
	mu    sync.Mutex
	errs  []error
	calls int
	got   [][]proxycore.CommandEntry
}

func (c *classifiedSender) SendBatch(ctx context.Context, entries []proxycore.CommandEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(c.errs) > 0 {
		err := c.errs[0]
		c.errs = c.errs[1:]
		return err
	}
	c.got = append(c.got, entries)
	return nil
}

func notStored() error { return &SendError{Err: errors.New("connection refused"), Retryable: true} }
func ambiguous() error { return &SendError{Err: errors.New("EOF after sending"), Retryable: false} }

func TestSyncRecorder_ReturnsOnlyAfterTheRecorderAccepted(t *testing.T) {
	s := &classifiedSender{}
	r := &SyncRecorder{Sender: s}
	if err := r.RecordBatch(context.Background(), []proxycore.CommandEntry{entryFor("ls")}); err != nil {
		t.Fatalf("RecordBatch: %v", err)
	}
	if s.calls != 1 || len(s.got) != 1 {
		t.Fatalf("calls=%d stored=%d", s.calls, len(s.got))
	}
}

// A blip of the recorder's connection costs a retry, not the operator's session.
func TestSyncRecorder_RetriesWhenTheBatchWasProvablyNotStored(t *testing.T) {
	s := &classifiedSender{errs: []error{notStored()}}
	r := &SyncRecorder{Sender: s, Backoff: time.Millisecond}
	if err := r.RecordBatch(context.Background(), []proxycore.CommandEntry{entryFor("ls")}); err != nil {
		t.Fatalf("RecordBatch: %v", err)
	}
	if s.calls != 2 || len(s.got) != 1 {
		t.Fatalf("expected one retry then success: calls=%d stored=%d", s.calls, len(s.got))
	}
}

// The reverse matters more: when the batch MAY have been stored, sending it
// again would record the command twice, so the failure is final.
func TestSyncRecorder_DoesNotRetryAnAmbiguousFailure(t *testing.T) {
	s := &classifiedSender{errs: []error{ambiguous()}}
	r := &SyncRecorder{Sender: s, Backoff: time.Millisecond}
	if err := r.RecordBatch(context.Background(), []proxycore.CommandEntry{entryFor("ls")}); err == nil {
		t.Fatal("expected the failure to be reported")
	}
	if s.calls != 1 {
		t.Fatalf("an ambiguous failure was retried (%d calls): the command could be recorded twice", s.calls)
	}
}

func TestSyncRecorder_DoesNotRetryAnUnclassifiedError(t *testing.T) {
	s := &classifiedSender{errs: []error{errors.New("something else")}}
	r := &SyncRecorder{Sender: s, Backoff: time.Millisecond}
	if err := r.RecordBatch(context.Background(), nil); err == nil || s.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, s.calls)
	}
}

func TestSyncRecorder_GivesUpAfterItsAttempts(t *testing.T) {
	s := &classifiedSender{errs: []error{notStored(), notStored(), notStored()}}
	r := &SyncRecorder{Sender: s, Attempts: 2, Backoff: time.Millisecond}
	if err := r.RecordBatch(context.Background(), []proxycore.CommandEntry{entryFor("ls")}); err == nil {
		t.Fatal("expected an error once the attempts are used up")
	}
	if s.calls != 2 || len(s.got) != 0 {
		t.Fatalf("calls=%d stored=%d", s.calls, len(s.got))
	}
}

// An unresponsive recorder ends the session in seconds; it must not freeze it.
func TestSyncRecorder_ABlockedRecorderIsCutOffByThePerAttemptTimeout(t *testing.T) {
	r := &SyncRecorder{Sender: &fakeSender{block: make(chan struct{})}, Timeout: 50 * time.Millisecond}
	start := time.Now()
	err := r.RecordBatch(context.Background(), []proxycore.CommandEntry{entryFor("ls")})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

func TestSyncRecorder_StopsWhenTheCallerGivesUp(t *testing.T) {
	s := &classifiedSender{errs: []error{notStored(), notStored()}}
	r := &SyncRecorder{Sender: s, Attempts: 5, Backoff: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := r.RecordBatch(ctx, []proxycore.CommandEntry{entryFor("ls")}); err == nil {
		t.Fatal("expected an error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the backoff ignored the caller's context (%v)", time.Since(start))
	}
}

// What the HTTP client classifies as safe to repeat, against a real server.
func TestCommandRecorderHTTPClient_ClassifiesFailuresBySafetyToRetry(t *testing.T) {
	entries := []proxycore.CommandEntry{entryFor("ls")}
	status := http.StatusAccepted
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	c := &CommandRecorderHTTPClient{BaseURL: srv.URL}

	for code, want := range map[int]bool{
		http.StatusInternalServerError: true,  // the recorder's own "store failed, rolled back"
		http.StatusServiceUnavailable:  true,  // nothing in front accepted it
		http.StatusBadGateway:          false, // something in front may have forwarded it
		http.StatusGatewayTimeout:      false, // ... and the recorder may have gone on to commit
		http.StatusBadRequest:          false, // permanent
		http.StatusForbidden:           false,
	} {
		status = code
		err := c.SendBatch(context.Background(), entries)
		if err == nil {
			t.Fatalf("status %d must be an error", code)
		}
		if retryable(err) != want {
			t.Errorf("status %d: retryable=%v, want %v", code, retryable(err), want)
		}
	}

	t.Run("a refused connection is safe to repeat: nothing was sent", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		url := dead.URL
		dead.Close()
		err := (&CommandRecorderHTTPClient{BaseURL: url}).SendBatch(context.Background(), entries)
		if err == nil || !retryable(err) {
			t.Fatalf("a failed dial must be retryable, got %v (retryable=%v)", err, retryable(err))
		}
	})

	t.Run("a recorder that takes the request and never answers is NOT safe to repeat", func(t *testing.T) {
		hang := make(chan struct{})
		slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-hang }))
		defer slow.Close()
		defer close(hang)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		err := (&CommandRecorderHTTPClient{BaseURL: slow.URL}).SendBatch(ctx, entries)
		if err == nil {
			t.Fatal("expected a timeout")
		}
		if retryable(err) {
			t.Fatal("a timeout after the request was sent is ambiguous — repeating it could record the command twice")
		}
	})
}

func TestCommandRecorderHTTPClient_Ready(t *testing.T) {
	status := http.StatusOK
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(status)
	}))
	c := &CommandRecorderHTTPClient{BaseURL: srv.URL}

	if err := c.Ready(context.Background()); err != nil || gotPath != "/readyz" {
		t.Fatalf("ready recorder: err=%v path=%q", err, gotPath)
	}
	status = http.StatusServiceUnavailable
	if err := c.Ready(context.Background()); err == nil {
		t.Fatal("a 503 must mean not ready")
	}
	srv.Close()
	if err := c.Ready(context.Background()); err == nil {
		t.Fatal("an unreachable recorder must mean not ready")
	}
}
