package proxycore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type captureRecorder struct {
	entries []CommandEntry
}

func (c *captureRecorder) Record(ctx context.Context, entry CommandEntry) error {
	c.entries = append(c.entries, entry)
	return nil
}

func TestRecordingTap_ExtractsCompleteLinesOnly(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "session-123")

	_, _ = tap.Write([]byte("ls -la\nwhoami\npartial"))

	if len(rec.entries) != 2 {
		t.Fatalf("expected 2 recorded commands, got %d: %+v", len(rec.entries), rec.entries)
	}
	if rec.entries[0].Command != "ls -la" || rec.entries[1].Command != "whoami" {
		t.Fatalf("unexpected commands: %+v", rec.entries)
	}
}

func TestRecordingTap_HandlesWritesSplitAcrossCalls(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "session-123")

	_, _ = tap.Write([]byte("cat /etc/pass"))
	_, _ = tap.Write([]byte("wd\n"))

	if len(rec.entries) != 1 || rec.entries[0].Command != "cat /etc/passwd" {
		t.Fatalf("expected a single reassembled command, got %+v", rec.entries)
	}
}

// A real interactive SSH client with a PTY sends '\r' for Enter, never '\n'.
// The two tests above only pass because they hand-feed '\n'.
func TestRecordingTap_InteractiveEnterIsCarriageReturn(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "session-123")

	_, _ = tap.Write([]byte("whoami\r"))

	if len(rec.entries) != 1 || rec.entries[0].Command != "whoami" {
		t.Fatalf("a command terminated by \\r must be recorded, got %+v", rec.entries)
	}
}

func commands(entries []CommandEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Command)
	}
	return out
}

func assertCommands(t *testing.T, rec *captureRecorder, want ...string) {
	t.Helper()
	got := commands(rec.entries)
	if len(got) != len(want) {
		t.Fatalf("expected %q, got %q", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %q, got %q", want, got)
		}
	}
}

func TestRecordingTap_CRLFIsASingleTerminator(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("ls\r\npwd\r\n"))
	assertCommands(t, rec, "ls", "pwd")
}

func TestRecordingTap_CRThenLFSplitAcrossWritesIsASingleTerminator(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("ls\r"))
	_, _ = tap.Write([]byte("\npwd\r"))
	assertCommands(t, rec, "ls", "pwd")
}

func TestRecordingTap_BlankLinesAreNotRecorded(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("\r\r  \rls\r"))
	assertCommands(t, rec, "ls")
}

func TestRecordingTap_BackspaceEditsTheLine(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("lss\x7f -la\r"))
	_, _ = tap.Write([]byte("cat xx\x08\x08y\r"))
	assertCommands(t, rec, "ls -la", "cat y")
}

func TestRecordingTap_BackspaceRemovesAWholeMultibyteRune(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("echo é\x7fe\r"))
	assertCommands(t, rec, "echo e")
}

func TestRecordingTap_BackspaceOnAnEmptyLineIsHarmless(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("\x7f\x7fls\r"))
	assertCommands(t, rec, "ls")
}

func TestRecordingTap_CtrlCAndCtrlUDiscardTheLine(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("rm -rf /\x03"))
	_, _ = tap.Write([]byte("rm -rf /tmp/x\x15whoami\r"))
	assertCommands(t, rec, "whoami")
}

func TestRecordingTap_CtrlWDeletesTheLastWord(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("cat /etc/shadow\x17passwd\r"))
	assertCommands(t, rec, "cat passwd")
}

func TestRecordingTap_EscapeSequencesAreDropped(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	// Up arrow, Left arrow (CSI), SS3 Down arrow, then the real text.
	_, _ = tap.Write([]byte("\x1b[A\x1b[D\x1bOBls\r"))
	// Bracketed paste markers around a pasted command.
	_, _ = tap.Write([]byte("\x1b[200~uname -a\x1b[201~\r"))
	assertCommands(t, rec, "ls", "uname -a")
}

func TestRecordingTap_EscapeSequenceSplitAcrossWrites(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("l\x1b"))
	_, _ = tap.Write([]byte("["))
	_, _ = tap.Write([]byte("1;5C"))
	_, _ = tap.Write([]byte("s\r"))
	assertCommands(t, rec, "ls")
}

func TestRecordingTap_TabAndOtherControlBytesAreNotPartOfTheCommand(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("ca\tt\x01 f\x04ile\r"))
	assertCommands(t, rec, "cat file")
}

func TestRecordingTap_OverlongLineIsTruncatedNotUnbounded(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Write(append(make([]byte, 0), []byte(strings.Repeat("a", maxLineBytes*3))...))
	_, _ = tap.Write([]byte("\r"))
	if len(rec.entries) != 1 || len(rec.entries[0].Command) != maxLineBytes {
		t.Fatalf("expected one entry truncated to %d bytes, got %d entries (first len %d)", maxLineBytes, len(rec.entries), len(rec.entries[0].Command))
	}
}

func TestRecordingTap_InputAtASecretPromptIsRedactedNotStored(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")

	_, _ = tap.Write([]byte("sudo -s\r"))
	_, _ = tap.Output().Write([]byte("[sudo] password for bob: "))
	_, _ = tap.Write([]byte("hunter2\r"))
	_, _ = tap.Output().Write([]byte("\r\nroot@host:~# "))
	_, _ = tap.Write([]byte("id\r"))

	assertCommands(t, rec, "sudo -s", RedactedSecretInput, "id")
	for _, e := range rec.entries {
		if strings.Contains(e.Command, "hunter2") {
			t.Fatalf("the secret was stored: %+v", e)
		}
	}
}

func TestRecordingTap_SecretPromptSplitAcrossOutputChunks(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Output().Write([]byte("Enter passph"))
	_, _ = tap.Output().Write([]byte("rase for key '/home/bob/.ssh/id_ed25519': "))
	_, _ = tap.Write([]byte("correct horse\r"))
	assertCommands(t, rec, RedactedSecretInput)
}

func TestRecordingTap_OrdinaryPromptsAreNotTreatedAsSecretPrompts(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Output().Write([]byte("bob@host:~$ "))
	_, _ = tap.Write([]byte("ls\r"))
	// "password" appears, but not at the end of the current line.
	_, _ = tap.Output().Write([]byte("Last password change: never\r\nbob@host:~$ "))
	_, _ = tap.Write([]byte("whoami\r"))
	assertCommands(t, rec, "ls", "whoami")
}

func TestRecordingTap_OnlyTheNextLineIsRedacted(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Output().Write([]byte("Password: "))
	_, _ = tap.Write([]byte("s3cret\r"))
	_, _ = tap.Write([]byte("ls\r"))
	assertCommands(t, rec, RedactedSecretInput, "ls")
}

func TestRecordingTap_AnUnansweredSecretPromptDoesNotSwallowALaterCommand(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	// The prompt appears, the target then moves on (timeout) — a new output
	// line makes the prompt stale — and the operator types a real command.
	_, _ = tap.Output().Write([]byte("Password: "))
	_, _ = tap.Output().Write([]byte("\r\nsudo: timed out\r\nbob@host:~$ "))
	_, _ = tap.Write([]byte("ls\r"))
	assertCommands(t, rec, "ls")
}

func TestRecordingTap_CtrlCCancelsAPendingSecretPrompt(t *testing.T) {
	rec := &captureRecorder{}
	tap := NewRecordingTap(rec, "s")
	_, _ = tap.Output().Write([]byte("Password: "))
	_, _ = tap.Write([]byte("\x03"))
	_, _ = tap.Write([]byte("ls\r"))
	assertCommands(t, rec, "ls")
}

// A recorder that blocks must not hold the tap's lock: the output side of
// the relay shares it, and a stalled recorder would otherwise stall the
// session.
type blockingRecorder struct{ release chan struct{} }

func (b *blockingRecorder) Record(ctx context.Context, entry CommandEntry) error {
	<-b.release
	return nil
}

func TestRecordingTap_SlowRecorderDoesNotBlockTheOutputObserver(t *testing.T) {
	rec := &blockingRecorder{release: make(chan struct{})}
	tap := NewRecordingTap(rec, "s")

	writeDone := make(chan struct{})
	go func() {
		_, _ = tap.Write([]byte("ls\r"))
		close(writeDone)
	}()

	observed := make(chan struct{})
	go func() {
		// Give the Write goroutine time to reach Record and block there.
		time.Sleep(50 * time.Millisecond)
		_, _ = tap.Output().Write([]byte("output\r\n"))
		close(observed)
	}()

	select {
	case <-observed:
	case <-time.After(2 * time.Second):
		t.Fatal("the output observer was blocked by a slow recorder")
	}
	close(rec.release)
	<-writeDone
}

// -- required mode (ADR-0008) -----------------------------------------------------

// scriptedBatchRecorder records the batches it is given and can be made to
// fail, or to hold a call until released.
type scriptedBatchRecorder struct {
	batches [][]CommandEntry
	err     error
	release chan struct{} // if set, RecordBatch blocks until it is closed
}

func (r *scriptedBatchRecorder) RecordBatch(ctx context.Context, entries []CommandEntry) error {
	if r.release != nil {
		<-r.release
	}
	if r.err != nil {
		return r.err
	}
	r.batches = append(r.batches, append([]CommandEntry(nil), entries...))
	return nil
}

func (r *scriptedBatchRecorder) commands() []string {
	var out []string
	for _, b := range r.batches {
		for _, e := range b {
			out = append(out, e.Command)
		}
	}
	return out
}

// The enforcement point: the line is acknowledged BEFORE Write returns, which
// is before the relay forwards the Enter that would run it.
func TestRequiredTap_WaitsForTheAcknowledgementBeforeReturning(t *testing.T) {
	rec := &scriptedBatchRecorder{release: make(chan struct{})}
	tap := NewRequiredRecordingTap(rec, "s")

	returned := make(chan struct{})
	go func() {
		_, _ = tap.Write([]byte("rm -rf /var/lib/app\r"))
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("Write returned before the recorder acknowledged the command — the Enter would already be on its way to the target")
	case <-time.After(100 * time.Millisecond):
	}
	close(rec.release)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return after the acknowledgement")
	}
	if got := rec.commands(); len(got) != 1 || got[0] != "rm -rf /var/lib/app" {
		t.Fatalf("got %q", got)
	}
}

func TestRequiredTap_ARefusedChunkForwardsNothing(t *testing.T) {
	rec := &scriptedBatchRecorder{err: errors.New("command-recorder: status 503")}
	tap := NewRequiredRecordingTap(rec, "s")

	n, err := tap.Write([]byte("rm -rf /var/lib/app\r"))
	if n != 0 {
		t.Fatalf("Write reported %d bytes consumed; any n > 0 lets the relay forward part of an unrecorded command", n)
	}
	if !errors.Is(err, ErrRecordingUnavailable) || !strings.Contains(err.Error(), "503") {
		t.Fatalf("got %v", err)
	}
}

// What the relay actually does with the tap: io.Copy over io.TeeReader. This
// is the property the whole policy rests on, so it is asserted on the real
// stdlib plumbing rather than on the tap's return value alone.
func TestRequiredTap_ThroughATeeReaderTheTargetNeverSeesAnUnrecordedCommand(t *testing.T) {
	rec := &scriptedBatchRecorder{}
	tap := NewRequiredRecordingTap(rec, "s")
	var target bytes.Buffer

	// First command: recorded, so it goes through.
	if _, err := io.Copy(&target, io.TeeReader(strings.NewReader("whoami\r"), tap)); err != nil {
		t.Fatalf("a recorded command must be forwarded: %v", err)
	}
	if target.String() != "whoami\r" {
		t.Fatalf("the target received %q", target.String())
	}

	// The recorder goes away. The next command must not reach the target.
	rec.err = errors.New("connection refused")
	target.Reset()
	n, err := io.Copy(&target, io.TeeReader(strings.NewReader("cat /etc/shadow\r"), tap))
	if !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("the copy must end with the recording error, got %v", err)
	}
	if n != 0 || target.Len() != 0 {
		t.Fatalf("the target received %q of a command that was never recorded", target.String())
	}
}

func TestRequiredTap_OrdinaryKeystrokesDoNotWaitForTheRecorder(t *testing.T) {
	rec := &scriptedBatchRecorder{err: errors.New("recorder is down")}
	tap := NewRequiredRecordingTap(rec, "s")

	// No Enter, so no completed command: nothing to acknowledge, nothing to
	// refuse — typing still echoes while the recorder is unavailable, and the
	// session ends only when the operator submits something.
	for _, chunk := range []string{"l", "s", " -l", "\x7f", "a"} {
		if n, err := tap.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v", chunk, n, err)
		}
	}
	if len(rec.batches) != 0 {
		t.Fatalf("the recorder was called without a completed line: %v", rec.batches)
	}
}

// A pasted script arrives as one chunk. Its lines are recorded together,
// all or none, so the recording can never show commands that did not run.
func TestRequiredTap_OneBatchPerChunkInOrder(t *testing.T) {
	rec := &scriptedBatchRecorder{}
	tap := NewRequiredRecordingTap(rec, "session-9")

	if _, err := tap.Write([]byte("cd /srv\rls\rls\rexit")); err != nil {
		t.Fatal(err)
	}
	if len(rec.batches) != 1 {
		t.Fatalf("expected one batch for one chunk, got %d", len(rec.batches))
	}
	if got := rec.commands(); strings.Join(got, "|") != "cd /srv|ls|ls" {
		t.Fatalf("got %q (identical lines are real repeats and must both be kept)", got)
	}
	for _, e := range rec.batches[0] {
		if e.SessionID != "session-9" || e.Timestamp.IsZero() {
			t.Fatalf("bad entry %+v", e)
		}
	}
}

func TestRequiredTap_AFailedTapStaysFailed(t *testing.T) {
	rec := &scriptedBatchRecorder{err: errors.New("down")}
	tap := NewRequiredRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("first\r"))

	// The recorder comes back. The session is already over: a tap that
	// resumed would let a later command through with a hole before it.
	rec.err = nil
	n, err := tap.Write([]byte("second\r"))
	if n != 0 || !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("a failed tap accepted more input: %d, %v", n, err)
	}
	if len(rec.batches) != 0 {
		t.Fatalf("a failed tap recorded: %v", rec.batches)
	}
}

func TestRequiredTap_SecretPromptInputIsStillRedacted(t *testing.T) {
	rec := &scriptedBatchRecorder{}
	tap := NewRequiredRecordingTap(rec, "s")
	_, _ = tap.Write([]byte("sudo -s\r"))
	_, _ = tap.Output().Write([]byte("[sudo] password for bob: "))
	_, _ = tap.Write([]byte("hunter2\r"))
	if got := rec.commands(); strings.Join(got, "|") != "sudo -s|"+RedactedSecretInput {
		t.Fatalf("got %q", got)
	}
}

// The output observer shares the tap's lock with Write; a recorder that is
// slow to acknowledge must not freeze what the target is sending back.
func TestRequiredTap_SlowAcknowledgementDoesNotBlockTheOutputObserver(t *testing.T) {
	rec := &scriptedBatchRecorder{release: make(chan struct{})}
	tap := NewRequiredRecordingTap(rec, "s")

	writeDone := make(chan struct{})
	go func() {
		_, _ = tap.Write([]byte("ls\r"))
		close(writeDone)
	}()
	observed := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = tap.Output().Write([]byte("output\r\n"))
		close(observed)
	}()
	select {
	case <-observed:
	case <-time.After(2 * time.Second):
		t.Fatal("the output observer was blocked by a recorder that had not acknowledged yet")
	}
	close(rec.release)
	<-writeDone
}

// ADR-0038: an event (a file transfer) is recorded before it is relayed — acknowledged in
// required mode, or an error that finishes the tap.
func TestRecordingTap_RecordEvent(t *testing.T) {
	ok := &scriptedBatchRecorder{}
	tap := NewRequiredRecordingTap(ok, "s1")
	if err := tap.RecordEvent(context.Background(), `sftp open "/etc/x" for writing`); err != nil {
		t.Fatal(err)
	}
	if got := ok.commands(); len(got) != 1 || got[0] != `sftp open "/etc/x" for writing` {
		t.Fatalf("recorded %q", got)
	}
	failing := &scriptedBatchRecorder{err: errors.New("recorder down")}
	tap = NewRequiredRecordingTap(failing, "s2")
	if err := tap.RecordEvent(context.Background(), "e"); !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("got %v, want ErrRecordingUnavailable", err)
	}
	if n, err := tap.Write([]byte("ls\r")); n != 0 || err == nil {
		t.Fatal("the tap goes on after a refused event")
	}
	best := &captureRecorder{}
	if err := NewRecordingTap(best, "s3").RecordEvent(context.Background(), "e"); err != nil {
		t.Fatalf("best effort never fails: %v", err)
	}
}
