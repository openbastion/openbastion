package proxycore

import (
	"context"
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
