package proxycore

import (
	"context"
	"testing"
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
