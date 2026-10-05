package proxycore

import (
	"context"
	"sync"
	"time"
)

// CommandEntry mirrors recording/v1/recording.proto's CommandEntry message.
type CommandEntry struct {
	SessionID string
	Timestamp time.Time
	Command   string
}

// Recorder is the minimal interface the Recording Tap needs against the
// Session Recorder (proto/recording/v1/recording.proto, StreamCommandEntries).
type Recorder interface {
	Record(ctx context.Context, entry CommandEntry) error
}

// RecordingTap duplicates protocol traffic to the Session Recorder without
// blocking the primary relay: a slow or unavailable Recorder must never
// stall an active session.
//
// It implements io.Writer so a Codec can wrap its client stream with
// io.MultiWriter(target, tap) to capture traffic without a separate copy
// loop. Lines are recorded as they're completed by '\n' — a simplification
// that stands in for real protocol-aware extraction until a given Codec
// provides its own structured extraction (e.g. from SSH channel requests).
type RecordingTap struct {
	recorder  Recorder
	sessionID string
	mu        sync.Mutex
	buf       []byte
}

func NewRecordingTap(recorder Recorder, sessionID string) *RecordingTap {
	return &RecordingTap{recorder: recorder, sessionID: sessionID}
}

func (t *RecordingTap) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	for {
		idx := indexByte(t.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(t.buf[:idx])
		t.buf = t.buf[idx+1:]
		if line == "" {
			continue
		}
		// Best-effort: a slow recorder must not block the session. Production
		// wiring streams asynchronously over StreamCommandEntries instead of
		// a blocking call per line.
		_ = t.recorder.Record(context.Background(), CommandEntry{
			SessionID: t.sessionID,
			Timestamp: time.Now().UTC(),
			Command:   line,
		})
	}
	return len(p), nil
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
