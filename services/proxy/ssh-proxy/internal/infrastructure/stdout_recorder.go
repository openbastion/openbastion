package infrastructure

import (
	"context"
	"log"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

// StdoutRecorder stands in for the not-yet-built Session Recorder /
// Command Recorder services (docs/architecture/system-overview.md) — it logs captured commands
// instead of streaming them over SessionRecording.StreamCommandEntries
// (proto/recording/v1/recording.proto). Swapping it for a real HTTP/gRPC
// client touches only cmd/ssh-proxy's wiring, not pkg/proxycore or the
// codec.
type StdoutRecorder struct{}

func (StdoutRecorder) Record(ctx context.Context, entry proxycore.CommandEntry) error {
	log.Printf("[recorded] session=%s command=%q", entry.SessionID, entry.Command)
	return nil
}
