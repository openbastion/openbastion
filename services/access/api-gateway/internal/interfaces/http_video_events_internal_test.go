package interfaces

import (
	"strings"
	"testing"
	"time"

	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ADR-0133: the Gateway relays an operator's password marker with its size and salted fingerprint,
// and refuses what the Video Recorder never writes.
func TestVideoEvents_AnOperatorPasteMarker(t *testing.T) {
	at := timestamppb.New(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC))
	vault := &recordingv1.VideoRecordingEvent{EventId: "e1", SessionId: "s1", EventType: "secret_injection_started", Protocol: "rdp", Source: "vault", AccountId: "a1", OccurredAt: at}
	paste := &recordingv1.VideoRecordingEvent{EventId: "e2", SessionId: "s1", EventType: "secret_paste_started", Protocol: "vnc", Source: "operator", AccountId: "a1", OccurredAt: at,
		PasteBytes: 9, PasteSalt: strings.Repeat("0", 32), PasteSha256: strings.Repeat("f", 64)}
	got, err := toVideoEventsResponse(&recordingv1.GetVideoEventsResponse{Events: []*recordingv1.VideoRecordingEvent{vault, paste}}, "s1")
	if err != nil || len(got.Events) != 2 || got.Events[1].PasteBytes != 9 || got.Events[1].PasteSHA256 != strings.Repeat("f", 64) || got.Events[0].PasteSalt != "" {
		t.Fatalf("%+v, %v", got, err)
	}
	for name, event := range map[string]*recordingv1.VideoRecordingEvent{
		"a Vault marker with a fingerprint": {EventId: "e3", SessionId: "s1", EventType: "secret_injection_started", Protocol: "rdp", Source: "vault", AccountId: "a1", OccurredAt: at, PasteSha256: strings.Repeat("f", 64)},
		"an operator marker without one":    {EventId: "e3", SessionId: "s1", EventType: "secret_paste_started", Protocol: "rdp", Source: "operator", AccountId: "a1", OccurredAt: at},
		"the text as fingerprint":           {EventId: "e3", SessionId: "s1", EventType: "secret_paste_started", Protocol: "rdp", Source: "operator", AccountId: "a1", OccurredAt: at, PasteBytes: 8, PasteSalt: strings.Repeat("0", 32), PasteSha256: "hunter22"},
	} {
		if _, err := toVideoEventsResponse(&recordingv1.GetVideoEventsResponse{Events: []*recordingv1.VideoRecordingEvent{event}}, "s1"); err == nil {
			t.Errorf("%s relayed", name)
		}
	}
}
