package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The display control of ADR-0095 in the RDP engine: the target's capabilities read once, a resize
// ignored before them or past them, and the adapter routing InputResize only when it resizes.

func displayCapsPDU(monitors, a, b uint32) []byte {
	out := binary.LittleEndian.AppendUint32(nil, 5)
	out = binary.LittleEndian.AppendUint32(out, 20)
	out = binary.LittleEndian.AppendUint32(out, monitors)
	out = binary.LittleEndian.AppendUint32(out, a)
	return binary.LittleEndian.AppendUint32(out, b)
}

func TestRDPTargetSession_ReadsTheDisplayCapsOnce(t *testing.T) {
	s := &rdpTargetSession{resize: true}
	if err := s.displayControlMessage(rdp.RDPDisplayControlChannel, displayCapsPDU(1, 2560, 1600)); err != nil {
		t.Fatal(err)
	}
	if !s.displayReady || s.displayCaps.MaxMonitorAreaFactorA != 2560 {
		t.Fatalf("caps %+v ready %v", s.displayCaps, s.displayReady)
	}
	if err := s.displayControlMessage(rdp.RDPDisplayControlChannel, displayCapsPDU(1, 2560, 1600)); !errors.Is(err, rdp.ErrRDPDisplayControl) {
		t.Fatalf("caps twice: %v", err)
	}
	for name, c := range map[string]struct {
		channel string
		message []byte
	}{
		"another message": {rdp.RDPDisplayControlChannel, []byte{2, 0, 0, 0, 8, 0, 0, 0}},
		"another channel": {"other", displayCapsPDU(1, 2560, 1600)},
	} {
		if err := (&rdpTargetSession{resize: true}).displayControlMessage(c.channel, c.message); !errors.Is(err, rdp.ErrRDPDisplayControl) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

// Before the capabilities, past them, or with Resize off, a resize is ignored without touching the
// target: the session here has none, and would panic if it were sent.
func TestRDPTargetSession_IgnoresAResizeItCannotAskFor(t *testing.T) {
	ctx := context.Background()
	if err := (&rdpTargetSession{resize: true}).Resize(ctx, 1920, 1080, time.Second); err != nil {
		t.Fatalf("before the caps: %v", err)
	}
	small := &rdpTargetSession{resize: true, displayReady: true, displayCaps: rdp.RDPDisplayControlCaps{MaxNumMonitors: 1, MaxMonitorAreaFactorA: 1024, MaxMonitorAreaFactorB: 768}}
	if err := small.Resize(ctx, 1920, 1080, time.Second); err != nil {
		t.Fatalf("past the caps: %v", err)
	}
	off := &rdpTargetSession{displayReady: true, displayCaps: rdp.RDPDisplayControlCaps{MaxNumMonitors: 1, MaxMonitorAreaFactorA: 4096, MaxMonitorAreaFactorB: 4096}}
	if err := off.Resize(ctx, 1920, 1080, time.Second); err != nil {
		t.Fatalf("Resize off: %v", err)
	}
}

func TestRDPAdapter_ResizableOnlyWithResizeOn(t *testing.T) {
	on := &rdpScreenSessionAdapter{target: &rdpTargetSession{resize: true}, inputTimeout: time.Second}
	off := &rdpScreenSessionAdapter{target: &rdpTargetSession{}, inputTimeout: time.Second}
	if !on.Resizable() || off.Resizable() {
		t.Fatalf("Resizable: on %v, off %v", on.Resizable(), off.Resizable())
	}
	// Off, InputResize is ignored: nothing is asked of the target, and it is no error.
	if err := off.Input(screenstream.InputEvent{Type: screenstream.InputResize, X: 1920, Y: 1080}); err != nil {
		t.Fatalf("a resize to a session that cannot: %v", err)
	}
}

// Windows closes the display control while it reactivates, then opens it again with its
// capabilities (CI of PR #155): a resize meanwhile is dropped, not a fault; the capabilities that
// follow the reopening are taken; any other send failure is one.
func TestRDPTargetSession_FollowsTheDisplayControlClosingAndOpening(t *testing.T) {
	caps := rdp.RDPDisplayControlCaps{MaxNumMonitors: 1, MaxMonitorAreaFactorA: 4096, MaxMonitorAreaFactorB: 4096}
	sent := 0
	var failure error
	s := &rdpTargetSession{resize: true, displayReady: true, displayCaps: caps,
		send: func(context.Context, string, []byte, time.Duration) error { sent++; return failure }}
	if err := s.Resize(context.Background(), 1024, 768, time.Second); err != nil || sent != 1 {
		t.Fatalf("open: %v, %d sent", err, sent)
	}
	failure = rdp.ErrRDPDynamicChannelClosed
	if err := s.Resize(context.Background(), 1024, 768, time.Second); err != nil {
		t.Fatalf("closed meanwhile: %v, want dropped", err)
	}
	failure = errors.New("transport down")
	if err := s.Resize(context.Background(), 1024, 768, time.Second); err == nil {
		t.Fatal("a broken transport taken for a closed channel")
	}
	s.displayControlOpened(rdp.RDPDisplayControlChannel)
	if s.displayReady {
		t.Fatal("reopened: the old capabilities still taken")
	}
	failure, sent = nil, 0
	if err := s.Resize(context.Background(), 1024, 768, time.Second); err != nil || sent != 0 {
		t.Fatalf("before the new capabilities: %v, %d sent", err, sent)
	}
	if err := s.displayControlMessage(rdp.RDPDisplayControlChannel, displayCapsPDU(1, 2560, 1600)); err != nil {
		t.Fatalf("the capabilities after a reopening: %v", err)
	}
	if err := s.Resize(context.Background(), 1024, 768, time.Second); err != nil || sent != 1 {
		t.Fatalf("after them: %v, %d sent", err, sent)
	}
}
