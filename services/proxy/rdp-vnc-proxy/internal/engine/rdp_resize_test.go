package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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

// The page asks for its size once, as the session opens, before the target's capabilities (CI of
// PR #157): the size is kept and asked when they come, once; the same size is not asked twice.
func TestRDPTargetSession_AsksTheSizeWantedWhenTheCapsCome(t *testing.T) {
	var sent []string
	s := &rdpTargetSession{resize: true, send: func(_ context.Context, _ string, layout []byte, _ time.Duration) error {
		sent = append(sent, fmt.Sprintf("%dx%d", binary.LittleEndian.Uint32(layout[28:32]), binary.LittleEndian.Uint32(layout[32:36])))
		return nil
	}}
	if err := s.Resize(context.Background(), 1103, 700, time.Second); err != nil || len(sent) != 0 {
		t.Fatalf("before the caps: %v, sent %q", err, sent)
	}
	if err := s.displayControlMessage(rdp.RDPDisplayControlChannel, displayCapsPDU(1, 4096, 4096)); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0] != "1102x700" {
		t.Fatalf("the caps came: sent %q, want the size asked before them, 1102x700", sent)
	}
	if err := s.Resize(context.Background(), 1102, 700, time.Second); err != nil || len(sent) != 1 {
		t.Fatalf("the same size again: %v, sent %q", err, sent)
	}
	if err := s.Resize(context.Background(), 1600, 900, time.Second); err != nil || len(sent) != 2 || sent[1] != "1600x900" {
		t.Fatalf("a new size: %v, sent %q", err, sent)
	}
}

// Windows closes the display control while it reactivates, then opens it again with its
// capabilities (CI of PR #155): a size asked meanwhile is kept and asked once they come; any other
// send failure is one.
func TestRDPTargetSession_FollowsTheDisplayControlClosingAndOpening(t *testing.T) {
	sent := 0
	var failure error
	s := &rdpTargetSession{resize: true,
		send: func(context.Context, string, []byte, time.Duration) error {
			if failure == nil {
				sent++
			}
			return failure
		}}
	if err := s.displayControlMessage(rdp.RDPDisplayControlChannel, displayCapsPDU(1, 4096, 4096)); err != nil {
		t.Fatal(err)
	}
	if err := s.Resize(context.Background(), 1024, 768, time.Second); err != nil || sent != 1 {
		t.Fatalf("open: %v, %d sent", err, sent)
	}
	failure = rdp.ErrRDPDynamicChannelClosed
	if err := s.Resize(context.Background(), 1280, 720, time.Second); err != nil || sent != 1 {
		t.Fatalf("closed meanwhile: %v, %d sent, want kept for later", err, sent)
	}
	s.displayControlOpened(rdp.RDPDisplayControlChannel)
	if s.displayReady {
		t.Fatal("reopened: the old capabilities still taken")
	}
	failure = nil
	if err := s.displayControlMessage(rdp.RDPDisplayControlChannel, displayCapsPDU(1, 2560, 1600)); err != nil {
		t.Fatalf("the capabilities after a reopening: %v", err)
	}
	if sent != 2 {
		t.Fatalf("the size asked while closed was not asked with the new capabilities: %d sent", sent)
	}
	failure = errors.New("transport down")
	if err := s.Resize(context.Background(), 1600, 900, time.Second); err == nil {
		t.Fatal("a broken transport taken for a closed channel")
	}
}
