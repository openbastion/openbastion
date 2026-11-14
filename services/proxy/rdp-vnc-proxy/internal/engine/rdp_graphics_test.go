package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The graphics pipeline in the screen proxy (ADR-0101, increment 5): a session of Windows Server
// 2022 (pkg/rdp's testdata, captured in the CI of PR #199) replayed through the engine's channel
// callbacks, its frames handed on as bitmap updates and drawn by the proxy's framebuffer. The screen
// the proxy encodes is, to the pixel, the one the compositor made; every frame ended is
// acknowledged, and the capabilities advertised when the channel opens.
func TestRDPGraphics_AWindowsSessionThroughTheEngine(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "..", "pkg", "rdp", "testdata", "graphics", "windows-2022")
	var mu sync.Mutex
	var sent [][]byte
	target := &rdpTargetSession{}
	target.enableGraphics()
	target.graphics.send = func(_ context.Context, name string, data []byte, _ time.Duration) error {
		if name != rdp.RDPGraphicsChannel {
			return fmt.Errorf("a send on %q", name)
		}
		mu.Lock()
		sent = append(sent, append([]byte(nil), data...))
		mu.Unlock()
		return nil
	}
	target.channelOpened(rdp.RDPGraphicsChannel)
	// The messages come from a pump, as the session's reader would deliver them; the reader takes
	// the updates and draws them.
	messages := make(chan []byte)
	go func() {
		defer close(messages)
		for i := range 17 {
			m, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("message-%03d.bin", i)))
			if err != nil {
				t.Error(err)
				return
			}
			messages <- m
		}
	}()
	read := func() (rdp.RDPBitmapUpdate, error) {
		for m := range messages {
			if err := target.channelMessage(rdp.RDPGraphicsChannel, m); err != nil {
				return rdp.RDPBitmapUpdate{}, err
			}
		}
		select {} // the session stays open; the reader stops on its own
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var framebuffer *rdp.RDPFramebuffer
	for {
		next, err := func() (rdp.RDPBitmapUpdate, error) {
			c, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			return target.graphics.next(c, read)
		}()
		if err != nil {
			break // no more frames: the replay is over
		}
		if framebuffer == nil {
			if framebuffer, err = rdp.NewRDPFramebuffer(next.DesktopWidth, next.DesktopHeight); err != nil {
				t.Fatal(err)
			}
		}
		if err := framebuffer.Draw(next); err != nil {
			t.Fatal(err)
		}
	}
	target.Close()
	if framebuffer == nil || target.graphicsFrames() == 0 {
		t.Fatalf("%d frame(s) handed on", target.graphicsFrames())
	}
	frame, err := framebuffer.Frame(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	shown, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatal(err)
	}
	// The compositor's own screen, replayed apart.
	p, c := rdp.NewRDPGraphicsPipeline(), rdp.NewRDPGraphicsCompositor()
	ends := 0
	for i := range 17 {
		m, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("message-%03d.bin", i)))
		pdus, err := p.Read(m)
		if err != nil {
			t.Fatal(err)
		}
		for _, pdu := range pdus {
			if _, end, err := c.Apply(pdu); err != nil {
				t.Fatal(err)
			} else if end {
				ends++
			}
		}
	}
	want := c.Output()
	got := image.NewRGBA(shown.Bounds())
	for y := range got.Rect.Dy() {
		for x := range got.Rect.Dx() {
			got.Set(x, y, shown.At(x, y))
		}
	}
	if got.Rect != want.Rect || !bytes.Equal(got.Pix, want.Pix) {
		t.Fatalf("the proxy's screen %v is not the compositor's %v", got.Rect, want.Rect)
	}
	// The capabilities first, then one acknowledgement a frame ended.
	mu.Lock()
	defer mu.Unlock()
	acks := 0
	for _, m := range sent[1:] {
		if binary.LittleEndian.Uint16(m[0:2]) == 0x000d {
			acks++
		}
	}
	if len(sent) == 0 || binary.LittleEndian.Uint16(sent[0][0:2]) != 0x0012 || acks != ends {
		t.Fatalf("%d message(s) sent, %d acknowledgement(s) for %d frame(s)", len(sent), acks, ends)
	}
	t.Logf("%d frame(s) ended, %d handed on with a change, %d acknowledged", ends, target.graphicsFrames(), acks)
}

// A message the pipeline refuses ends the session; one before the channel opened too.
func TestRDPGraphics_ARefusedMessageEndsTheSession(t *testing.T) {
	target := &rdpTargetSession{}
	target.enableGraphics()
	target.graphics.send = func(context.Context, string, []byte, time.Duration) error { return nil }
	if err := target.channelMessage(rdp.RDPGraphicsChannel, []byte{0xe0, 0x04, 1}); err == nil {
		t.Fatal("a message before the channel opened")
	}
	target.channelOpened(rdp.RDPGraphicsChannel)
	if err := target.channelMessage(rdp.RDPGraphicsChannel, []byte{0xe2}); err == nil {
		t.Fatal("a message outside RDP_SEGMENTED_DATA")
	}
	// Without the pipeline, the graphics channel is not this session's: refused as any other.
	plain := &rdpTargetSession{}
	if err := plain.channelMessage(rdp.RDPGraphicsChannel, []byte{0xe0}); err == nil {
		t.Fatal("a graphics message on a session without the pipeline")
	}
}

// screenThroughGraphics opens the codec as the proxy runs it, the graphics pipeline on with gfx
// (SCREEN_RDPGFX), against a real target: the frames come, the operator's keys change the screen,
// and the frames go on. It returns the frames handed on by the pipeline and the bytes the target
// sent.
func screenThroughGraphics(t *testing.T, codec *RDPCodec, cred *proxycore.Credential, gfx bool, dump string) (int, uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	codec.GraphicsPipeline, codec.Resize = gfx, true
	session, err := codec.Open(ctx, cred)
	if err != nil {
		var failure *proxycore.ScreenFailure
		if errors.As(err, &failure) {
			t.Fatalf("opening the screen: %v: %v", err, failure.Err)
		}
		t.Fatalf("opening the screen: %v", err)
	}
	defer session.Close()
	frames := 0
	next := func(limit time.Duration) (screenstream.Message, bool) {
		select {
		case message, ok := <-session.Frames():
			if !ok {
				t.Fatalf("the stream ended after %d frame(s): %v", frames, session.Err())
			}
			frames++
			return message, true
		case <-time.After(limit):
			return screenstream.Message{}, false
		}
	}
	settle := func(frame screenstream.Message, quiet time.Duration) screenstream.Message {
		for {
			following, ok := next(quiet)
			if !ok {
				return frame
			}
			frame = following
		}
	}
	first, ok := next(90 * time.Second)
	if !ok {
		t.Fatalf("no frame in 90 s: %v", session.Err())
	}
	before := settle(first, 10*time.Second)
	// A click at a fifth of the width, a quarter of the height, then keys: in FreeRDP's xterm (top
	// left) and in Windows' Notepad alike, the screen changes through the pipeline.
	for _, buttons := range []uint8{1, 0} {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: uint16(before.Width / 5), Y: uint16(before.Height / 4), Buttons: buttons}); err != nil {
			t.Fatalf("pointer: %v", err)
		}
	}
	time.Sleep(time.Second)
	for _, scancode := range []uint16{0x22, 0x21, 0x22, 0x21} { // g f g f
		for _, flags := range []uint8{screenstream.KeyPressed, screenstream.KeyReleased} {
			if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: scancode, Flags: flags}); err != nil {
				t.Fatalf("input: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	changed, ok := next(20 * time.Second)
	if !ok {
		t.Fatalf("the screen did not change after the keys: %v", session.Err())
	}
	after := settle(changed, 5*time.Second)
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && dump != "" {
		_ = os.WriteFile(filepath.Join(dir, dump+"-before.png"), before.PNG, 0o644)
		_ = os.WriteFile(filepath.Join(dir, dump+"-after.png"), after.PNG, 0o644)
	}
	handed, received := 0, uint64(0)
	if adapter, ok := session.(*rdpScreenSessionAdapter); ok {
		if target, ok := adapter.target.(*rdpTargetSession); ok {
			handed, received = target.graphicsFrames(), target.session.ServerBytes()
		}
	}
	t.Logf("pipeline %v: %d frame(s) shown, %d through the graphics pipeline, %d byte(s) from the target; %dx%d",
		gfx, frames, handed, received, after.Width, after.Height)
	return handed, received
}

// FreeRDP's shadow server opens the pipeline: its frames, in RemoteFX Progressive, reach the
// operator through it.
func TestRDPInterop_ScreenThroughTheGraphicsPipeline(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(rdpInteropPassword), TargetHost: target.address,
		TargetUser: rdpInteropUser, TLSCertificateSHA256: target.pin, TargetDomain: rdpInteropName,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	handed, _ := screenThroughGraphics(t, &RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second}, cred, true, "")
	if handed == 0 {
		t.Fatal("no frame came through the graphics pipeline")
	}
}
