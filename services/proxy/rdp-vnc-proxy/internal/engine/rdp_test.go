package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"image/png"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

type fakeRDPDesktop struct {
	mu       sync.Mutex
	updates  []rdp.RDPBitmapUpdate
	closed   bool
	calls    int
	width    uint16
	height   uint16
	inputs   [][]rdp.RDPInputEvent
	inputErr error
	// endErr, when set, is what the read returns once the updates are spent.
	endErr error
}

func (f *fakeRDPDesktop) ReadBitmapUpdate(ctx context.Context, _ time.Duration) (rdp.RDPBitmapUpdate, error) {
	f.mu.Lock()
	f.calls++
	if len(f.updates) > 0 {
		update := f.updates[0]
		f.updates = f.updates[1:]
		f.mu.Unlock()
		return update, nil
	}
	endErr := f.endErr
	f.mu.Unlock()
	if endErr != nil {
		return rdp.RDPBitmapUpdate{}, endErr
	}
	<-ctx.Done()
	return rdp.RDPBitmapUpdate{}, ctx.Err()
}
func (f *fakeRDPDesktop) SendInput(_ context.Context, events []rdp.RDPInputEvent, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputs = append(f.inputs, append([]rdp.RDPInputEvent(nil), events...))
	return f.inputErr
}
func (f *fakeRDPDesktop) Dimensions() (uint16, uint16) { return f.width, f.height }
func (f *fakeRDPDesktop) Close()                       { f.mu.Lock(); f.closed = true; f.mu.Unlock() }

func rdpTestCredential(t *testing.T) *proxycore.Credential {
	t.Helper()
	vault := testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte("temporary-password"), TargetHost: "rdp.example:3389",
		TargetUser: "operator", TLSCertificateSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		TargetDomain: "rdp.example",
	}}
	cred, err := proxycore.NewCredentialFetcher(vault, "rdp-vnc-proxy").Fetch(context.Background(), "one-use")
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

type testMetadataVault struct{ fetched proxycore.Fetched }

func (v testMetadataVault) FetchCredential(context.Context, string, string) (proxycore.Fetched, error) {
	return v.fetched, nil
}

func TestRDPCodecRejectsMissingTrustMetadataBeforeOpeningTarget(t *testing.T) {
	cred := rdpTestCredential(t)
	cred.TLSCertificateSHA256 = ""
	called := false
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
		called = true
		return nil, errors.New("must not dial")
	}}
	_, err := codec.Open(context.Background(), cred)
	if !errors.Is(err, ErrRDPConfiguration) {
		t.Fatalf("Open error = %v", err)
	}
	if called {
		t.Fatal("target was contacted without Vault TLS pin metadata")
	}
}

func TestRDPCodecRequiresExplicitTrustRoots(t *testing.T) {
	cred := rdpTestCredential(t)
	if _, err := (&RDPCodec{}).Open(context.Background(), cred); !errors.Is(err, ErrRDPConfiguration) {
		t.Fatalf("Open error = %v, want missing explicit roots", err)
	}
}

func TestRDPCodecStreamsFramebufferAndClosesTargetOnCancellation(t *testing.T) {
	cred := rdpTestCredential(t)
	pixel := []byte{0x11, 0x22, 0x33, 0xff}
	target := &fakeRDPDesktop{width: 2, height: 1, updates: []rdp.RDPBitmapUpdate{{Rectangles: []rdp.RDPBitmapRectangle{{X: 1, Y: 0, Width: 1, Height: 1, Pixels: pixel}}}}}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), DesktopWidth: 1920, DesktopHeight: 1080,
		openSession: func(_ context.Context, _ *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), cred)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	select {
	case frame, ok := <-session.Frames():
		if !ok {
			t.Fatal("frame stream closed before first frame")
		}
		if frame.Type != screenstream.TypeFrame || frame.Sequence != 1 || frame.Width != 2 || frame.Height != 1 {
			t.Fatalf("unexpected frame metadata: %#v", frame)
		}
		if _, err := screenstream.Encode(frame); err != nil {
			t.Fatalf("invalid ScreenStream frame: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RDP framebuffer update was not emitted")
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Scancode: 0x1e}); err != nil {
		t.Fatalf("key down: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Scancode: 0xe01d}); err != nil {
		t.Fatalf("extended key down: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 1, Y: 0, Buttons: 7}); err != nil {
		t.Fatalf("pointer down: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 1, Y: 0, Buttons: 7, Wheel: -1}); err != nil {
		t.Fatalf("wheel: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61}); !errors.Is(err, screenstream.ErrUnsupported) {
		t.Fatalf("keysym-only input error = %v, want unsupported", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	target.mu.Lock()
	inputBatches := append([][]rdp.RDPInputEvent(nil), target.inputs...)
	target.mu.Unlock()
	if len(inputBatches) != 5 {
		t.Fatalf("input batches = %d, want 5 including release-all on close", len(inputBatches))
	}
	if got := inputBatches[0][0]; got.Type != rdp.RDPInputScancode || got.Scancode != 0x1e || got.Released {
		t.Fatalf("normal key mapping = %+v", got)
	}
	if got := inputBatches[1][0]; got.Type != rdp.RDPInputScancode || got.Scancode != 0x1d || !got.Extended {
		t.Fatalf("extended key mapping = %+v", got)
	}
	if len(inputBatches[2]) != 4 || inputBatches[2][1].PointerFlags != rdpMouseButton1|rdpMouseDown ||
		inputBatches[2][2].PointerFlags != rdpMouseButton3|rdpMouseDown || inputBatches[2][3].PointerFlags != rdpMouseButton2|rdpMouseDown {
		t.Fatalf("mouse button mapping = %+v", inputBatches[2])
	}
	if got := inputBatches[3][1]; got.PointerFlags != rdpMouseWheel|rdpMouseWheelNegative|120 {
		t.Fatalf("wheel mapping = %+v", got)
	}
	if len(inputBatches[4]) != 5 || !inputBatches[4][0].Released || !inputBatches[4][1].Released ||
		inputBatches[4][2].PointerFlags != rdpMouseButton1 || inputBatches[4][3].PointerFlags != rdpMouseButton3 ||
		inputBatches[4][4].PointerFlags != rdpMouseButton2 {
		t.Fatalf("release-all events = %+v", inputBatches[4])
	}
	target.mu.Lock()
	closed := target.closed
	target.mu.Unlock()
	if !closed {
		t.Fatal("closing screen session did not close the RDP transport")
	}
	if err := session.Err(); err != nil {
		t.Fatalf("normal cancellation recorded as session failure: %v", err)
	}
}

func TestRDPCodecMapsPinMismatchToStableScreenFailure(t *testing.T) {
	cred := rdpTestCredential(t)
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
		return nil, rdp.ErrTLSVerification
	}}
	_, err := codec.Open(context.Background(), cred)
	var failure *proxycore.ScreenFailure
	if !errors.As(err, &failure) || failure.ScreenEndCode() != "pin_mismatch" {
		t.Fatalf("Open error = %v, want stable pin_mismatch failure", err)
	}
}

func TestRDPCodecReleaseAllBatchesLargeHeldKeySet(t *testing.T) {
	cred := rdpTestCredential(t)
	target := &fakeRDPDesktop{width: 2, height: 1}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
		return target, nil
	}}
	session, err := codec.Open(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	for code := uint16(1); code <= 127; code++ {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Scancode: code}); err != nil {
			t.Fatalf("press scancode %#x: %v", code, err)
		}
	}
	for code := uint16(0xe001); code <= 0xe003; code++ {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Scancode: code}); err != nil {
			t.Fatalf("press extended scancode %#x: %v", code, err)
		}
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputReleaseAll}); err != nil {
		t.Fatalf("release all: %v", err)
	}
	target.mu.Lock()
	batches := append([][]rdp.RDPInputEvent(nil), target.inputs...)
	target.mu.Unlock()
	if len(batches) != 132 || len(batches[130]) != 128 || len(batches[131]) != 2 {
		t.Fatalf("total batches=%d release batch sizes=%d/%d", len(batches), len(batches)-130, len(batches)-131)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestRDPCodecReleasesHeldInputsAfterParentContextCancellation(t *testing.T) {
	cred := rdpTestCredential(t)
	target := &fakeRDPDesktop{width: 2, height: 1}
	ctx, cancel := context.WithCancel(context.Background())
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
		return target, nil
	}}
	session, err := codec.Open(ctx, cred)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Scancode: 0x1e}); err != nil {
		cancel()
		t.Fatalf("key down: %v", err)
	}
	cancel()
	if err := session.Close(); err != nil {
		t.Fatalf("Close after parent cancellation: %v", err)
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	if len(target.inputs) != 2 || !target.inputs[1][0].Released || !target.closed {
		t.Fatalf("inputs=%+v closed=%v; expected key-up before target close", target.inputs, target.closed)
	}
}

func TestRDPCodecCloseReturnsSameReleaseErrorOnRepeatedCalls(t *testing.T) {
	cred := rdpTestCredential(t)
	target := &fakeRDPDesktop{width: 2, height: 1}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
		return target, nil
	}}
	session, err := codec.Open(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Scancode: 0x1e}); err != nil {
		t.Fatalf("key down: %v", err)
	}
	target.mu.Lock()
	target.inputErr = errors.New("simulated write failure")
	target.mu.Unlock()
	first := session.Close()
	second := session.Close()
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("Close errors differ: first=%v second=%v", first, second)
	}
}

func TestRDPCodecMapsScreenStreamWheelButtonBits(t *testing.T) {
	cred := rdpTestCredential(t)
	target := &fakeRDPDesktop{width: 2, height: 1}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
		return target, nil
	}}
	session, err := codec.Open(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []screenstream.InputEvent{
		{Type: screenstream.InputPointer, X: 1, Y: 0, Buttons: 0x08},
		{Type: screenstream.InputPointer, X: 1, Y: 0},
		{Type: screenstream.InputPointer, X: 1, Y: 0, Buttons: 0x10},
		{Type: screenstream.InputPointer, X: 1, Y: 0},
	} {
		if err := session.Input(event); err != nil {
			t.Fatalf("pointer input %#v: %v", event, err)
		}
	}
	target.mu.Lock()
	batches := append([][]rdp.RDPInputEvent(nil), target.inputs...)
	target.mu.Unlock()
	if len(batches) != 4 || len(batches[0]) != 2 || len(batches[1]) != 1 || len(batches[2]) != 2 || len(batches[3]) != 1 {
		t.Fatalf("wheel button batches = %#v", batches)
	}
	if batches[0][1].PointerFlags != rdpMouseWheel|120 || batches[2][1].PointerFlags != rdpMouseWheel|rdpMouseWheelNegative|120 {
		t.Fatalf("wheel button flags = %#v / %#v", batches[0][1], batches[2][1])
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// A server may repaint its screen tens of times a second: only what changes costs a PNG and a
// recorded segment. The first frame is always sent, even of a screen still black.
func TestRDPCodec_ARepaintOfTheSamePixelsIsNotAFrame(t *testing.T) {
	// The very pixels of a new framebuffer: nothing changes, and the operator must still see it.
	black := rdp.RDPBitmapUpdate{Rectangles: []rdp.RDPBitmapRectangle{{Width: 1, Height: 1, Pixels: []byte{0, 0, 0, 0xff}}}}
	white := rdp.RDPBitmapUpdate{Rectangles: []rdp.RDPBitmapRectangle{{Width: 1, Height: 1, Pixels: []byte{0xff, 0xff, 0xff, 0xff}}}}
	target := &fakeRDPDesktop{width: 1, height: 1, updates: []rdp.RDPBitmapUpdate{black, black, black, white, white, black}}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var frames int
	var last uint64
	for frames < 3 {
		select {
		case frame := <-session.Frames():
			frames++
			if frame.Sequence <= last && frames > 1 {
				t.Fatalf("sequence %d after %d", frame.Sequence, last)
			}
			last = frame.Sequence
		case <-time.After(5 * time.Second):
			t.Fatalf("%d frames, want 3: black, white, black", frames)
		}
	}
	select {
	case frame, ok := <-session.Frames():
		if ok {
			t.Fatalf("a fourth frame: %+v", frame.Sequence)
		}
	case <-time.After(200 * time.Millisecond):
	}
}

// A failing phase of the connection sequence is named, keeps its error for the refusal code, and
// stops the sequence; a cancelled context stops it before the next phase (ADR-0071).
func TestRunRDPConnectionStepsNamesTheFailingPhase(t *testing.T) {
	var ran []string
	step := func(name string, err error) rdpConnectionStep {
		return rdpConnectionStep{name, func() error { ran = append(ran, name); return err }}
	}
	err := runRDPConnectionSteps(context.Background(), []rdpConnectionStep{
		step("MCS connect", nil), step("licensing", rdp.ErrMCSConnection), step("capabilities", nil),
	})
	if !errors.Is(err, rdp.ErrMCSConnection) || err.Error() != "RDP licensing: "+rdp.ErrMCSConnection.Error() {
		t.Fatalf("err = %v", err)
	}
	if len(ran) != 2 {
		t.Fatalf("ran %v: the sequence must stop at the failing phase", ran)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran = nil
	if err := runRDPConnectionSteps(ctx, []rdpConnectionStep{step("MCS connect", nil)}); !errors.Is(err, context.Canceled) || len(ran) != 0 {
		t.Fatalf("cancelled: %v, ran %v", err, ran)
	}
}

// A reactivation that changes the desktop's size (MS-RDPBCGR 1.3.1.3): the frames take the new
// size, the sequence carries on, and the operator's pointer is bounded by the new desktop.
func TestRDPCodec_AReactivationResizesTheScreen(t *testing.T) {
	pixel := []byte{0xff, 0xff, 0xff, 0xff}
	target := &fakeRDPDesktop{width: 4, height: 4, updates: []rdp.RDPBitmapUpdate{
		{Rectangles: []rdp.RDPBitmapRectangle{{X: 3, Y: 3, Width: 1, Height: 1, Pixels: pixel}}, DesktopWidth: 4, DesktopHeight: 4},
		// The same pixels as the black desktop of the new size: still a frame, the first at that size.
		{Rectangles: []rdp.RDPBitmapRectangle{{X: 7, Y: 1, Width: 1, Height: 1, Pixels: []byte{0, 0, 0, 0xff}}}, DesktopWidth: 8, DesktopHeight: 2},
	}}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var frames []screenstream.Message
	for len(frames) < 2 {
		select {
		case frame := <-session.Frames():
			frames = append(frames, frame)
		case <-time.After(5 * time.Second):
			t.Fatalf("%d frame(s), want 2", len(frames))
		}
	}
	if frames[0].Width != 4 || frames[1].Width != 8 || frames[1].Height != 2 || frames[1].Sequence != frames[0].Sequence+1 {
		t.Fatalf("frames %dx%d #%d, then %dx%d #%d", frames[0].Width, frames[0].Height, frames[0].Sequence, frames[1].Width, frames[1].Height, frames[1].Sequence)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 7, Y: 1}); err != nil {
		t.Fatalf("a point of the new desktop: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 3, Y: 3}); err == nil {
		t.Fatal("a point of the old desktop only was sent")
	}
}

// A screen too large to record ends the stream with the error that says so: the relay turns it
// into a recording loss, said to the operator and audited (ADR-0070, pkg/proxycore).
func TestRDPCodec_AScreenTooLargeToRecordEndsTheStreamSayingSo(t *testing.T) {
	const width, height = 1600, 1200
	noise := make([]byte, width*height*4)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	for i := 3; i < len(noise); i += 4 {
		noise[i] = 0xff
	}
	target := &fakeRDPDesktop{width: width, height: height, updates: []rdp.RDPBitmapUpdate{
		{Rectangles: []rdp.RDPBitmapRectangle{{Width: width, Height: height, Pixels: noise}}, DesktopWidth: width, DesktopHeight: height},
	}}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	select {
	case frame, ok := <-session.Frames():
		if ok {
			t.Fatalf("a frame of %d bytes was sent", len(frame.PNG))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end")
	}
	if err := session.Err(); !errors.Is(err, screenstream.ErrFrameTooLarge) {
		t.Fatalf("Err() = %v, want ErrFrameTooLarge", err)
	}
}

// The frames follow a cadence (ADR-0071 §8): updates are drawn as they come, and at most one frame
// a interval is encoded and recorded, the latest screen. The first frame goes at once, and the
// last screen drawn is never lost.
func TestRDPCodec_FramesFollowTheCadence(t *testing.T) {
	var updates []rdp.RDPBitmapUpdate
	for i := 1; i <= 40; i++ {
		updates = append(updates, rdp.RDPBitmapUpdate{Rectangles: []rdp.RDPBitmapRectangle{{Width: 1, Height: 1, Pixels: []byte{byte(i), 0, 0, 0xff}}}})
	}
	target := &fakeRDPDesktop{width: 1, height: 1, updates: updates, endErr: rdp.ErrMCSConnection}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), FrameInterval: time.Hour, openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var frames []screenstream.Message
	for frame := range session.Frames() {
		frames = append(frames, frame)
	}
	// 40 updates within the hour: the first at once, then the latest when the stream ends.
	if len(frames) != 2 {
		t.Fatalf("%d frame(s) for 40 updates within one interval, want 2", len(frames))
	}
	if frames[1].Sequence != frames[0].Sequence+1 {
		t.Fatalf("sequences %d then %d", frames[0].Sequence, frames[1].Sequence)
	}
	last, err := png.Decode(bytes.NewReader(frames[1].PNG))
	if err != nil {
		t.Fatal(err)
	}
	if r, _, _, _ := last.At(0, 0).RGBA(); r>>8 != 40 {
		t.Fatalf("the last frame shows update %d, want 40, the latest", r>>8)
	}
}

// A screen drawn within the interval goes out when the interval is over, with no further update.
func TestRDPCodec_AWaitingScreenGoesOutAtTheInterval(t *testing.T) {
	pixel := func(v byte) rdp.RDPBitmapUpdate {
		return rdp.RDPBitmapUpdate{Rectangles: []rdp.RDPBitmapRectangle{{Width: 1, Height: 1, Pixels: []byte{v, 0, 0, 0xff}}}}
	}
	target := &fakeRDPDesktop{width: 1, height: 1, updates: []rdp.RDPBitmapUpdate{pixel(1), pixel(2)}}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), FrameInterval: 50 * time.Millisecond, openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for i := 1; i <= 2; i++ {
		select {
		case frame := <-session.Frames():
			shown, err := png.Decode(bytes.NewReader(frame.PNG))
			if err != nil {
				t.Fatal(err)
			}
			if r, _, _, _ := shown.At(0, 0).RGBA(); r>>8 != uint32(i) {
				t.Fatalf("frame %d shows %d", i, r>>8)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("frame %d never came: the waiting screen was not sent at the interval", i)
		}
	}
}
