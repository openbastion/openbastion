package engine

import (
	"context"
	"crypto/x509"
	"errors"
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
	f.mu.Unlock()
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
