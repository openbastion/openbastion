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
	mu      sync.Mutex
	updates []rdp.RDPBitmapUpdate
	closed  bool
	calls   int
	width   uint16
	height  uint16
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
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Scancode: 0x1e}); !errors.Is(err, screenstream.ErrUnsupported) {
		t.Fatalf("Input error = %v, want explicit unsupported", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
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
