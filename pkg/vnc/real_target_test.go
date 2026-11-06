package vnc

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"image/png"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// TestRealTarget proves interoperability against a real RFB server (ADR-0071): the fake
// server of client_test.go proves the refusals, but it only speaks what this client's author
// believed the protocol to be. Optional, since it needs a target:
//
//	OPENBASTION_VNC_TARGET        host:port of the target
//	OPENBASTION_VNC_CA_FILE       PEM roots that validate the target's certificate
//	OPENBASTION_VNC_PIN           SHA-256 of its leaf certificate, in hexadecimal
//	OPENBASTION_VNC_SERVER_NAME   the name its certificate is valid for
//	OPENBASTION_VNC_USER, OPENBASTION_VNC_PASSWORD
//
// test/integration/testdata/vnc/target.sh starts such a target and prints these variables;
// docs/development/testing.md says how.
func TestRealTarget(t *testing.T) {
	cfg := realTargetConfig(t)

	t.Run("frame and input", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client := &Client{Config: cfg}
		session, err := client.Open(ctx)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer session.Close()

		frame := nextRealFrame(t, ctx, session)
		img, err := png.Decode(bytes.NewReader(frame.PNG))
		if err != nil {
			t.Fatalf("the frame is not a PNG: %v", err)
		}
		if got := img.Bounds().Size(); uint32(got.X) != frame.Width || uint32(got.Y) != frame.Height {
			t.Fatalf("PNG is %v, the frame announces %dx%d", got, frame.Width, frame.Height)
		}

		// Everything an operator sends, against a server that would close on a malformed message.
		events := []screenstream.InputEvent{
			{Type: screenstream.InputPointer, X: 10, Y: 10},
			{Type: screenstream.InputPointer, X: 10, Y: 10, Buttons: 1},
			{Type: screenstream.InputPointer, X: 10, Y: 10},
			{Type: screenstream.InputPointer, X: 10, Y: 10, Wheel: 1},
			{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61},
			{Type: screenstream.InputKey, Flags: screenstream.KeyReleased, Keysym: 0x61},
			{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0xffe3},
			{Type: screenstream.InputReleaseAll},
		}
		for _, e := range events {
			if err := session.Input(e); err != nil {
				t.Fatalf("input %+v: %v", e, err)
			}
		}
		// The server still serves the session after all of it.
		select {
		case <-time.After(time.Second):
		case _, ok := <-session.Frames():
			if !ok {
				t.Fatalf("the target closed the session after the input: %v", session.Err())
			}
		}
		if err := session.Err(); err != nil {
			t.Fatalf("session error: %v", err)
		}
	})

	t.Run("wrong password is refused", func(t *testing.T) {
		wrong := cfg
		wrong.Password = []byte("wrongpwd")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client := &Client{Config: wrong}
		session, err := client.Open(ctx)
		if err == nil {
			session.Close()
			t.Fatal("a wrong password opened a session")
		}
		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("Open = %v, want ErrAuthentication", err)
		}
	})

	t.Run("wrong pin never reaches authentication", func(t *testing.T) {
		wrong := cfg
		wrong.TLSFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client := &Client{Config: wrong}
		session, err := client.Open(ctx)
		if err == nil {
			session.Close()
			t.Fatal("a wrong pin opened a session")
		}
		if !errors.Is(err, ErrTLSVerification) {
			t.Fatalf("Open = %v, want ErrTLSVerification", err)
		}
	})
}

func realTargetConfig(t *testing.T) Config {
	t.Helper()
	address := os.Getenv("OPENBASTION_VNC_TARGET")
	if address == "" {
		t.Skip("OPENBASTION_VNC_TARGET is not set: no real VNC target to test against")
	}
	pem, err := os.ReadFile(os.Getenv("OPENBASTION_VNC_CA_FILE"))
	if err != nil {
		t.Fatalf("OPENBASTION_VNC_CA_FILE: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("OPENBASTION_VNC_CA_FILE holds no certificate")
	}
	return Config{
		Address:        address,
		Username:       os.Getenv("OPENBASTION_VNC_USER"),
		Password:       []byte(os.Getenv("OPENBASTION_VNC_PASSWORD")),
		TLSFingerprint: os.Getenv("OPENBASTION_VNC_PIN"),
		TLSRoots:       roots,
		TLSServerName:  os.Getenv("OPENBASTION_VNC_SERVER_NAME"),
		DialTimeout:    10 * time.Second,
	}
}

func nextRealFrame(t *testing.T, ctx context.Context, session *Session) screenstream.Message {
	t.Helper()
	select {
	case frame, ok := <-session.Frames():
		if !ok {
			t.Fatalf("the frame stream closed before a frame: %v", session.Err())
		}
		return frame
	case <-ctx.Done():
		t.Fatal("no frame before the deadline")
	}
	return screenstream.Message{}
}
