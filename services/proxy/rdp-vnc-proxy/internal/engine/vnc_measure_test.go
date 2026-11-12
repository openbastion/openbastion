package engine

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/pkg/vnc"
)

// The measurements of ADR-0090 (lot A) and ADR-0092 against a real VNC target, a terminal running
// `cat` (the Base44 sandbox's TigerVNC): VNC_MEASURE_ADDR, VNC_MEASURE_CA (its certificate, PEM),
// VNC_MEASURE_NAME and VNC_MEASURE_PASSWORD. Whole frames, then partial frames.
func TestVNCMeasure(t *testing.T) {
	address := os.Getenv("VNC_MEASURE_ADDR")
	if address == "" {
		t.Skip("VNC_MEASURE_ADDR not set: this measures a real VNC target")
	}
	raw, err := os.ReadFile(os.Getenv("VNC_MEASURE_CA"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("VNC_MEASURE_CA is not a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(raw)
	for _, partial := range []bool{false, true} {
		name := "whole-frames"
		if partial {
			name = "partial-frames"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
				Type: "password", Material: []byte(os.Getenv("VNC_MEASURE_PASSWORD")), TargetHost: address,
				TargetUser: "operator", TLSCertificateSHA256: hex.EncodeToString(sum[:]), TargetDomain: os.Getenv("VNC_MEASURE_NAME"),
			}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
			if err != nil {
				t.Fatal(err)
			}
			session, err := (&VNCCodec{TLSRoots: roots, DialTimeout: 10 * time.Second, DrawPointer: true,
				FrameInterval: 50 * time.Millisecond, PartialFrames: partial}).Open(ctx, cred)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			target, ok := session.(vncScreenSession).ScreenSession.(*vnc.Session)
			if !ok {
				t.Fatal("not a VNC session")
			}
			label := "tigervnc"
			if partial {
				label += "-partial"
			}
			m := newSessionMeter(t, label, session, target.ServerBytes)
			m.settle(2*time.Second, 30*time.Second)
			// No window manager: the keyboard goes to the window under the pointer, which the X
			// server keeps from one session to the next. xterm is at the top left.
			if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 100, Y: 100}); err != nil {
				t.Fatal(err)
			}
			m.settle(time.Second, 10*time.Second)
			key := func(keysym uint32) {
				for _, flags := range []uint8{screenstream.KeyPressed, screenstream.KeyReleased} {
					if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Keysym: keysym, Flags: flags}); err != nil {
						t.Fatal(err)
					}
				}
			}
			m.scene("idle", func() { time.Sleep(5 * time.Second) })
			m.latency("key-to-frame", 10, func() { key('a') }, func() { key(0xff08) })
			m.scene("typing", func() {
				for _, c := range "the quick brown fox jumps over the lazy dog 0123456789" {
					key(uint32(c))
					time.Sleep(30 * time.Millisecond)
				}
				key(0xff0d)
			})
			m.scene("scrolling", func() {
				for i := 0; i < 40; i++ {
					key(0xff0d)
					time.Sleep(50 * time.Millisecond)
				}
			})
			m.scene("pointer", func() { m.pointerCircle(400, 300, 150, 50, 20*time.Millisecond) })
			dir := os.Getenv("VNC_MEASURE_DUMP")
			if dir != "" {
				dir = filepath.Join(dir, label)
				_ = os.MkdirAll(dir, 0o755)
			}
			m.publish(dir)
		})
	}
}
