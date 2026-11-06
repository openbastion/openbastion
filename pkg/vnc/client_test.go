package vnc

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

func TestOpenVeNCryptX509PlainFrameAndInput(t *testing.T) {
	serverCert, leaf := vncTestCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	pinSum := sha256.Sum256(serverCert.Certificate[0])
	pin := hex.EncodeToString(pinSum[:])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	eventsSeen := make(chan struct{})
	go func() { serverResult <- serveFakeVeNCrypt(t, listener, serverCert, eventsSeen) }()

	client := &Client{Config: Config{Address: listener.Addr().String(), Username: "operator", Password: []byte("vault-password"), TLSFingerprint: pin, TLSRoots: roots, TLSServerName: "target.test", DialTimeout: 3 * time.Second}}
	session, err := client.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if client.Config.Password != nil {
		t.Fatal("client retained a reference to the credential after Open")
	}
	frame, ok := <-session.Frames()
	if !ok {
		t.Fatalf("frame stream closed: %v", session.Err())
	}
	if frame.Type != screenstream.TypeFrame || frame.Sequence != 1 || frame.Width != 1 || frame.Height != 1 {
		t.Fatalf("unexpected frame: %#v", frame)
	}
	img, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatalf("decode PNG: %v", err)
	}
	pixel := img.At(0, 0)
	r, g, b, _ := pixel.RGBA()
	if r>>8 != 30 || g>>8 != 20 || b>>8 != 10 {
		t.Fatalf("pixel RGB = %d,%d,%d, want 30,20,10", r>>8, g>>8, b>>8)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61}); err != nil {
		t.Fatalf("key input: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 0, Y: 0, Buttons: 1}); err != nil {
		t.Fatalf("pointer input: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputReleaseAll}); err != nil {
		t.Fatalf("release all: %v", err)
	}
	<-eventsSeen
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("fake target: %v", err)
	}
}

func TestOpenRejectsWrongCertificatePinBeforeAuthentication(t *testing.T) {
	serverCert, leaf := vncTestCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	other, _ := vncTestCertificate(t)
	wrongSum := sha256.Sum256(other.Certificate[0])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := writeFull(conn, []byte(protocolVersion)); err != nil {
			serverResult <- err
			return
		}
		var ver [12]byte
		if _, err := io.ReadFull(conn, ver[:]); err != nil {
			serverResult <- err
			return
		}
		if err := writeFull(conn, []byte{1, securityVeNCrypt}); err != nil {
			serverResult <- err
			return
		}
		var choice [1]byte
		if _, err := io.ReadFull(conn, choice[:]); err != nil {
			serverResult <- err
			return
		}
		if err := writeFull(conn, []byte{0, 2}); err != nil {
			serverResult <- err
			return
		}
		var ven [2]byte
		if _, err := io.ReadFull(conn, ven[:]); err != nil {
			serverResult <- err
			return
		}
		if err := writeFull(conn, []byte{0, 1, 0, 0, 1, 6}); err != nil {
			serverResult <- err
			return
		}
		var subtype [4]byte
		if _, err := io.ReadFull(conn, subtype[:]); err != nil {
			serverResult <- err
			return
		}
		if err := writeFull(conn, []byte{1}); err != nil {
			serverResult <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12})
		err = tlsConn.Handshake()
		serverResult <- err
	}()
	cfg := Config{Address: listener.Addr().String(), Username: "operator", Password: []byte("secret"), TLSFingerprint: hex.EncodeToString(wrongSum[:]), TLSRoots: roots, TLSServerName: "target.test", DialTimeout: 3 * time.Second}
	if _, err := (&Client{Config: cfg}).Open(context.Background()); err == nil {
		t.Fatal("target with wrong pin accepted")
	}
	if err := <-serverResult; err == nil {
		t.Fatal("fake target completed TLS handshake despite the wrong pin")
	}
}

func TestX509VNCChallengeResponseUsesReversedDESKey(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	password := []byte("12345678")
	serverErr := make(chan error, 1)
	go func() {
		challenge := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		if err := writeFull(server, challenge); err != nil {
			serverErr <- err
			return
		}
		var got [16]byte
		if _, err := io.ReadFull(server, got[:]); err != nil {
			serverErr <- err
			return
		}
		var key [8]byte
		copy(key[:], password)
		for i := range key {
			key[i] = reverseBits(key[i])
		}
		block, err := des.NewCipher(key[:])
		zero(key[:])
		if err != nil {
			serverErr <- err
			return
		}
		var want [16]byte
		block.Encrypt(want[:8], challenge[:8])
		block.Encrypt(want[8:], challenge[8:])
		if !bytes.Equal(got[:], want[:]) {
			serverErr <- errors.New("incorrect VNC DES challenge response")
			return
		}
		serverErr <- writeFull(server, []byte{0, 0, 0, 0})
	}()
	if err := authenticateVNC(client, password); err != nil {
		t.Fatalf("authenticateVNC: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsMissingPinAndUnsupportedTarget(t *testing.T) {
	c := &Client{Config: Config{Address: "127.0.0.1:5900", Username: "u", Password: []byte("p"), TLSRoots: x509.NewCertPool()}}
	if _, err := c.Open(context.Background()); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("missing pin error = %v", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	go func() { _, _ = right.Write([]byte("RFB 003.007\n")) }()
	if err := handshakeRFB(left); !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("RFB 3.7 error = %v", err)
	}
}

func TestHandshakeRejectsCleartextSecurityTypes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = writeFull(server, []byte(protocolVersion))
		var selectedVersion [12]byte
		if _, err := io.ReadFull(server, selectedVersion[:]); err != nil {
			return
		}
		_ = writeFull(server, []byte{2, 1, 2}) // None and classic VNC auth only.
	}()
	if err := handshakeRFB(client); !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("cleartext security error = %v", err)
	}
}

func TestX509VNCRefusesPasswordThatWouldBeTruncated(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if err := authenticateVNC(left, []byte("123456789")); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("long password error = %v", err)
	}
	_ = right.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	var b [1]byte
	if _, err := right.Read(b[:]); err == nil {
		t.Fatal("authentication bytes sent for rejected password")
	}
}

func serveFakeVeNCrypt(t *testing.T, listener net.Listener, cert tls.Certificate, eventsSeen chan<- struct{}) error {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = writeFull(conn, []byte(protocolVersion)); err != nil {
		return err
	}
	var version [12]byte
	if _, err = io.ReadFull(conn, version[:]); err != nil {
		return err
	}
	if string(version[:]) != protocolVersion {
		return errors.New("client did not select RFB 3.8")
	}
	if err = writeFull(conn, []byte{1, securityVeNCrypt}); err != nil {
		return err
	}
	var security [1]byte
	if _, err = io.ReadFull(conn, security[:]); err != nil {
		return err
	}
	if security[0] != securityVeNCrypt {
		return errors.New("client did not require VeNCrypt")
	}
	if err = writeFull(conn, []byte{0, 2}); err != nil {
		return err
	}
	var venVersion [2]byte
	if _, err = io.ReadFull(conn, venVersion[:]); err != nil {
		return err
	}
	if venVersion != [2]byte{0, 2} {
		return errors.New("wrong VeNCrypt version")
	}
	if err = writeFull(conn, []byte{0, 1, 0, 0, 1, 6}); err != nil {
		return err
	}
	var subtype [4]byte
	if _, err = io.ReadFull(conn, subtype[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(subtype[:]) != vencryptX509Plain {
		return errors.New("client did not prefer X509Plain")
	}
	if err = writeFull(conn, []byte{1}); err != nil { // accepted: TigerVNC and QEMU say yes with 1
		return err
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err = tlsConn.Handshake(); err != nil {
		return err
	}
	var lens [8]byte
	if _, err = io.ReadFull(tlsConn, lens[:]); err != nil {
		return err
	}
	un := binary.BigEndian.Uint32(lens[:4])
	pn := binary.BigEndian.Uint32(lens[4:])
	if un > maxAuthField || pn > maxAuthField {
		return errors.New("auth fields oversized")
	}
	u := make([]byte, un)
	p := make([]byte, pn)
	if _, err = io.ReadFull(tlsConn, u); err != nil {
		return err
	}
	if _, err = io.ReadFull(tlsConn, p); err != nil {
		return err
	}
	if string(u) != "operator" || string(p) != "vault-password" {
		return errors.New("unexpected credential fields")
	}
	for i := range p {
		p[i] = 0
	}
	if err = writeFull(tlsConn, []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	var shared [1]byte
	if _, err = io.ReadFull(tlsConn, shared[:]); err != nil {
		return err
	}
	if shared[0] != 1 {
		return errors.New("client did not request a shared session")
	}
	var init [24]byte
	binary.BigEndian.PutUint16(init[0:2], 1)
	binary.BigEndian.PutUint16(init[2:4], 1)
	init[4], init[5], init[6], init[7] = 32, 24, 0, 1
	binary.BigEndian.PutUint16(init[8:10], 255)
	binary.BigEndian.PutUint16(init[10:12], 255)
	binary.BigEndian.PutUint16(init[12:14], 255)
	init[14], init[15], init[16] = 16, 8, 0
	if err = writeFull(tlsConn, init[:]); err != nil {
		return err
	}
	var pf [20]byte
	if _, err = io.ReadFull(tlsConn, pf[:]); err != nil {
		return err
	}
	var encHdr [4]byte
	if _, err = io.ReadFull(tlsConn, encHdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint16(encHdr[2:])
	encs := make([]byte, int(n)*4)
	if _, err = io.ReadFull(tlsConn, encs); err != nil {
		return err
	}
	if n != 6 {
		return errors.New("unexpected encoding list")
	}
	var request [10]byte
	if _, err = io.ReadFull(tlsConn, request[:]); err != nil {
		return err
	}
	if request[0] != 3 || request[1] != 0 {
		return errors.New("first update was not full")
	}
	var update bytes.Buffer
	update.Write([]byte{0, 0, 0, 1})
	var rect [12]byte
	binary.BigEndian.PutUint16(rect[4:6], 1)
	binary.BigEndian.PutUint16(rect[6:8], 1)
	binary.BigEndian.PutUint32(rect[8:12], 0)
	update.Write(rect[:])
	update.Write([]byte{10, 20, 30, 0})
	if err = writeFull(tlsConn, update.Bytes()); err != nil {
		return err
	}
	// Read the follow-up update request and the input events in any valid order.
	seenRequest, seenKey, seenPointer, seenRelease, seenPointerRelease := false, false, false, false, false
	for !(seenRequest && seenKey && seenPointer && seenRelease && seenPointerRelease) {
		var kind [1]byte
		if _, err = io.ReadFull(tlsConn, kind[:]); err != nil {
			return err
		}
		switch kind[0] {
		case 3:
			var rest [9]byte
			if _, err = io.ReadFull(tlsConn, rest[:]); err != nil {
				return err
			}
			seenRequest = true
		case 4:
			var rest [7]byte
			if _, err = io.ReadFull(tlsConn, rest[:]); err != nil {
				return err
			}
			key := binary.BigEndian.Uint32(rest[3:])
			if key == 0x61 && rest[0] == 1 {
				seenKey = true
			}
			if key == 0x61 && rest[0] == 0 {
				seenRelease = true
			}
		case 5:
			var rest [5]byte
			if _, err = io.ReadFull(tlsConn, rest[:]); err != nil {
				return err
			}
			if rest[0] == 1 {
				seenPointer = true
			} else if rest[0] == 0 {
				seenPointerRelease = true
			}
		default:
			return errors.New("unexpected client message")
		}
	}
	close(eventsSeen)
	var closeProbe [1]byte
	if n, err := io.ReadFull(tlsConn, closeProbe[:]); err == nil {
		return fmt.Errorf("client sent unexpected data after input: n=%d byte=%d", n, closeProbe[0])
	}
	return nil
}

func vncTestCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "target.test"}, DNSNames: []string{"target.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func TestEmitFrameUnblocksWhenSessionCloses(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	s := &Session{conn: client, frames: make(chan screenstream.Message), width: 1, height: 1, framebuffer: image.NewRGBA(image.Rect(0, 0, 1, 1)), pressed: make(map[uint32]struct{}), done: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- s.emitFrame() }()
	select {
	case err := <-result:
		t.Fatalf("frame send did not wait for consumer: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("emitFrame after close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked frame sender did not unblock on close")
	}
}

func TestReadRectangleRejectsOutOfBoundsAndHandlesLastRect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	s := &Session{conn: client, width: 1, height: 1, framebuffer: image.NewRGBA(image.Rect(0, 0, 1, 1))}
	go func() {
		var out [12]byte
		binary.BigEndian.PutUint16(out[4:6], 2)
		binary.BigEndian.PutUint16(out[6:8], 1)
		binary.BigEndian.PutUint32(out[8:12], 0)
		_ = writeFull(server, out[:])
	}()
	if _, err := s.readRectangle(false); !errors.Is(err, ErrInvalidFramebuffer) {
		t.Fatalf("out-of-bounds rectangle error = %v", err)
	}
	go func() {
		var out [12]byte
		binary.BigEndian.PutUint32(out[8:12], uint32(0xffffff20))
		_ = writeFull(server, out[:])
	}()
	if _, err := s.readRectangle(true); !errors.Is(err, errLastRect) {
		t.Fatalf("LastRect error = %v", err)
	}
}

// Refused by the server, the subtype must not start a TLS handshake nor, later, an
// authentication: 0 is the server's no, whatever the status of the version said.
func TestVeNCryptSubtypeRefusalIsNotMistakenForAcceptance(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = writeFull(server, []byte{0, 2})
		var version [2]byte
		_, _ = io.ReadFull(server, version[:])
		_ = writeFull(server, []byte{0, 1, 0, 0, 1, 6})
		var subtype [4]byte
		_, _ = io.ReadFull(server, subtype[:])
		_ = writeFull(server, []byte{0})
	}()
	if _, err := negotiateVeNCrypt(client); !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("refused subtype: %v", err)
	}
}

func pipeSession(t *testing.T, width, height uint32) (*Session, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	return &Session{conn: client, frames: make(chan screenstream.Message), width: width, height: height, framebuffer: image.NewRGBA(image.Rect(0, 0, int(width), int(height))), pressed: make(map[uint32]struct{}), done: make(chan struct{})}, server
}

func extendedDesktopSize(reason, w, h uint16) []byte {
	var m bytes.Buffer
	m.Write([]byte{0, 0, 0, 1})
	var rect [12]byte
	binary.BigEndian.PutUint16(rect[0:2], reason)
	binary.BigEndian.PutUint16(rect[4:6], w)
	binary.BigEndian.PutUint16(rect[6:8], h)
	var encoding int32 = -308
	binary.BigEndian.PutUint32(rect[8:12], uint32(encoding))
	m.Write(rect[:])
	m.Write([]byte{1, 0, 0, 0})
	var screen [16]byte
	binary.BigEndian.PutUint16(screen[8:10], w)
	binary.BigEndian.PutUint16(screen[10:12], h)
	m.Write(screen[:])
	return m.Bytes()
}

// TigerVNC answers each full request with the size alone. Asking again in full would loop for
// as long as the session lives, at the target's expense, without ever showing a pixel.
func TestSameSizeAnnouncementAsksIncrementallyInsteadOfLooping(t *testing.T) {
	s, server := pipeSession(t, 4, 3)
	go func() { _ = writeFull(server, extendedDesktopSize(0, 4, 3)) }()
	result := make(chan error, 1)
	go func() { result <- s.readServerMessage() }()
	var request [10]byte
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(server, request[:]); err != nil {
		t.Fatal(err)
	}
	if request[0] != 3 || request[1] != 1 {
		t.Fatalf("after the same size: request %v, want an incremental one", request[:2])
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// A size that does change discards the old picture and asks for the new one in full; another
// client resizing the desktop (reason 2) is such a change, and the reason 1 this client never
// asks for is refused.
func TestRealResizeAsksForTheWholeNewDesktop(t *testing.T) {
	s, server := pipeSession(t, 4, 3)
	go func() { _ = writeFull(server, extendedDesktopSize(2, 8, 6)) }()
	result := make(chan error, 1)
	go func() { result <- s.readServerMessage() }()
	var request [10]byte
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(server, request[:]); err != nil {
		t.Fatal(err)
	}
	if request[0] != 3 || request[1] != 0 || binary.BigEndian.Uint16(request[6:8]) != 8 || binary.BigEndian.Uint16(request[8:10]) != 6 {
		t.Fatalf("after a resize: request %v, want a full one of 8x6", request)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if s.width != 8 || s.height != 6 || s.framebuffer.Bounds().Dx() != 8 {
		t.Fatalf("framebuffer stayed %dx%d", s.width, s.height)
	}

	s2, server2 := pipeSession(t, 4, 3)
	go func() {
		_ = writeFull(server2, extendedDesktopSize(1, 8, 6))
		_, _ = io.Copy(io.Discard, server2)
	}()
	if err := s2.readServerMessage(); !errors.Is(err, ErrInvalidFramebuffer) {
		t.Fatalf("an answer to a request never made: %v", err)
	}
}

// A clipboard larger than a credential field is an ordinary event on a real desktop: it is read
// and thrown away, without ending the session and without reaching anything.
func TestLargeServerCutTextIsDiscardedAndAbsurdOneRefused(t *testing.T) {
	cut := func(n uint32) []byte {
		m := []byte{2, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(m[4:], n)
		return m
	}
	s, server := pipeSession(t, 1, 1)
	const size = 256 << 10
	go func() {
		_ = writeFull(server, cut(size))
		_ = writeFull(server, make([]byte, size))
	}()
	if err := s.readServerMessage(); err != nil {
		t.Fatalf("256 KiB of clipboard ended the session: %v", err)
	}

	s2, server2 := pipeSession(t, 1, 1)
	go func() {
		_ = writeFull(server2, cut(maxServerCutText+1))
		_, _ = io.Copy(io.Discard, server2)
	}()
	_ = s2.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := s2.readServerMessage(); !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("oversized clipboard: %v", err)
	}
}

// Losing the focus lifts the buttons where the pointer is: moving it to a corner is an action
// the operator did not take, on a privileged desktop.
func TestReleaseAllKeepsThePointerWhereItIs(t *testing.T) {
	s, server := pipeSession(t, 100, 100)
	done := make(chan error, 1)
	go func() {
		if err := s.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 40, Y: 30, Buttons: 1}); err != nil {
			done <- err
			return
		}
		done <- s.Input(screenstream.InputEvent{Type: screenstream.InputReleaseAll})
	}()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	var msgs [12]byte
	if _, err := io.ReadFull(server, msgs[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	release := msgs[6:]
	if release[1] != 0 || binary.BigEndian.Uint16(release[2:4]) != 40 || binary.BigEndian.Uint16(release[4:6]) != 30 {
		t.Fatalf("release = %v, want buttons up at 40,30", release)
	}
}

// Input out of the table never reaches the target (ADR-0071 §6): the adapter refuses, and the
// relay closes the session on that refusal.
func TestKeysymOutOfTheTableAndKeyFloodNeverReachTheTarget(t *testing.T) {
	s, server := pipeSession(t, 10, 10)
	seen := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, server)
		seen <- n
	}()
	for _, k := range []uint32{0, 0x1b, 0x7f, 0x9f, 0x2100, 0xfdff, 0x10000, 0x01000000, 0x01110000, 0xffffffff} {
		if err := s.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: k}); !errors.Is(err, screenstream.ErrOutOfBounds) {
			t.Errorf("keysym %#x: %v, want a refusal", k, err)
		}
	}
	s.conn.Close()
	if n := <-seen; n != 0 {
		t.Fatalf("%d bytes reached the target", n)
	}

	s2, server2 := pipeSession(t, 10, 10)
	go func() { _, _ = io.Copy(io.Discard, server2) }()
	for i := 0; i < maxPressedKeys; i++ {
		if err := s2.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x100 + uint32(i)}); err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
	}
	if err := s2.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61}); !errors.Is(err, screenstream.ErrOutOfBounds) {
		t.Fatalf("one key too many: %v", err)
	}
	if err := s2.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x100}); err != nil {
		t.Fatalf("auto-repeat of a held key: %v", err)
	}
}

// The interval paces what a busy desktop costs in PNG encoding and recorded bytes: no update is
// asked for before it, and closing the session does not wait for it.
func TestFrameIntervalDelaysTheNextRequestAndCloseInterruptsIt(t *testing.T) {
	s, server := pipeSession(t, 1, 1)
	s.frameInterval = 80 * time.Millisecond
	rawUpdate := func() []byte {
		var m bytes.Buffer
		m.Write([]byte{0, 0, 0, 1})
		var rect [12]byte
		binary.BigEndian.PutUint16(rect[4:6], 1)
		binary.BigEndian.PutUint16(rect[6:8], 1)
		m.Write(rect[:])
		m.Write([]byte{1, 2, 3, 0})
		return m.Bytes()
	}
	go func() { _ = writeFull(server, rawUpdate()) }()
	result := make(chan error, 1)
	go func() { result <- s.readServerMessage() }()
	<-s.frames
	received := time.Now()
	var request [10]byte
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(server, request[:]); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(received); waited < 60*time.Millisecond {
		t.Fatalf("the next update was asked for after %v, before the interval", waited)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}

	s.frameInterval = time.Hour
	go func() { _ = writeFull(server, rawUpdate()) }()
	go func() { result <- s.readServerMessage() }()
	<-s.frames
	_ = s.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed during the wait: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not interrupt the wait")
	}
}
