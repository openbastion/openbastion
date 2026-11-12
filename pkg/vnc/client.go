// Package vnc implements the deliberately small, fail-closed RFB 3.8 client
// described by ADR-0071. It accepts only VeNCrypt X.509 security and bounded
// framebuffer encodings; it is not a general-purpose VNC implementation.
package vnc

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/pkg/tlspin"
)

const (
	protocolVersion            = "RFB 003.008\n"
	securityVeNCrypt           = byte(19)
	vencryptX509VNC     uint32 = 261
	vencryptX509Plain   uint32 = 262
	maxDesktopName             = 4096
	maxAuthField               = 4096
	maxFramebufferBytes        = 64 << 20
	maxRectangles              = 4096
	// A target's clipboard is read and thrown away (ADR-0071 §5), so this bound protects
	// nothing but the read loop: an operator copying a page on the target must not end the session.
	maxServerCutText = 16 << 20
	// A session holds few keys down; more than this is not a keyboard.
	maxPressedKeys = 64
)

var (
	ErrUnsupportedProtocol = errors.New("vnc: unsupported RFB or security negotiation")
	ErrInvalidTarget       = errors.New("vnc: invalid target configuration")
	ErrInvalidFramebuffer  = errors.New("vnc: invalid framebuffer update")
	ErrAuthentication      = errors.New("vnc: target authentication failed")
	ErrTLSVerification     = errors.New("vnc: target TLS verification failed")
	// ErrTargetRefused is the target saying no before any negotiation, with its own reason: too
	// many failures, too many clients. Nothing about it is unsupported.
	ErrTargetRefused = errors.New("vnc: the target refused the connection")
	// The refusals the operator is told apart (ADR-0071 §12); each remains what it wraps.
	ErrProtocolVersion    = fmt.Errorf("%w: not RFB 3.8 with VeNCrypt 0.2", ErrUnsupportedProtocol)
	ErrTLSRequired        = fmt.Errorf("%w: no VeNCrypt X.509 security", ErrUnsupportedProtocol)
	ErrPasswordTruncation = fmt.Errorf("%w: X509Vnc would truncate the password", ErrInvalidTarget)
	errLastRect           = errors.New("vnc: last rectangle marker")
)

// Config must be populated from the Vault-issued target identity and the
// credential for this session. Roots are explicit; system roots are never
// selected implicitly. Open clears the Client's reference to Password and only
// retains a temporary copy during authentication; the caller still owns and
// must purge the original credential.
type Config struct {
	Address        string
	Username       string
	Password       []byte
	TLSFingerprint string
	TLSRoots       *x509.CertPool
	TLSServerName  string
	DialTimeout    time.Duration
	// FrameInterval is the least time between two frames (SCREEN_FRAME_INTERVAL_MS, ADR-0071
	// §8). The next update is asked for only then: the target coalesces what changed meanwhile,
	// and nothing is dropped. Zero asks at once.
	FrameInterval time.Duration
	// DrawPointer draws the target's pointer into each frame, where the operator put it
	// (SCREEN_DRAW_POINTER, ADR-0091): its shape comes from the Cursor pseudo-encoding. Off, the
	// shape is read and thrown away, as before, and no frame carries a pointer.
	DrawPointer bool
	// PartialFrames sends partial frames anchored on key frames (SCREEN_PARTIAL_FRAMES, ADR-0092):
	// what differs from the frame before, not the whole screen at every change.
	PartialFrames bool
}

// Client opens one target session. A Client is intended for one session only.
type Client struct{ Config Config }

func (c *Client) Open(ctx context.Context) (*Session, error) {
	cfg := c.Config
	// Client is single-use; don't keep a reference to credential material after
	// entering Open, even if validation or the network handshake later fails.
	c.Config.Password = nil
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" || port == "" {
		return nil, ErrInvalidTarget
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, ErrInvalidTarget
	}
	if cfg.Username == "" || len(cfg.Username) > maxAuthField || len(cfg.Password) == 0 || len(cfg.Password) > maxAuthField || cfg.TLSRoots == nil || cfg.TLSFingerprint == "" {
		return nil, ErrInvalidTarget
	}
	serverName := cfg.TLSServerName
	if serverName == "" {
		serverName = host
	}
	tlsConfig, err := tlspin.ServerConfig(cfg.TLSFingerprint, cfg.TLSRoots, serverName)
	if err != nil {
		return nil, fmt.Errorf("%w: TLS pin configuration", ErrInvalidTarget)
	}
	password := append([]byte(nil), cfg.Password...)
	cfg.Password = nil
	defer zero(password)

	if cfg.DialTimeout < 0 || cfg.FrameInterval < 0 {
		return nil, ErrInvalidTarget
	}
	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("vnc: target connection failed")
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	ok := false
	defer func() {
		if !ok {
			stopCancel()
			_ = conn.Close()
		}
	}()
	if deadline, exists := dialCtx.Deadline(); exists {
		_ = conn.SetDeadline(deadline)
	}
	if err := handshakeRFB(conn); err != nil {
		return nil, err
	}
	subtype, err := negotiateVeNCrypt(conn)
	if err != nil {
		return nil, err
	}
	if subtype == vencryptX509VNC && len(password) > 8 {
		return nil, ErrPasswordTruncation
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return nil, ErrTLSVerification
	}
	if subtype == vencryptX509Plain {
		err = authenticatePlain(tlsConn, cfg.Username, password)
	} else {
		err = authenticateVNC(tlsConn, password)
	}
	if err != nil {
		return nil, err
	}
	// RFB ClientInit must precede ServerInit even when VeNCrypt wraps TLS.
	if err := writeFull(tlsConn, []byte{1}); err != nil {
		return nil, err
	}
	width, height, err := readServerInit(tlsConn)
	if err != nil {
		return nil, err
	}
	if err := configurePixelFormatAndEncodings(tlsConn); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	s := &Session{conn: tlsConn, frames: make(chan screenstream.Message), width: width, height: height, framebuffer: image.NewRGBA(image.Rect(0, 0, int(width), int(height))), pressed: make(map[uint32]struct{}), done: make(chan struct{}), frameInterval: cfg.FrameInterval}
	if cfg.DrawPointer {
		s.drawPointer, s.pointerMoved = true, make(chan struct{}, 1)
	}
	if cfg.PartialFrames {
		s.partial, s.keyWanted = &screenstream.FrameEncoder{}, make(chan struct{}, 1)
	}
	if s.drawPointer || s.partial != nil {
		s.pointerLoopDone = make(chan struct{})
	}
	if err := s.requestUpdate(false); err != nil {
		return nil, err
	}
	stopCancel()
	s.stopCancel = context.AfterFunc(ctx, func() { s.signalDone(); _ = conn.Close() })
	ok = true
	if s.pointerLoopDone != nil {
		go s.pointerLoop()
	}
	go s.readLoop()
	return s, nil
}

// Session exposes full PNG frames and validated normalized input. Frames are
// never dropped: backpressure propagates to the target reader and recorder.
type Session struct {
	conn            net.Conn
	frames          chan screenstream.Message
	width, height   uint32
	framebuffer     *image.RGBA
	writeMu         sync.Mutex
	mu              sync.Mutex
	closeOnce       sync.Once
	doneOnce        sync.Once
	done            chan struct{}
	err             error
	pressed         map[uint32]struct{}
	pointerX        uint16
	pointerY        uint16
	sequence        uint64
	updatePixels    uint64
	forceFullUpdate bool
	frameInterval   time.Duration
	stopCancel      func() bool
	// The pointer drawn into the frames (Config.DrawPointer, ADR-0091). frameMu orders the frames
	// of the reader (an update applied, then encoded) and of pointerLoop (a move, encoded): one
	// framebuffer, one sequence. cursor is the reader's; pointerPlaced, like pointerX and pointerY,
	// is under mu.
	drawPointer     bool
	frameMu         sync.Mutex
	cursor          *cursor
	pointerPlaced   bool
	pointerMoved    chan struct{}
	pointerLoopDone chan struct{}
	// partial makes the frames of ADR-0092 (Config.PartialFrames); keyWanted tells pointerLoop the
	// relay wants a key frame (RequestKeyFrame). Both nil without partial frames.
	partial   *screenstream.FrameEncoder
	keyWanted chan struct{}
}

// RequestKeyFrame makes a key frame now, even on a still screen: the operator's display, fallen
// behind, dropped partial frames and waits for it (ADR-0092).
func (s *Session) RequestKeyFrame() {
	if s.keyWanted == nil {
		return
	}
	select {
	case s.keyWanted <- struct{}{}:
	default: // one is already wanted
	}
}

// PointerDrawn says the frames carry the pointer: the HELLO tells the operator's browser, which
// hides its own (ADR-0091).
func (s *Session) PointerDrawn() bool { return s.drawPointer }

func (s *Session) signalDone() { s.doneOnce.Do(func() { close(s.done) }) }

func (s *Session) Frames() <-chan screenstream.Message { return s.frames }

func (s *Session) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.signalDone()
		if s.stopCancel != nil {
			s.stopCancel()
		}
		err = s.conn.Close()
	})
	return err
}

func (s *Session) Input(e screenstream.InputEvent) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch e.Type {
	case screenstream.InputKey:
		if (e.Flags != screenstream.KeyPressed && e.Flags != screenstream.KeyReleased) || !validKeysym(e.Keysym) || e.X != 0 || e.Y != 0 || e.Buttons != 0 || e.Wheel != 0 {
			return screenstream.ErrOutOfBounds
		}
		if e.Flags == screenstream.KeyPressed {
			if _, held := s.pressed[e.Keysym]; !held && len(s.pressed) >= maxPressedKeys {
				return screenstream.ErrOutOfBounds
			}
			s.pressed[e.Keysym] = struct{}{}
		} else {
			delete(s.pressed, e.Keysym)
		}
		return s.writeKey(e.Keysym, e.Flags == screenstream.KeyPressed)
	case screenstream.InputPointer:
		if uint32(e.X) >= s.width || uint32(e.Y) >= s.height || e.Buttons & ^screenstream.AllowedPointerButtons != 0 || e.Wheel < -1 || e.Wheel > 1 {
			return screenstream.ErrOutOfBounds
		}
		moved := e.X != s.pointerX || e.Y != s.pointerY || !s.pointerPlaced
		s.pointerX, s.pointerY = e.X, e.Y
		if s.drawPointer && moved {
			s.pointerPlaced = true
			select {
			case s.pointerMoved <- struct{}{}:
			default: // a frame is already wanted
			}
		}
		mask := e.Buttons
		if e.Wheel > 0 {
			mask |= 1 << 3
		}
		if e.Wheel < 0 {
			mask |= 1 << 4
		}
		if err := s.writePointer(mask, e.X, e.Y); err != nil {
			return err
		}
		if e.Wheel != 0 {
			return s.writePointer(e.Buttons, e.X, e.Y)
		}
		return nil
	case screenstream.InputReleaseAll:
		if e.Flags != 0 || e.Keysym != 0 || e.Scancode != 0 || e.X != 0 || e.Y != 0 || e.Buttons != 0 || e.Wheel != 0 {
			return screenstream.ErrMalformedMessage
		}
		for key := range s.pressed {
			if err := s.writeKey(key, false); err != nil {
				return err
			}
			delete(s.pressed, key)
		}
		// Buttons up where the pointer already is: losing the focus must not move it.
		return s.writePointer(0, s.pointerX, s.pointerY)
	default:
		return screenstream.ErrUnsupported
	}
}

// validKeysym is the key table of ADR-0071 §6: printable Latin-1, the legacy X11 groups, ISO and
// function keys, and Unicode keysyms. Anything else is not a key and closes the session.
func validKeysym(k uint32) bool {
	switch {
	case k >= 0x20 && k <= 0x7e, k >= 0xa0 && k <= 0xff:
		return true
	case k >= 0x100 && k <= 0x20ff:
		return true
	case k >= 0xfe00 && k <= 0xffff:
		return true
	case k >= 0x01000100 && k <= 0x0110ffff:
		return true
	}
	return false
}

func (s *Session) writeKey(key uint32, down bool) error {
	var msg [8]byte
	msg[0] = 4
	if down {
		msg[1] = 1
	}
	binary.BigEndian.PutUint32(msg[4:], key)
	return writeFull(s.conn, msg[:])
}
func (s *Session) writePointer(buttons byte, x, y uint16) error {
	var msg [6]byte
	msg[0] = 5
	msg[1] = buttons
	binary.BigEndian.PutUint16(msg[2:], x)
	binary.BigEndian.PutUint16(msg[4:], y)
	return writeFull(s.conn, msg[:])
}
func (s *Session) requestUpdate(incremental bool) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	width, height := s.width, s.height
	s.mu.Unlock()
	var msg [10]byte
	msg[0] = 3
	if incremental {
		msg[1] = 1
	}
	binary.BigEndian.PutUint16(msg[6:], uint16(width))
	binary.BigEndian.PutUint16(msg[8:], uint16(height))
	return writeFull(s.conn, msg[:])
}

func (s *Session) readLoop() {
	defer close(s.frames)
	if s.pointerLoopDone != nil {
		// pointerLoop sends frames too: it stops before the channel closes.
		defer func() { <-s.pointerLoopDone }()
		defer s.signalDone()
	}
	for {
		if err := s.readServerMessage(); err != nil {
			s.mu.Lock()
			if s.err == nil && !errors.Is(err, net.ErrClosed) {
				s.err = err
			}
			s.mu.Unlock()
			return
		}
	}
}

func (s *Session) readServerMessage() error {
	var kind [1]byte
	if _, err := io.ReadFull(s.conn, kind[:]); err != nil {
		return err
	}
	switch kind[0] {
	case 0:
		// The update is applied and encoded whole before a pointer frame may come between.
		s.frameMu.Lock()
		locked := true
		unlock := func() {
			if locked {
				locked = false
				s.frameMu.Unlock()
			}
		}
		defer unlock()
		var hdr [3]byte
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return err
		}
		rawCount := binary.BigEndian.Uint16(hdr[1:])
		lastRectMode := rawCount == 0xffff
		count := int(rawCount)
		if !lastRectMode && count > maxRectangles {
			return ErrInvalidFramebuffer
		}
		if lastRectMode {
			count = maxRectangles
		}
		changed, sawLastRect := false, false
		s.updatePixels = 0
		for i := 0; i < count; i++ {
			done, err := s.readRectangle(lastRectMode)
			if errors.Is(err, errLastRect) {
				sawLastRect = true
				break
			}
			if err != nil {
				return err
			}
			changed = changed || done
		}
		if lastRectMode && !sawLastRect {
			return ErrInvalidFramebuffer
		}
		if changed {
			if err := s.emitFrame(); err != nil {
				return err
			}
			unlock()
			if err := s.waitFrameInterval(); err != nil {
				return err
			}
		}
		if s.forceFullUpdate {
			s.forceFullUpdate = false
			return s.requestUpdate(false)
		}
		return s.requestUpdate(true)
	case 1: // Bell: intentionally ignored.
		return nil
	case 2: // ServerCutText: consume bounded text, never expose clipboard.
		var hdr [7]byte
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(hdr[3:])
		if n > maxServerCutText {
			return ErrUnsupportedProtocol
		}
		return discardN(s.conn, uint64(n))
	default:
		return ErrUnsupportedProtocol
	}
}

func (s *Session) readRectangle(allowLastRect bool) (bool, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return false, err
	}
	x, y, w, h := binary.BigEndian.Uint16(hdr[0:2]), binary.BigEndian.Uint16(hdr[2:4]), binary.BigEndian.Uint16(hdr[4:6]), binary.BigEndian.Uint16(hdr[6:8])
	enc := int32(binary.BigEndian.Uint32(hdr[8:12]))
	switch enc {
	case 0: // Raw, 32-bit little-endian true colour.
		s.updatePixels += uint64(w) * uint64(h)
		if s.updatePixels > screenstream.MaxPixels {
			return false, ErrInvalidFramebuffer
		}
		if w == 0 || h == 0 || uint32(x)+uint32(w) > s.width || uint32(y)+uint32(h) > s.height || uint64(w)*uint64(h)*4 > maxFramebufferBytes {
			return false, ErrInvalidFramebuffer
		}
		row := make([]byte, int(w)*4)
		for yy := uint16(0); yy < h; yy++ {
			if _, err := io.ReadFull(s.conn, row); err != nil {
				return false, err
			}
			for xx := uint16(0); xx < w; xx++ {
				i := int(xx) * 4
				s.framebuffer.SetRGBA(int(x+xx), int(y+yy), color.RGBA{R: row[i+2], G: row[i+1], B: row[i], A: 255})
			}
		}
		return true, nil
	case 1: // CopyRect.
		s.updatePixels += uint64(w) * uint64(h)
		if s.updatePixels > screenstream.MaxPixels {
			return false, ErrInvalidFramebuffer
		}
		if w == 0 || h == 0 || uint32(x)+uint32(w) > s.width || uint32(y)+uint32(h) > s.height {
			return false, ErrInvalidFramebuffer
		}
		var src [4]byte
		if _, err := io.ReadFull(s.conn, src[:]); err != nil {
			return false, err
		}
		sx, sy := binary.BigEndian.Uint16(src[:2]), binary.BigEndian.Uint16(src[2:])
		if uint32(sx)+uint32(w) > s.width || uint32(sy)+uint32(h) > s.height {
			return false, ErrInvalidFramebuffer
		}
		// Copy through a temporary buffer to preserve overlapping rectangles.
		tmp := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
		for yy := 0; yy < int(h); yy++ {
			for xx := 0; xx < int(w); xx++ {
				tmp.Set(xx, yy, s.framebuffer.At(int(sx)+xx, int(sy)+yy))
			}
		}
		for yy := 0; yy < int(h); yy++ {
			for xx := 0; xx < int(w); xx++ {
				s.framebuffer.Set(int(x)+xx, int(y)+yy, tmp.At(xx, yy))
			}
		}
		return true, nil
	case -223: // DesktopSize.
		if x != 0 || y != 0 {
			return false, ErrInvalidFramebuffer
		}
		return s.resize(uint32(w), uint32(h))
	case -308: // ExtendedDesktopSize, exactly one screen.
		// x is why (0: the server, 2: another client; 1 answers a request this client never
		// makes) and y the status, for which only success says anything about the size.
		if (x != 0 && x != 2) || y != 0 {
			return false, ErrInvalidFramebuffer
		}
		var prefix [4]byte
		if _, err := io.ReadFull(s.conn, prefix[:]); err != nil {
			return false, err
		}
		if prefix[0] != 1 || prefix[1] != 0 || prefix[2] != 0 || prefix[3] != 0 {
			return false, ErrUnsupportedProtocol
		}
		var screen [16]byte
		if _, err := io.ReadFull(s.conn, screen[:]); err != nil {
			return false, err
		}
		if binary.BigEndian.Uint16(screen[4:6]) != 0 || binary.BigEndian.Uint16(screen[6:8]) != 0 || binary.BigEndian.Uint16(screen[8:10]) != w || binary.BigEndian.Uint16(screen[10:12]) != h {
			return false, ErrUnsupportedProtocol
		}
		return s.resize(uint32(w), uint32(h))
	case -239: // Cursor shape: pixels and a 1-bit mask; drawn when the pointer is (ADR-0091).
		if s.drawPointer {
			shape, err := readCursor(s.conn, x, y, w, h)
			if err != nil {
				return false, err
			}
			s.cursor = shape
			s.mu.Lock()
			placed := s.pointerPlaced
			s.mu.Unlock()
			return placed, nil // a new shape where the pointer shows is a new frame
		}
		if uint64(w)*uint64(h)*4 > maxFramebufferBytes {
			return false, ErrInvalidFramebuffer
		}
		if err := discardN(s.conn, uint64(w)*uint64(h)*4+uint64((w+7)/8)*uint64(h)); err != nil {
			return false, err
		}
		return false, nil
	case -224: // LastRect.
		if !allowLastRect {
			return false, ErrUnsupportedProtocol
		}
		return false, errLastRect
	default:
		return false, ErrUnsupportedProtocol
	}
}

func (s *Session) resize(w, h uint32) (bool, error) {
	if w == 0 || h == 0 || uint64(w)*uint64(h) > screenstream.MaxPixels || uint64(w)*uint64(h)*4 > maxFramebufferBytes {
		return false, ErrInvalidFramebuffer
	}
	s.mu.Lock()
	unchanged := s.width == w && s.height == h
	if !unchanged {
		s.width, s.height = w, h
		s.framebuffer = image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	}
	s.mu.Unlock()
	// A server may answer every full request with the size it already announced, and nothing
	// else (TigerVNC does): asking again for a full update would then never get a pixel.
	s.forceFullUpdate = s.forceFullUpdate || !unchanged
	return false, nil
}
func (s *Session) emitFrame() error {
	picture := s.framebuffer
	s.mu.Lock()
	placed, x, y := s.pointerPlaced, int(s.pointerX), int(s.pointerY)
	s.mu.Unlock()
	if s.drawPointer && placed && s.cursor != nil && s.cursor.width > 0 {
		// On a copy: the framebuffer stays the target's screen (ADR-0091 §1).
		picture = &image.RGBA{Pix: append([]byte(nil), s.framebuffer.Pix...), Stride: s.framebuffer.Stride, Rect: s.framebuffer.Rect}
		s.cursor.drawOn(picture, x, y)
	}
	if s.partial != nil {
		// What differs from the frame before; nothing, no frame (ADR-0092).
		msg, err := s.partial.Encode(picture, s.sequence+1, time.Now().UTC())
		if errors.Is(err, screenstream.ErrUnchanged) {
			return nil
		}
		if errors.Is(err, screenstream.ErrFrameTooLarge) {
			return fmt.Errorf("%w: %w", ErrInvalidFramebuffer, err)
		}
		if err != nil {
			return err
		}
		s.sequence++
		select {
		case s.frames <- msg:
			return nil
		case <-s.done:
			return net.ErrClosed
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, picture); err != nil {
		return err
	}
	if buf.Len() > screenstream.MaxPNGBytes {
		// A screen that cannot be recorded ends the session as a recording loss (ADR-0070).
		return fmt.Errorf("%w: %d-byte PNG: %w", ErrInvalidFramebuffer, buf.Len(), screenstream.ErrFrameTooLarge)
	}
	if buf.Len() == 0 {
		return ErrInvalidFramebuffer
	}
	s.sequence++
	msg := screenstream.Message{Type: screenstream.TypeFrame, Sequence: s.sequence, Timestamp: time.Now().UTC(), Width: s.width, Height: s.height, PNG: buf.Bytes()}
	if _, err := screenstream.Encode(msg); err != nil {
		return err
	}
	select {
	case s.frames <- msg:
		return nil
	case <-s.done:
		return net.ErrClosed
	}
}

// pointerLoop makes a frame of the operator's moves, which the target does not answer: with the
// Cursor pseudo-encoding the pointer is not in its framebuffer. One frame a interval at most, the
// latest position; none before the first frame of the target, nor before it sent a shape.
func (s *Session) pointerLoop() {
	defer close(s.pointerLoopDone)
	for {
		select {
		case <-s.done:
			return
		case <-s.pointerMoved: // nil, and never ready, when the pointer is not drawn
		case <-s.keyWanted: // nil without partial frames
			s.frameMu.Lock()
			s.partial.Reset()
			s.frameMu.Unlock()
		}
		s.frameMu.Lock()
		var err error
		if s.sequence > 0 && (s.cursor != nil || s.partial != nil) {
			err = s.emitFrame()
		}
		s.frameMu.Unlock()
		if err != nil {
			s.mu.Lock()
			if s.err == nil && !errors.Is(err, net.ErrClosed) {
				s.err = err
			}
			s.mu.Unlock()
			_ = s.conn.Close() // the reader stops, and the session ends with this error
			return
		}
		if s.waitFrameInterval() != nil {
			return
		}
	}
}

func (s *Session) waitFrameInterval() error {
	if s.frameInterval <= 0 {
		return nil
	}
	timer := time.NewTimer(s.frameInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-s.done:
		return net.ErrClosed
	}
}

func handshakeRFB(conn net.Conn) error {
	var version [12]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return err
	}
	if string(version[:]) != protocolVersion {
		return ErrProtocolVersion
	}
	if err := writeFull(conn, []byte(protocolVersion)); err != nil {
		return err
	}
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		return err
	}
	if count[0] == 0 {
		n, err := readLength(conn, 4096)
		if err != nil {
			return err
		}
		_ = discardN(conn, uint64(n))
		return ErrTargetRefused
	}
	types := make([]byte, int(count[0]))
	if _, err := io.ReadFull(conn, types); err != nil {
		return err
	}
	found := false
	for _, v := range types {
		if v == securityVeNCrypt {
			found = true
		}
	}
	if !found {
		return ErrTLSRequired
	}
	return writeFull(conn, []byte{securityVeNCrypt})
}
func negotiateVeNCrypt(conn net.Conn) (uint32, error) {
	var version [2]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return 0, err
	}
	if version[0] != 0 || version[1] != 2 {
		return 0, ErrProtocolVersion
	}
	if err := writeFull(conn, []byte{0, 2}); err != nil {
		return 0, err
	}
	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return 0, err
	}
	if status[0] != 0 {
		return 0, ErrProtocolVersion
	}
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		return 0, err
	}
	if count[0] == 0 {
		return 0, ErrTLSRequired
	}
	raw := make([]byte, int(count[0])*4)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return 0, err
	}
	supported := map[uint32]bool{}
	for i := 0; i < len(raw); i += 4 {
		supported[binary.BigEndian.Uint32(raw[i:i+4])] = true
	}
	chosen := uint32(0)
	if supported[vencryptX509Plain] {
		chosen = vencryptX509Plain
	} else if supported[vencryptX509VNC] {
		chosen = vencryptX509VNC
	} else {
		return 0, ErrTLSRequired
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], chosen)
	if err := writeFull(conn, out[:]); err != nil {
		return 0, err
	}
	// Unlike the status of the version above, this one says yes with 1: the server accepted
	// the subtype and TLS starts now. 0 is its refusal, never an invitation to continue.
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return 0, err
	}
	if status[0] != 1 {
		return 0, ErrTLSRequired
	}
	return chosen, nil
}
func authenticatePlain(conn net.Conn, username string, password []byte) error {
	// VeNCrypt X509Plain sends two 32-bit length-prefixed fields inside TLS.
	if len(username) == 0 || len(username) > maxAuthField || len(password) == 0 || len(password) > maxAuthField {
		return ErrInvalidTarget
	}
	var lens [8]byte
	binary.BigEndian.PutUint32(lens[:4], uint32(len(username)))
	binary.BigEndian.PutUint32(lens[4:], uint32(len(password)))
	if err := writeFull(conn, lens[:]); err != nil {
		return err
	}
	if err := writeFull(conn, []byte(username)); err != nil {
		return err
	}
	if err := writeFull(conn, password); err != nil {
		return err
	}
	return readSecurityResult(conn)
}
func authenticateVNC(conn net.Conn, password []byte) error {
	if len(password) > 8 {
		return ErrPasswordTruncation
	}
	var challenge [16]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return err
	}
	var key [8]byte
	copy(key[:], password)
	for i := range key {
		key[i] = reverseBits(key[i])
	}
	block, err := des.NewCipher(key[:])
	zero(key[:])
	if err != nil {
		return err
	}
	var response [16]byte
	block.Encrypt(response[:8], challenge[:8])
	block.Encrypt(response[8:], challenge[8:])
	if err := writeFull(conn, response[:]); err != nil {
		return err
	}
	return readSecurityResult(conn)
}
func readSecurityResult(conn net.Conn) error {
	var status [4]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(status[:]) == 0 {
		return nil
	}
	n, err := readLength(conn, 4096)
	if err == nil {
		_ = discardN(conn, uint64(n))
	}
	return ErrAuthentication
}
func readServerInit(conn net.Conn) (uint32, uint32, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, 0, err
	}
	w, h := binary.BigEndian.Uint16(hdr[:2]), binary.BigEndian.Uint16(hdr[2:4])
	if w == 0 || h == 0 || uint64(w)*uint64(h) > screenstream.MaxPixels || uint64(w)*uint64(h)*4 > maxFramebufferBytes {
		return 0, 0, ErrInvalidFramebuffer
	}
	bpp, depth := hdr[4], hdr[5]
	if (bpp != 8 && bpp != 16 && bpp != 32) || depth == 0 || depth > bpp || hdr[6] > 1 || hdr[7] > 1 {
		return 0, 0, ErrUnsupportedProtocol
	}
	nameLen := binary.BigEndian.Uint32(hdr[20:24])
	if nameLen > maxDesktopName {
		return 0, 0, ErrUnsupportedProtocol
	}
	if err := discardN(conn, uint64(nameLen)); err != nil {
		return 0, 0, err
	}
	return uint32(w), uint32(h), nil
}
func configurePixelFormatAndEncodings(conn net.Conn) error {
	// SetPixelFormat: 32bpp, depth 24, little-endian true colour, RGB shifts 16/8/0.
	var pf [20]byte
	pf[0] = 0
	pf[4] = 32
	pf[5] = 24
	pf[6] = 0
	pf[7] = 1
	binary.BigEndian.PutUint16(pf[8:10], 255)
	binary.BigEndian.PutUint16(pf[10:12], 255)
	binary.BigEndian.PutUint16(pf[12:14], 255)
	pf[14] = 16
	pf[15] = 8
	pf[16] = 0
	if err := writeFull(conn, pf[:]); err != nil {
		return err
	}
	enc := []int32{0, 1, -223, -308, -239, -224}
	var msg bytes.Buffer
	msg.Write([]byte{2, 0})
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(enc)))
	msg.Write(n[:])
	for _, e := range enc {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(e))
		msg.Write(b[:])
	}
	return writeFull(conn, msg.Bytes())
}
func readLength(r io.Reader, max uint32) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(b[:])
	if n > max {
		return 0, ErrUnsupportedProtocol
	}
	return n, nil
}
func discardN(r io.Reader, n uint64) error {
	if n > maxFramebufferBytes {
		return ErrUnsupportedProtocol
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func reverseBits(v byte) byte {
	v = (v&0xF0)>>4 | (v&0x0F)<<4
	v = (v&0xCC)>>2 | (v&0x33)<<2
	return (v&0xAA)>>1 | (v&0x55)<<1
}
