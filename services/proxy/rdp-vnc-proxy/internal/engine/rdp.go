package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

var ErrRDPConfiguration = errors.New("rdp-vnc-proxy: RDP target metadata is incomplete")

const (
	rdpDefaultDesktopWidth  = uint16(1280)
	rdpDefaultDesktopHeight = uint16(800)
	rdpClientName           = "OPENBASTION"
	rdpReadTimeout          = 24 * time.Hour
	rdpInputTimeout         = 2 * time.Second
)

// RDPCodec adapts the strict RDP client to the shared screen lifecycle. It is
// deliberately not selected by the proxy runtime until real Windows/RDS
// interoperability and end-to-end recording have been validated.
type RDPCodec struct {
	TLSRoots      *x509.CertPool
	DialTimeout   time.Duration
	DesktopWidth  uint16
	DesktopHeight uint16
	FrenchLocale  bool
	InputTimeout  time.Duration
	openSession   func(context.Context, *proxycore.Credential) (rdpScreenSession, error)
}

var _ proxycore.ScreenCodec = (*RDPCodec)(nil)

type rdpScreenSession interface {
	ReadBitmapUpdate(context.Context, time.Duration) (rdp.RDPBitmapUpdate, error)
	SendInput(context.Context, []rdp.RDPInputEvent, time.Duration) error
	Dimensions() (uint16, uint16)
	Close()
}

func (c *RDPCodec) Open(ctx context.Context, cred *proxycore.Credential) (proxycore.ScreenSession, error) {
	if c == nil || c.TLSRoots == nil || cred == nil || cred.Type != "password" ||
		cred.TargetHost == "" || cred.TargetUser == "" || cred.TLSCertificateSHA256 == "" || cred.TargetDomain == "" ||
		c.DialTimeout < 0 || c.InputTimeout < 0 {
		return nil, &proxycore.ScreenFailure{Code: "pin_missing", Err: ErrRDPConfiguration}
	}
	var target rdpScreenSession
	var err error
	if c.openSession != nil {
		target, err = c.openSession(ctx, cred)
	} else {
		target, err = c.openRDPSession(ctx, cred)
	}
	if err != nil {
		code := "target_unreachable"
		switch {
		case errors.Is(err, rdp.ErrInvalidTarget):
			code = "pin_missing"
		case errors.Is(err, rdp.ErrTLSVerification):
			code = "pin_mismatch"
		case errors.Is(err, rdp.ErrUnsupportedProtocol):
			code = "nla_required"
		case errors.Is(err, rdp.ErrMCSConnection):
			code = "codec_unsupported"
		}
		return nil, &proxycore.ScreenFailure{Code: code, Err: err}
	}
	if target == nil {
		return nil, &proxycore.ScreenFailure{Code: "target_unreachable", Err: rdp.ErrMCSConnection}
	}
	if err := ctx.Err(); err != nil {
		target.Close()
		return nil, err
	}
	width, height := target.Dimensions()
	framebuffer, err := rdp.NewRDPFramebuffer(width, height)
	if err != nil {
		target.Close()
		return nil, &proxycore.ScreenFailure{Code: "codec_unsupported", Err: err}
	}
	// The session lifetime is explicitly owned by ScreenSession.Close. Keeping
	// it independent from the request context lets Close release held keys and
	// mouse buttons before canceling the blocked TLS reader.
	sessionCtx, cancel := context.WithCancel(context.Background())
	inputTimeout := c.InputTimeout
	if inputTimeout == 0 {
		inputTimeout = rdpInputTimeout
	}
	s := &rdpScreenSessionAdapter{target: target, framebuffer: framebuffer, frames: make(chan screenstream.Message), cancel: cancel, done: make(chan struct{}),
		inputTimeout: inputTimeout, width: width, height: height, pressedKeys: make(map[uint16]bool)}
	go s.readLoop(sessionCtx)
	return s, nil
}

func (c *RDPCodec) openRDPSession(ctx context.Context, cred *proxycore.Credential) (rdpScreenSession, error) {
	transport, err := rdp.DialHybrid(ctx, rdp.TransportConfig{
		Address: cred.TargetHost, TLSFingerprint: cred.TLSCertificateSHA256,
		TLSRoots: c.TLSRoots, TLSServerName: cred.TargetDomain, DialTimeout: c.DialTimeout,
	})
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = transport.Close()
		}
	}()
	client, err := transport.EstablishCredSSP(ctx, rdp.CredSSPClientConfig{
		Version: 6, Username: cred.TargetUser, Password: cred.Material(), Timeout: c.DialTimeout,
	})
	if err != nil {
		return nil, err
	}
	width, height := c.DesktopWidth, c.DesktopHeight
	if width == 0 {
		width = rdpDefaultDesktopWidth
	}
	if height == 0 {
		height = rdpDefaultDesktopHeight
	}
	settings := rdp.MCSClientSettings{DesktopWidth: width, DesktopHeight: height, ClientName: rdpClientName, FrenchLocale: c.FrenchLocale, Timeout: c.DialTimeout}
	var negotiatedWidth, negotiatedHeight uint16
	steps := []func() error{
		func() error { _, e := client.ConnectMCS(ctx, settings); return e },
		func() error { _, e := client.ConnectMCSChannels(ctx, c.DialTimeout); return e },
		func() error {
			return client.SendClientInfo(ctx, rdp.RDPClientInfo{Username: cred.TargetUser, Password: cred.Material()}, c.DialTimeout)
		},
		func() error { return client.CompleteLicensing(ctx, c.DialTimeout) },
		func() error {
			capabilities, e := client.ExchangeCapabilities(ctx, c.DialTimeout)
			if e == nil {
				negotiatedWidth, negotiatedHeight = capabilities.DesktopWidth, capabilities.DesktopHeight
			}
			return e
		},
		func() error { _, e := client.FinalizeConnection(ctx, c.DialTimeout); return e },
	}
	for _, step := range steps {
		if ctx.Err() != nil {
			client.Close()
			return nil, ctx.Err()
		}
		if err := step(); err != nil {
			client.Close()
			return nil, err
		}
	}
	if negotiatedWidth == 0 || negotiatedHeight == 0 {
		client.Close()
		return nil, rdp.ErrMCSConnection
	}
	keep = true
	return &rdpTargetSession{session: client, width: negotiatedWidth, height: negotiatedHeight}, nil
}

type rdpTargetSession struct {
	session       *rdp.CredSSPClientSession
	width, height uint16
}

func (s *rdpTargetSession) ReadBitmapUpdate(ctx context.Context, timeout time.Duration) (rdp.RDPBitmapUpdate, error) {
	return s.session.ReadBitmapUpdate(ctx, timeout)
}
func (s *rdpTargetSession) SendInput(ctx context.Context, events []rdp.RDPInputEvent, timeout time.Duration) error {
	return s.session.SendInput(ctx, events, timeout)
}
func (s *rdpTargetSession) Dimensions() (uint16, uint16) { return s.width, s.height }
func (s *rdpTargetSession) Close()                       { s.session.Close() }

type rdpScreenSessionAdapter struct {
	target       rdpScreenSession
	framebuffer  *rdp.RDPFramebuffer
	frames       chan screenstream.Message
	cancel       context.CancelFunc
	done         chan struct{}
	closeOnce    sync.Once
	closeErr     error
	mu           sync.Mutex
	inputMu      sync.Mutex
	inputTimeout time.Duration
	width        uint16
	height       uint16
	pointerX     uint16
	pointerY     uint16
	pointerBtns  byte
	pressedKeys  map[uint16]bool
	err          error
}

func (s *rdpScreenSessionAdapter) Frames() <-chan screenstream.Message { return s.frames }

// Input translates bounded ScreenStream events to RDP slow-path input PDUs.
// Keysym-only input and extended mouse buttons are rejected rather than guessed.
func (s *rdpScreenSessionAdapter) Input(input screenstream.InputEvent) error {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if s.target == nil {
		return screenstream.ErrUnsupported
	}
	keys := make(map[uint16]bool, len(s.pressedKeys))
	for code, down := range s.pressedKeys {
		keys[code] = down
	}
	buttons, x, y := s.pointerBtns, s.pointerX, s.pointerY
	var events []rdp.RDPInputEvent
	switch input.Type {
	case screenstream.InputKey:
		if input.Scancode == 0 {
			return screenstream.ErrUnsupported
		}
		code := input.Scancode
		extended := false
		if code > 0xff {
			if code>>8 != 0xe0 || code&0xff == 0 || code&0xff > 0x7f {
				return screenstream.ErrUnsupported
			}
			extended = true
			code &= 0xff
		} else if code > 0x7f {
			return screenstream.ErrUnsupported
		}
		if input.Flags != screenstream.KeyPressed && input.Flags != screenstream.KeyReleased {
			return screenstream.ErrMalformedMessage
		}
		released := input.Flags == screenstream.KeyReleased
		events = append(events, rdp.RDPInputEvent{Type: rdp.RDPInputScancode, Scancode: byte(code), Extended: extended, Released: released})
		keyID := input.Scancode
		if released {
			delete(keys, keyID)
		} else {
			keys[keyID] = true
		}
	case screenstream.InputPointer:
		if input.Buttons&^byte(0x07) != 0 || uint32(input.X) >= uint32(s.width) || uint32(input.Y) >= uint32(s.height) {
			return screenstream.ErrUnsupported
		}
		events = append(events, rdp.RDPInputEvent{Type: rdp.RDPInputMouse, PointerFlags: rdpMouseMove, X: input.X, Y: input.Y})
		for _, button := range []struct {
			bit  byte
			flag uint16
		}{{1, rdpMouseButton1}, {2, rdpMouseButton2}, {4, rdpMouseButton3}} {
			if (buttons & button.bit) != (input.Buttons & button.bit) {
				flags := button.flag
				if input.Buttons&button.bit != 0 {
					flags |= rdpMouseDown
				}
				events = append(events, rdp.RDPInputEvent{Type: rdp.RDPInputMouse, PointerFlags: flags, X: input.X, Y: input.Y})
			}
		}
		if input.Wheel != 0 {
			steps := int(input.Wheel)
			if steps > 120 || steps < -120 {
				return screenstream.ErrUnsupported
			}
			for i := 0; i < absInt(steps); i++ {
				flags := rdpMouseWheel | 120
				if steps < 0 {
					flags |= rdpMouseWheelNegative
				}
				events = append(events, rdp.RDPInputEvent{Type: rdp.RDPInputMouse, PointerFlags: flags, X: input.X, Y: input.Y})
			}
		}
		buttons, x, y = input.Buttons, input.X, input.Y
	case screenstream.InputReleaseAll:
		events = releaseAllRDPInput(keys, buttons, x, y)
		keys = make(map[uint16]bool)
		buttons = 0
	default:
		return screenstream.ErrUnsupported
	}
	if err := s.sendInputEvents(events); err != nil {
		return err
	}
	s.pressedKeys, s.pointerBtns, s.pointerX, s.pointerY = keys, buttons, x, y
	return nil
}

func (s *rdpScreenSessionAdapter) sendInputEvents(events []rdp.RDPInputEvent) error {
	for len(events) > 0 {
		count := len(events)
		if count > 128 {
			count = 128
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.inputTimeout)
		err := s.target.SendInput(ctx, events[:count], s.inputTimeout)
		cancel()
		if err != nil {
			return err
		}
		events = events[count:]
	}
	return nil
}

const (
	rdpMouseMove          = uint16(0x0800)
	rdpMouseButton1       = uint16(0x1000)
	rdpMouseButton2       = uint16(0x2000)
	rdpMouseButton3       = uint16(0x4000)
	rdpMouseDown          = uint16(0x8000)
	rdpMouseWheel         = uint16(0x0200)
	rdpMouseWheelNegative = uint16(0x0100)
)

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func releaseAllRDPInput(keys map[uint16]bool, buttons byte, x, y uint16) []rdp.RDPInputEvent {
	codes := make([]int, 0, len(keys))
	for code := range keys {
		codes = append(codes, int(code))
	}
	sort.Ints(codes)
	events := make([]rdp.RDPInputEvent, 0, len(codes)+3)
	for _, raw := range codes {
		code := uint16(raw)
		extended := code > 0xff
		if extended {
			code &= 0xff
		}
		events = append(events, rdp.RDPInputEvent{Type: rdp.RDPInputScancode, Scancode: byte(code), Extended: extended, Released: true})
	}
	for _, button := range []struct {
		bit  byte
		flag uint16
	}{{1, rdpMouseButton1}, {2, rdpMouseButton2}, {4, rdpMouseButton3}} {
		if buttons&button.bit != 0 {
			events = append(events, rdp.RDPInputEvent{Type: rdp.RDPInputMouse, PointerFlags: button.flag, X: x, Y: y})
		}
	}
	return events
}

func (s *rdpScreenSessionAdapter) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *rdpScreenSessionAdapter) Close() error {
	s.closeOnce.Do(func() {
		s.inputMu.Lock()
		events := releaseAllRDPInput(s.pressedKeys, s.pointerBtns, s.pointerX, s.pointerY)
		if len(events) > 0 {
			s.closeErr = s.sendInputEvents(events)
		}
		s.pressedKeys = make(map[uint16]bool)
		s.pointerBtns = 0
		s.inputMu.Unlock()
		s.cancel()
		s.target.Close()
		<-s.done
	})
	return s.closeErr
}

func (s *rdpScreenSessionAdapter) readLoop(ctx context.Context) {
	defer close(s.done)
	defer close(s.frames)
	for {
		update, err := s.target.ReadBitmapUpdate(ctx, rdpReadTimeout)
		if err != nil {
			if ctx.Err() == nil {
				s.mu.Lock()
				s.err = err
				s.mu.Unlock()
			}
			return
		}
		frame, err := s.framebuffer.Apply(update, time.Now().UTC())
		if err != nil {
			s.mu.Lock()
			s.err = err
			s.mu.Unlock()
			return
		}
		select {
		case s.frames <- frame:
		case <-ctx.Done():
			return
		}
	}
}
