package engine

import (
	"context"
	"crypto/x509"
	"errors"
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
)

// RDPCodec adapts the strict RDP client to the shared screen lifecycle. It is
// deliberately not selected by the proxy runtime until keyboard/pointer input
// and real Windows/RDS interoperability have been validated.
type RDPCodec struct {
	TLSRoots      *x509.CertPool
	DialTimeout   time.Duration
	DesktopWidth  uint16
	DesktopHeight uint16
	FrenchLocale  bool
	openSession   func(context.Context, *proxycore.Credential) (rdpScreenSession, error)
}

var _ proxycore.ScreenCodec = (*RDPCodec)(nil)

type rdpScreenSession interface {
	ReadBitmapUpdate(context.Context, time.Duration) (rdp.RDPBitmapUpdate, error)
	Dimensions() (uint16, uint16)
	Close()
}

func (c *RDPCodec) Open(ctx context.Context, cred *proxycore.Credential) (proxycore.ScreenSession, error) {
	if c == nil || c.TLSRoots == nil || cred == nil || cred.Type != "password" ||
		cred.TargetHost == "" || cred.TargetUser == "" || cred.TLSCertificateSHA256 == "" || cred.TargetDomain == "" ||
		c.DialTimeout < 0 {
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
	width, height := target.Dimensions()
	framebuffer, err := rdp.NewRDPFramebuffer(width, height)
	if err != nil {
		target.Close()
		return nil, &proxycore.ScreenFailure{Code: "codec_unsupported", Err: err}
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	s := &rdpScreenSessionAdapter{target: target, framebuffer: framebuffer, frames: make(chan screenstream.Message), cancel: cancel, done: make(chan struct{})}
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
func (s *rdpTargetSession) Dimensions() (uint16, uint16) { return s.width, s.height }
func (s *rdpTargetSession) Close()                       { s.session.Close() }

type rdpScreenSessionAdapter struct {
	target      rdpScreenSession
	framebuffer *rdp.RDPFramebuffer
	frames      chan screenstream.Message
	cancel      context.CancelFunc
	done        chan struct{}
	closeOnce   sync.Once
	mu          sync.Mutex
	err         error
}

func (s *rdpScreenSessionAdapter) Frames() <-chan screenstream.Message { return s.frames }

// Input remains fail-closed: the RDP input PDU encoder and its independent
// write path are a separate increment. The runtime must not expose this codec.
func (s *rdpScreenSessionAdapter) Input(screenstream.InputEvent) error {
	return screenstream.ErrUnsupported
}

func (s *rdpScreenSessionAdapter) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *rdpScreenSessionAdapter) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.target.Close()
		<-s.done
	})
	return nil
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
