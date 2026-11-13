// Package engine adapts protocol clients to the shared proxy lifecycle.
package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/pkg/vnc"
)

var ErrVNCConfiguration = errors.New("rdp-vnc-proxy: VNC target metadata is incomplete")

// VNCCodec adapts the RFB client to proxycore.ScreenCodec. TLS roots must be
// loaded from explicit operator configuration; system roots are never implicit.
// Missing Vault-issued identity or pin metadata refuses the session before dial.
type VNCCodec struct {
	TLSRoots    *x509.CertPool
	DialTimeout time.Duration
	// FrameInterval is SCREEN_FRAME_INTERVAL_MS: the least time between two frames of a session.
	FrameInterval time.Duration
	// DrawPointer draws the target's pointer into each frame (SCREEN_DRAW_POINTER, ADR-0091).
	DrawPointer bool
	// PartialFrames sends partial frames anchored on key frames (SCREEN_PARTIAL_FRAMES, ADR-0092).
	PartialFrames bool
}

var _ proxycore.ScreenCodec = (*VNCCodec)(nil)

func (c *VNCCodec) Open(ctx context.Context, cred *proxycore.Credential) (proxycore.ScreenSession, error) {
	if c == nil || c.TLSRoots == nil || cred == nil || cred.Type != "password" ||
		cred.TargetHost == "" || cred.TargetUser == "" || cred.TLSCertificateSHA256 == "" || cred.TargetDomain == "" {
		return nil, &proxycore.ScreenFailure{Code: "pin_missing", Err: ErrVNCConfiguration}
	}
	client := &vnc.Client{Config: vnc.Config{
		Address:        cred.TargetHost,
		Username:       cred.TargetUser,
		Password:       cred.Material(),
		TLSFingerprint: cred.TLSCertificateSHA256,
		TLSRoots:       c.TLSRoots,
		TLSServerName:  cred.TargetDomain,
		DialTimeout:    c.DialTimeout,
		FrameInterval:  c.FrameInterval,
		DrawPointer:    c.DrawPointer,
		PartialFrames:  c.PartialFrames,
	}}
	session, err := client.Open(ctx)
	if err == nil {
		return vncScreenSession{session}, nil
	}
	return nil, &proxycore.ScreenFailure{Code: vncEndCode(err), Err: err}
}

// vncEndCode is what the operator is told (ADR-0071 §12). A target refusing the password says
// target_auth_failed; every other cause not named stays target_unreachable.
func vncEndCode(err error) string {
	switch {
	case errors.Is(err, vnc.ErrAuthentication):
		return "target_auth_failed"
	case errors.Is(err, screenstream.ErrFrameTooLarge):
		return "recording_lost"
	case errors.Is(err, vnc.ErrPasswordTruncation):
		return "codec_unsupported"
	case errors.Is(err, vnc.ErrInvalidTarget):
		return "pin_missing"
	case errors.Is(err, vnc.ErrTLSVerification):
		return "pin_mismatch"
	case errors.Is(err, vnc.ErrTLSRequired):
		return "tls_required"
	case errors.Is(err, vnc.ErrProtocolVersion):
		return "protocol_version_unsupported"
	case errors.Is(err, vnc.ErrUnsupportedProtocol), errors.Is(err, vnc.ErrInvalidFramebuffer):
		return "codec_unsupported"
	}
	return "target_unreachable"
}

// vncScreenSession gives what ends a running session the same codes as what refuses its opening:
// a target that sends a rectangle out of bounds is not a target that cannot be reached.
type vncScreenSession struct{ proxycore.ScreenSession }

// PointerDrawn passes on what the session says (ADR-0091): the embedded interface would hide it.
func (s vncScreenSession) PointerDrawn() bool {
	drawer, ok := s.ScreenSession.(proxycore.PointerDrawer)
	return ok && drawer.PointerDrawn()
}

// RequestKeyFrame passes the relay's request on (ADR-0092), as PointerDrawn does its word.
func (s vncScreenSession) RequestKeyFrame() {
	if requester, ok := s.ScreenSession.(proxycore.KeyFrameRequester); ok {
		requester.RequestKeyFrame()
	}
}

func (s vncScreenSession) Err() error {
	err := s.ScreenSession.Err()
	if err == nil {
		return nil
	}
	return &proxycore.ScreenFailure{Code: vncEndCode(err), Err: err}
}
