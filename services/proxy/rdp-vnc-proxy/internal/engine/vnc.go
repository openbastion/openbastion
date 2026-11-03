// Package engine adapts protocol clients to the shared proxy lifecycle.
package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/vnc"
)

var ErrVNCConfiguration = errors.New("rdp-vnc-proxy: VNC target metadata is incomplete")

// VNCCodec adapts the RFB client to proxycore.ScreenCodec. TLS roots must be
// loaded from explicit operator configuration; system roots are never implicit.
// Missing Vault-issued identity or pin metadata refuses the session before dial.
type VNCCodec struct {
	TLSRoots    *x509.CertPool
	DialTimeout time.Duration
}

var _ proxycore.ScreenCodec = (*VNCCodec)(nil)

func (c *VNCCodec) Open(ctx context.Context, cred *proxycore.Credential) (proxycore.ScreenSession, error) {
	if c == nil || c.TLSRoots == nil || cred == nil || cred.Type != "password" ||
		cred.TargetHost == "" || cred.TargetUser == "" || cred.TLSCertificateSHA256 == "" || cred.TargetDomain == "" {
		return nil, ErrVNCConfiguration
	}
	client := &vnc.Client{Config: vnc.Config{
		Address:        cred.TargetHost,
		Username:       cred.TargetUser,
		Password:       cred.Material(),
		TLSFingerprint: cred.TLSCertificateSHA256,
		TLSRoots:       c.TLSRoots,
		TLSServerName:  cred.TargetDomain,
		DialTimeout:    c.DialTimeout,
	}}
	return client.Open(ctx)
}
