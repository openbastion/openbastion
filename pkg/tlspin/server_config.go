package tlspin

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

var ErrInvalidTLSConfig = errors.New("invalid target TLS configuration")

// ServerConfig returns a production-safe TLS client configuration. Standard
// certificate-chain and hostname verification remain enabled; the explicit pin
// is an additional check, not a replacement for PKI validation. roots must be
// an explicitly configured trust pool; system roots are never selected implicitly.
func ServerConfig(pinValue string, roots *x509.CertPool, serverName string) (*tls.Config, error) {
	pin, err := ParseFingerprint(pinValue)
	if err != nil {
		return nil, err
	}
	if roots == nil || serverName == "" {
		return nil, ErrInvalidTLSConfig
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: serverName,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrInvalidCertificate
			}
			return VerifyCertificate(state.PeerCertificates[0].Raw, pin)
		},
	}, nil
}
