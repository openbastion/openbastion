//go:build development

package tlspin

import "crypto/tls"

// DevelopmentServerConfig is available only in binaries built with -tags development.
// It permits a self-signed target certificate only when its exact leaf pin matches.
// Never use this function or a development-tagged binary in production.
func DevelopmentServerConfig(pinValue string) (*tls.Config, error) {
	pin, err := ParseFingerprint(pinValue)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Development-only; the callback below is mandatory.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrInvalidCertificate
			}
			return VerifyCertificate(state.PeerCertificates[0].Raw, pin)
		},
	}, nil
}
