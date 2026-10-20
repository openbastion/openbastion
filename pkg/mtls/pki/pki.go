// Package pki is a small certificate authority for OpenBastion's internal mTLS:
// enough to bring up a development environment and to give tests real,
// verifiable identities. Production deployments issue the same shape of
// certificate from their own infrastructure (cert-manager, SPIRE, a PKI
// engine) — the services only read PEM files and do not care who wrote them.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CA is a certificate authority: a certificate and the key that signs with it.
type CA struct {
	Cert        *x509.Certificate
	Key         *ecdsa.PrivateKey
	TrustDomain string
}

// NewCA creates a self-signed authority for a trust domain, valid for ttl from now.
func NewCA(trustDomain string, ttl time.Duration, now time.Time) (*CA, error) {
	if !mtls.ValidTrustDomain(trustDomain) {
		return nil, fmt.Errorf("pki: %q is not a valid trust domain", trustDomain)
	}
	if ttl <= 0 {
		return nil, errors.New("pki: the CA lifetime must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "OpenBastion internal CA (" + trustDomain + ")", Organization: []string{"OpenBastion"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true, // issues leaf certificates only
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, TrustDomain: trustDomain}, nil
}

// LoadCA reads an authority back from its PEM files.
func LoadCA(certPEM, keyPEM []byte, trustDomain string) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("pki: the CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("pki: the CA key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: the CA key: %w", err)
	}
	return &CA{Cert: cert, Key: key, TrustDomain: trustDomain}, nil
}

// CertPEM is the authority's certificate, the content of every service's TLS_CA_FILE.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// KeyPEM is the authority's private key. Keep it out of every service's reach.
func (ca *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// IssueOptions shapes a leaf certificate. The zero value issues one that is
// valid from a minute ago (clock skew) for 24 hours, for the service name and
// localhost.
type IssueOptions struct {
	TTL       time.Duration
	NotBefore time.Time
	DNSNames  []string
	IPs       []net.IP
}

// Leaf is an issued identity.
type Leaf struct {
	Cert    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte
}

// Issue creates the identity of a service: a key pair and a certificate whose
// single URI SAN is spiffe://<trust domain>/<service>, usable both to serve and
// to call. Its DNS and IP names are what peers verify the address they dial
// against.
func (ca *CA) Issue(service string, opts IssueOptions) (*Leaf, error) {
	id, err := mtls.SPIFFEID(ca.TrustDomain, service)
	if err != nil {
		return nil, err
	}
	if opts.TTL == 0 {
		opts.TTL = 24 * time.Hour
	}
	if opts.TTL < 0 {
		return nil, errors.New("pki: the certificate lifetime must be positive")
	}
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Minute)
	}
	notAfter := notBefore.Add(opts.TTL)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter // never outlive the authority
	}

	dns := opts.DNSNames
	if dns == nil {
		dns = []string{service, "localhost"}
	}
	ips := opts.IPs
	if ips == nil {
		ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: service, Organization: []string{"OpenBastion"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{id},
		DNSNames:              dns,
		IPAddresses:           ips,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Leaf{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func keyID(pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha1.Sum(der) //nolint:gosec // an identifier, not a security boundary
	return sum[:]
}
