package pki

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// StandardServices are the identities of a complete OpenBastion deployment.
var StandardServices = []string{
	mtls.APIGateway, mtls.Authentication, mtls.Authorization, mtls.SessionBroker,
	mtls.SSHProxy, mtls.PasswordVault, mtls.AuditService, mtls.CommandRecorder,
	mtls.AdminCLI,
}

// The layout of a PKI directory:
//
//	<dir>/ca.pem            the authority's certificate  — every service's TLS_CA_FILE
//	<dir>/ca-key.pem        the authority's key          — keep it away from the services
//	<dir>/<service>/cert.pem, key.pem                     — TLS_CERT_FILE, TLS_KEY_FILE
const (
	caCertName = "ca.pem"
	caKeyName  = "ca-key.pem"
)

// CAFile is the path of the CA certificate in dir.
func CAFile(dir string) string { return filepath.Join(dir, caCertName) }

// CertFile and KeyFile are where Issue's result for service lives in dir.
func CertFile(dir, service string) string { return filepath.Join(dir, service, "cert.pem") }
func KeyFile(dir, service string) string  { return filepath.Join(dir, service, "key.pem") }

// ErrCAExists is returned by InitDir when dir already holds an authority:
// replacing it would silently invalidate every certificate issued from it.
var ErrCAExists = errors.New("pki: a certificate authority already exists in this directory")

// InitDir creates a new authority in dir.
func InitDir(dir, trustDomain string, ttl time.Duration) (*CA, error) {
	if _, err := os.Stat(CAFile(dir)); err == nil {
		return nil, ErrCAExists
	}
	ca, err := NewCA(trustDomain, ttl, time.Now())
	if err != nil {
		return nil, err
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(filepath.Join(dir, caKeyName), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(CAFile(dir), ca.CertPEM(), 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

// LoadDir reads the authority back from dir.
func LoadDir(dir, trustDomain string) (*CA, error) {
	certPEM, err := os.ReadFile(CAFile(dir))
	if err != nil {
		return nil, fmt.Errorf("pki: no authority in %s (run init first): %w", dir, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyName))
	if err != nil {
		return nil, fmt.Errorf("pki: the authority's key: %w", err)
	}
	return LoadCA(certPEM, keyPEM, trustDomain)
}

// IssueToDir issues the identity of service and writes it under dir. Calling it
// again for the same service is how a certificate is renewed: running services
// pick the new files up on their own (mtls.Credentials reloads), so renewal needs
// no restart. The key is written first, so a service that looks between the two
// writes sees a mismatch, refuses it, and keeps what it has.
func IssueToDir(ca *CA, dir, service string, opts IssueOptions) (*Leaf, error) {
	leaf, err := ca.Issue(service, opts)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, service), 0o700); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(KeyFile(dir, service), leaf.KeyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(CertFile(dir, service), leaf.CertPEM, 0o644); err != nil {
		return nil, err
	}
	return leaf, nil
}

// WriteFileAtomic writes data to a temporary file next to path and renames it
// over path, so a reader never sees half a file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once renamed
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
