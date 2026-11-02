package infrastructure

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

type S3ObjectStore struct {
	client *minio.Client
	bucket string
}

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func NewS3ObjectStore(endpoint, bucket, accessKey, secretKey, caFile, expectedService, trustDomain string, clientCredentials *mtls.Credentials, allowHTTP bool) (*S3ObjectStore, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("S3_ENDPOINT must be an origin with a host and no path or credentials")
	}
	if !bucketNamePattern.MatchString(bucket) || strings.Contains(bucket, "..") ||
		(strings.Count(bucket, ".") == 3 && net.ParseIP(bucket) != nil) || accessKey == "" || secretKey == "" {
		return nil, errors.New("S3_BUCKET must be a DNS-compatible bucket name, and S3_ACCESS_KEY and S3_SECRET_KEY are required")
	}
	secure := u.Scheme == "https"
	if !secure && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("S3_ENDPOINT must use https; plain HTTP requires S3_ALLOW_HTTP=true")
	}
	if trustDomain == "" {
		trustDomain = mtls.DefaultTrustDomain
	}
	if !mtls.ValidTrustDomain(trustDomain) {
		return nil, errors.New("S3_TLS_TRUST_DOMAIN is not a valid trust domain")
	}
	if !secure && (caFile != "" || expectedService != "") {
		return nil, errors.New("S3_CA_FILE and S3_TLS_SERVICE require an HTTPS S3 endpoint")
	}

	var tlsConfig *tls.Config
	if secure {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system certificate authorities: %w", err)
		}
		if roots == nil {
			return nil, errors.New("system certificate authorities are unavailable")
		}
		if caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("reading S3_CA_FILE: %w", err)
			}
			if !roots.AppendCertsFromPEM(pem) {
				return nil, errors.New("S3_CA_FILE contains no certificates")
			}
		}
		if expectedService != "" && !mtls.ValidServiceName(expectedService) {
			return nil, errors.New("S3_TLS_SERVICE is not a valid service name")
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
		if expectedService != "" {
			tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return mtls.ErrNoIdentity
				}
				got, err := mtls.ServiceFromCertificate(cs.PeerCertificates[0], trustDomain)
				if err != nil {
					return err
				}
				if got != expectedService {
					return fmt.Errorf("S3 endpoint answered as %q, expected %q", got, expectedService)
				}
				return nil
			}
		}
		if clientCredentials != nil {
			tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return clientCredentials.ClientCertificate(), nil
			}
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: tlsConfig,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 4,
	}

	client, err := minio.New(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       secure,
		Region:       "us-east-1",
		Transport:    transport,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring S3 client: %w", err)
	}
	return &S3ObjectStore{client: client, bucket: bucket}, nil
}

func (s *S3ObjectStore) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("checking S3 bucket: %w", err)
	}
	if exists {
		return nil
	}
	if err := s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		if exists, checkErr := s.client.BucketExists(ctx, s.bucket); checkErr == nil && exists {
			return nil
		}
		return fmt.Errorf("creating S3 bucket: %w", err)
	}
	return nil
}

func (s *S3ObjectStore) Put(ctx context.Context, key string, ciphertext []byte) error {
	if !validRecordingObjectKey(key) || len(ciphertext) == 0 || len(ciphertext) > application.MaxCiphertextBytes {
		return errors.New("invalid S3 recording object")
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(ciphertext), int64(len(ciphertext)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("putting S3 object: %w", err)
	}
	return nil
}

func (s *S3ObjectStore) Get(ctx context.Context, key string) ([]byte, error) {
	if !validRecordingObjectKey(key) {
		return nil, errors.New("invalid S3 recording object key")
	}
	object, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting S3 object: %w", err)
	}
	defer object.Close()
	data, err := io.ReadAll(io.LimitReader(object, application.MaxCiphertextBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading S3 object: %w", err)
	}
	if len(data) > application.MaxCiphertextBytes {
		return nil, errors.New("S3 object exceeds the ciphertext limit")
	}
	return data, nil
}

func (s *S3ObjectStore) Ready(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("checking S3 bucket: %w", err)
	}
	if !exists {
		return errors.New("S3 bucket does not exist")
	}
	return nil
}

var _ domain.ObjectStore = (*S3ObjectStore)(nil)

func validRecordingObjectKey(key string) bool {
	const prefix = "recordings/v1/"
	if !strings.HasPrefix(key, prefix) || len(key) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(key[len(prefix):])
	return err == nil
}
