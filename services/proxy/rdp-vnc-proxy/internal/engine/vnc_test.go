package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/vnc"
)

type metadataVault struct{ fetched proxycore.Fetched }

func (v metadataVault) FetchCredential(context.Context, string, string) (proxycore.Fetched, error) {
	return v.fetched, nil
}

func fetchTestCredential(t *testing.T, fetched proxycore.Fetched) *proxycore.Credential {
	t.Helper()
	cred, err := proxycore.NewCredentialFetcher(metadataVault{fetched: fetched}, "rdp-vnc-proxy").Fetch(context.Background(), "single-use")
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func TestVNCCodecRefusesMissingVaultTLSMetadataBeforeDial(t *testing.T) {
	cred := fetchTestCredential(t, proxycore.Fetched{Type: "password", Material: []byte("password"), TargetHost: "127.0.0.1:5900", TargetUser: "operator", TargetDomain: "target.example"})
	codec := &VNCCodec{TLSRoots: x509.NewCertPool()}
	if _, err := codec.Open(context.Background(), cred); !errors.Is(err, ErrVNCConfiguration) {
		t.Fatalf("missing TLS pin error = %v", err)
	}
}

func TestVNCCodecRequiresExplicitRoots(t *testing.T) {
	cred := fetchTestCredential(t, proxycore.Fetched{Type: "password", Material: []byte("password"), TargetHost: "127.0.0.1:5900", TargetUser: "operator", TLSCertificateSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", TargetDomain: "target.example"})
	if _, err := (&VNCCodec{}).Open(context.Background(), cred); !errors.Is(err, ErrVNCConfiguration) {
		t.Fatalf("missing explicit TLS roots error = %v", err)
	}
}

func TestVNCCodecPassesCompleteTargetMetadataToVNCClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	cred := fetchTestCredential(t, proxycore.Fetched{Type: "password", Material: []byte("password"), TargetHost: address, TargetUser: "operator", TLSCertificateSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", TargetDomain: "target.example"})
	_, err = (&VNCCodec{TLSRoots: x509.NewCertPool(), DialTimeout: 50 * time.Millisecond}).Open(context.Background(), cred)
	if err == nil {
		t.Fatal("listener without an RFB server unexpectedly accepted a session")
	}
	if errors.Is(err, ErrVNCConfiguration) || errors.Is(err, vnc.ErrInvalidTarget) {
		t.Fatalf("complete metadata rejected before target handshake: %v", err)
	}
}

// The operator is told why, in the words of ADR-0071 §12, and only in those. Mixed with an error
// the caller does not name, a code must not change: errors.Is looks through the wrapping.
func TestVNCRefusalsSayWhatADR0071Promises(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{vnc.ErrTLSRequired, "tls_required"},
		{vnc.ErrProtocolVersion, "protocol_version_unsupported"},
		{vnc.ErrPasswordTruncation, "codec_unsupported"},
		{vnc.ErrUnsupportedProtocol, "codec_unsupported"},
		{vnc.ErrInvalidFramebuffer, "codec_unsupported"},
		{vnc.ErrInvalidTarget, "pin_missing"},
		{vnc.ErrTLSVerification, "pin_mismatch"},
		{vnc.ErrAuthentication, "target_unreachable"},
		{vnc.ErrTargetRefused, "target_unreachable"},
		{errors.New("connection reset"), "target_unreachable"},
	} {
		if got := vncEndCode(fmt.Errorf("while opening: %w", tc.err)); got != tc.want {
			t.Errorf("%v: code %q, want %q", tc.err, got, tc.want)
		}
	}
}

type endingSession struct {
	proxycore.ScreenSession
	err error
}

func (s endingSession) Err() error { return s.err }

func TestVNCSessionEndsWithTheCodeOfItsCause(t *testing.T) {
	var failure *proxycore.ScreenFailure
	err := vncScreenSession{endingSession{err: vnc.ErrInvalidFramebuffer}}.Err()
	if !errors.As(err, &failure) || failure.Code != "codec_unsupported" || !errors.Is(err, vnc.ErrInvalidFramebuffer) {
		t.Fatalf("Err = %v", err)
	}
	if err := (vncScreenSession{endingSession{}}).Err(); err != nil {
		t.Fatalf("a session without error has one: %v", err)
	}
}
