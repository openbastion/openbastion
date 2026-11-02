package mtls_test

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestGRPCHandshakeUsesHTTP2AndPinsThePeerIdentity(t *testing.T) {
	e := newEnv(t)
	client, err := mtls.NewCredentials(e.issue("api-gateway", pki.IssueOptions{}))
	must(t, err)

	t.Run("the expected service negotiates h2 with mutual TLS 1.3", func(t *testing.T) {
		server, err := mtls.NewCredentials(e.issue(mtls.VideoRecorder, pki.IssueOptions{}))
		must(t, err)
		addr, result := serveGRPCTLS(t, server.GRPCServerTLS())
		cfg, err := client.GRPCClientTLS(mtls.Peer{URL: "https://" + addr, Service: mtls.VideoRecorder})
		must(t, err)
		conn, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		state := conn.ConnectionState()
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
			t.Fatalf("negotiated TLS %x, ALPN %q", state.Version, state.NegotiatedProtocol)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a valid certificate of another service is refused", func(t *testing.T) {
		server, err := mtls.NewCredentials(e.issue(mtls.CommandRecorder, pki.IssueOptions{}))
		must(t, err)
		addr, result := serveGRPCTLS(t, server.GRPCServerTLS())
		cfg, err := client.GRPCClientTLS(mtls.Peer{URL: "https://" + addr, Service: mtls.VideoRecorder})
		must(t, err)
		conn, err := tls.Dial("tcp", addr, cfg)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil || !strings.Contains(err.Error(), `answered as "command-recorder", expected "video-recorder"`) {
			t.Fatalf("identity mismatch was not rejected explicitly: %v", err)
		}
		_ = <-result
	})

	t.Run("plaintext and malformed peer URLs are rejected", func(t *testing.T) {
		for _, peer := range []mtls.Peer{
			{URL: "http://video-recorder:8089", Service: mtls.VideoRecorder},
			{URL: "https://video-recorder:8089/path", Service: mtls.VideoRecorder},
			{URL: "https://video-recorder:8089", Service: "VideoRecorder"},
		} {
			if _, err := client.GRPCClientTLS(peer); err == nil {
				t.Fatalf("accepted peer URL %q and service %q", peer.URL, peer.Service)
			}
		}
	})
}

func serveGRPCTLS(t *testing.T, cfg *tls.Config) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, cfg)
		if err := tlsConn.Handshake(); err != nil {
			result <- err
			return
		}
		if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
			result <- errors.New("server did not negotiate h2")
			return
		}
		result <- nil
	}()
	return listener.Addr().String(), result
}
