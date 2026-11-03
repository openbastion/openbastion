//go:build development

package tlspin

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"testing"
)

func TestDevelopmentServerConfigAllowsOnlyThePinnedSelfSignedTarget(t *testing.T) {
	serverCert, _ := targetCertificate(t, "self-signed.example")
	pin := mustPin(t, serverCert.Certificate[0])
	config, err := DevelopmentServerConfig(hex.EncodeToString(pin.sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if !config.InsecureSkipVerify {
		t.Fatal("development config should use the explicitly opted-in pin-only path")
	}
	if err := dialTLSWithConfig(serverCert, config); err != nil {
		t.Fatalf("matching self-signed target refused: %v", err)
	}

	wrongPin := mustPin(t, func() []byte { other, _ := targetCertificate(t, "self-signed.example"); return other.Certificate[0] }())
	wrongConfig, err := DevelopmentServerConfig(hex.EncodeToString(wrongPin.sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := dialTLSWithConfig(serverCert, wrongConfig); err == nil {
		t.Fatal("self-signed target with wrong pin accepted")
	}
	if _, err := DevelopmentServerConfig(""); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("missing pin: %v", err)
	}
}

func dialTLSWithConfig(serverCert tls.Certificate, clientConfig *tls.Config) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12})
		serverErr <- server.Handshake()
	}()
	client, dialErr := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if dialErr == nil {
		_ = client.Close()
	}
	<-serverErr
	return dialErr
}
