// Command rdp-vnc-proxy runs the Go-native graphical proxy. RDP remains disabled
// until its protocol engine and attack tests are implemented (ADR-0071).
package main

import (
	"context"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/command"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/engine"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/interfaces"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func runService() {
	log.Printf("rdp-vnc-proxy %s", buildinfo.String())
	rt, err := mtls.Setup(mtls.RDPVNCProxy)
	if err != nil {
		log.Fatal(err)
	}
	port := env("PORT", "8090")
	vaultURL := env("VAULT_URL", rt.DefaultURL("127.0.0.1:8081"))
	auditURL := env("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))
	recorderURL := env("VIDEO_RECORDER_GRPC_URL", rt.DefaultURL("127.0.0.1:8089"))
	endpoint := env("RDP_VNC_PROXY_PUBLIC_ENDPOINT", "127.0.0.1:"+port)
	if strings.Contains(endpoint, "://") {
		log.Fatal("RDP_VNC_PROXY_PUBLIC_ENDPOINT must be host:port, not a URL")
	}
	peer := func(url, service string) *http.Client {
		c, e := rt.Client(mtls.Peer{URL: url, Service: service})
		if e != nil {
			log.Fatalf("rdp-vnc-proxy: %v", e)
		}
		return c
	}
	vault := &infrastructure.VaultCredentialHTTPClient{BaseURL: vaultURL, Client: peer(vaultURL, mtls.PasswordVault)}
	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: peer(auditURL, mtls.AuditService)}
	recorder, err := infrastructure.NewVideoRecorderClient(rt, recorderURL)
	if err != nil {
		log.Fatal(err)
	}
	rootsFile := os.Getenv("TARGET_TLS_ROOTS_FILE")
	if rootsFile == "" {
		log.Fatal("rdp-vnc-proxy: TARGET_TLS_ROOTS_FILE must name explicit PEM roots for VNC target verification")
	}
	pem, err := os.ReadFile(rootsFile)
	if err != nil {
		log.Fatalf("rdp-vnc-proxy: reading TARGET_TLS_ROOTS_FILE: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		log.Fatal("rdp-vnc-proxy: TARGET_TLS_ROOTS_FILE contains no usable PEM certificates")
	}
	fetcher := proxycore.NewCredentialFetcher(vault, mtls.RDPVNCProxy)
	listener := proxycore.NewListener(fetcher, proxycore.NewTerminator(audit))
	vncCodec := &engine.VNCCodec{TLSRoots: roots, DialTimeout: 10 * time.Second}
	origins := splitOrigins(os.Getenv("SCREEN_ALLOWED_ORIGINS"))
	server := interfaces.NewHTTPServer(infrastructure.NewPendingScreenSessions(), listener, vncCodec, recorder, endpoint, origins)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- rt.ListenAndServe(":"+port, server.Routes(), interfaces.CallerRules()) }()
	log.Printf("rdp-vnc-proxy: control and screen WebSocket on :%s; VNC enabled; RDP disabled", port)
	log.Printf("rdp-vnc-proxy: Video Recorder %s; target roots loaded from configured PEM file", recorderURL)
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			log.Printf("rdp-vnc-proxy: server stopped: %v", err)
		}
	}
	if err := recorder.Close(); err != nil {
		log.Printf("rdp-vnc-proxy: closing recorder: %v", err)
	}
}

func splitOrigins(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			log.Fatal("rdp-vnc-proxy: SCREEN_ALLOWED_ORIGINS contains an empty origin")
		}
		out = append(out, v)
	}
	return out
}

// main dispatches version before entering the proxy lifecycle.
func main() {
	if err := command.NewServiceCommand("rdp-vnc-proxy", runService).Execute(); err != nil {
		log.Fatalf("rdp-vnc-proxy: %v", err)
	}
}
