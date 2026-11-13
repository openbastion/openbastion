// Command rdp-vnc-proxy runs the Go-native graphical proxy: VNC, and RDP unless RDP_ENABLED=false
// (ADR-0071, ADR-0088).
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
		log.Fatal("rdp-vnc-proxy: TARGET_TLS_ROOTS_FILE must name explicit PEM roots for VNC and RDP target verification")
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
	listener.ScreenInput = proxycore.ScreenInputLimits{
		RatePerSecond: boundedIntEnv("SCREEN_INPUT_RATE_PER_SECOND", proxycore.DefaultScreenInputRate, 1, 10000),
		Burst:         boundedIntEnv("SCREEN_INPUT_BURST", proxycore.DefaultScreenInputBurst, 1, 100000),
	}
	// The pointer drawn into the frames, shown and recorded alike (ADR-0091): on unless said
	// "false"; anything but "true" or "false" stops the service.
	drawPointer := true
	switch v := os.Getenv("SCREEN_DRAW_POINTER"); v {
	case "", "true":
	case "false":
		drawPointer = false
	default:
		log.Fatalf("rdp-vnc-proxy: SCREEN_DRAW_POINTER must be true or false, got %q", v)
	}
	// Partial frames anchored on key frames (ADR-0092), RDP and VNC: on unless said "false"
	// (the owner's decision, once a real browser showed them); anything else stops the service.
	partialFrames := true
	switch v := os.Getenv("SCREEN_PARTIAL_FRAMES"); v {
	case "", "true":
	case "false":
		partialFrames = false
	default:
		log.Fatalf("rdp-vnc-proxy: SCREEN_PARTIAL_FRAMES must be true or false, got %q", v)
	}
	// The resize of the target's desktop to the operator's window (ADR-0095), RDP only: on unless
	// said "false" (the owner's decision, 13 November 2026, once five Windows targets followed it in
	// a real browser); anything but "true" or "false" stops the service.
	resize := true
	switch v := os.Getenv("SCREEN_RESIZE"); v {
	case "", "true":
	case "false":
		resize = false
	default:
		log.Fatalf("rdp-vnc-proxy: SCREEN_RESIZE must be true or false, got %q", v)
	}
	// The clipboard of an RDP session (ADR-0096): on unless said "false" (the owner's decision,
	// 13 November 2026, once five Windows targets were proven in a real browser). On, a session opens
	// it only in the directions its rights allow, refused by default, and every transfer is audited
	// (session.clipboard) and recorded before it is delivered. Anything else stops the service.
	clipboard, err := switchFromEnv("SCREEN_CLIPBOARD", os.Getenv("SCREEN_CLIPBOARD"), true)
	if err != nil {
		log.Fatalf("rdp-vnc-proxy: %v", err)
	}
	if clipboard {
		listener.Clipboard = audit
	}
	vncCodec := &engine.VNCCodec{
		TLSRoots:      roots,
		DialTimeout:   time.Duration(boundedIntEnv("VNC_CONNECT_TIMEOUT_SECONDS", 10, 1, 120)) * time.Second,
		FrameInterval: time.Duration(boundedIntEnv("SCREEN_FRAME_INTERVAL_MS", 50, 16, 250)) * time.Millisecond,
		DrawPointer:   drawPointer,
		PartialFrames: partialFrames,
	}
	origins := splitOrigins(os.Getenv("SCREEN_ALLOWED_ORIGINS"))
	server := interfaces.NewHTTPServer(infrastructure.NewPendingScreenSessions(), listener, vncCodec, recorder, endpoint, origins)
	// RDP (ADR-0088): on unless said "false" (the owner's decision, 13 November 2026); only "true"
	// and "false", anything else stops the service. Off, the RDP codec is not built and
	// establish-session refuses rdp.
	rdpState := "RDP disabled"
	rdpEnabled, err := switchFromEnv("RDP_ENABLED", os.Getenv("RDP_ENABLED"), true)
	if err != nil {
		log.Fatalf("rdp-vnc-proxy: %v", err)
	}
	if rdpEnabled {
		server.WithRDP(&engine.RDPCodec{
			TLSRoots:    roots,
			DialTimeout: time.Duration(boundedIntEnv("RDP_CONNECT_TIMEOUT_SECONDS", 15, 1, 120)) * time.Second,
			// The cadence VNC has (ADR-0071 §8): at most one frame encoded and recorded a interval.
			FrameInterval: vncCodec.FrameInterval,
			DrawPointer:   drawPointer,
			PartialFrames: partialFrames,
			Resize:        resize,
			Clipboard:     clipboard,
		})
		rdpState = "RDP enabled"
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- rt.ListenAndServe(":"+port, server.Routes(), interfaces.CallerRules()) }()
	log.Printf("rdp-vnc-proxy: control and screen WebSocket on :%s; VNC enabled; %s (RDP_ENABLED, ADR-0088); pointer drawn %t (SCREEN_DRAW_POINTER, ADR-0091); partial frames %t (SCREEN_PARTIAL_FRAMES, ADR-0092); resize %t (SCREEN_RESIZE, ADR-0095); clipboard %t (SCREEN_CLIPBOARD, ADR-0096)", port, rdpState, drawPointer, partialFrames, resize, clipboard)
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

// boundedIntEnv reads a bounded integer: absent means the default, anything else out of bounds
// stops the service rather than running with a value nobody chose (settings/security.yaml).
func boundedIntEnv(name string, fallback, low, high int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < low || n > high {
		log.Fatalf("rdp-vnc-proxy: %s must be between %d and %d, got %q", name, low, high, value)
	}
	return n
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
	root := command.NewServiceCommand("rdp-vnc-proxy", runService)
	// The healthcheck of the distroless image (deploy/docker-compose): the running service, asked
	// under its own identity.
	root.AddCommand(command.NewProbeCommand(func(ctx context.Context, port int, path string) error {
		return mtls.ProbeSelf(ctx, mtls.RDPVNCProxy, port, path)
	}))
	if err := root.Execute(); err != nil {
		log.Fatalf("rdp-vnc-proxy: %v", err)
	}
}

// switchFromEnv reads an on/off setting: empty is def, "true" and "false" are themselves, and
// anything else is an error that stops the service rather than guessing.
func switchFromEnv(name, value string, def bool) (bool, error) {
	switch value {
	case "":
		return def, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false, got %q", name, value)
}
