package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/transit"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/interfaces"
)

func main() {
	log.Printf("video-recorder %s", buildinfo.String())
	runtime, err := mtls.Setup(mtls.VideoRecorder)
	if err != nil {
		log.Fatalf("%v", err)
	}

	httpPort := boundedIntEnv("PORT", 8088, 1, 65535)
	grpcPort := boundedIntEnv("GRPC_PORT", 8089, 1, 65535)
	if httpPort == grpcPort {
		log.Fatal("video-recorder: PORT and GRPC_PORT must be different")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("video-recorder: DATABASE_URL is required; refusing to start without durable metadata")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbCtx, cancelDB := context.WithTimeout(ctx, 10*time.Second)
	db, err := infrastructure.OpenPostgres(dbCtx, dsn)
	cancelDB()
	if err != nil {
		log.Fatalf("video-recorder: postgres: %v", err)
	}
	defer db.Close()
	log.Printf("video-recorder: using PostgreSQL at %s", redactDSN(dsn))

	trustDomain := mtls.DefaultTrustDomain
	if runtime.Credentials() != nil {
		trustDomain = runtime.Credentials().TrustDomain()
	}
	objects, err := infrastructure.NewS3ObjectStore(
		os.Getenv("S3_ENDPOINT"), os.Getenv("S3_BUCKET"), os.Getenv("S3_ACCESS_KEY"),
		os.Getenv("S3_SECRET_KEY"), os.Getenv("S3_CA_FILE"), os.Getenv("S3_TLS_SERVICE"),
		trustDomain, runtime.Credentials(), strictBoolEnv("S3_ALLOW_HTTP", false),
	)
	if err != nil {
		log.Fatalf("video-recorder: object store configuration: %v", err)
	}
	if strictBoolEnv("S3_CREATE_BUCKET", false) {
		createCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := objects.EnsureBucket(createCtx)
		cancel()
		if err != nil {
			log.Fatalf("video-recorder: creating S3 bucket: %v", err)
		}
		log.Printf("video-recorder: created or confirmed the configured S3 bucket")
	}

	keys := recordingKeyWrapper(ctx)
	authzURL := envOr("AUTHORIZATION_URL", runtime.DefaultURL("127.0.0.1:8083"))
	auditURL := envOr("AUDIT_URL", runtime.DefaultURL("127.0.0.1:8082"))
	authzHTTP, err := serviceClient(runtime, mtls.Peer{URL: authzURL, Service: mtls.Authorization})
	if err != nil {
		log.Fatalf("video-recorder: authorization client: %v", err)
	}
	auditHTTP, err := serviceClient(runtime, mtls.Peer{URL: auditURL, Service: mtls.AuditService})
	if err != nil {
		log.Fatalf("video-recorder: audit client: %v", err)
	}

	svc := application.NewRecorderService(
		infrastructure.NewPostgresStore(db), objects, keys,
		&infrastructure.AuthorizationHTTPClient{BaseURL: authzURL, Client: authzHTTP},
		&infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: auditHTTP},
	).WithReadRefusalAudit(
		boundedIntEnv("RECORDING_READ_AUDIT_BURST", application.DefaultReadAuditBurst, 1, application.MaxReadAuditBurst),
		boundedIntEnv("RECORDING_READ_AUDIT_RATE_PER_MINUTE", application.DefaultReadAuditRatePerMinute, 1, application.MaxReadAuditRatePerMinute),
	)
	readyCtx, cancelReady := context.WithTimeout(ctx, 15*time.Second)
	err = svc.Ready(readyCtx)
	cancelReady()
	if err != nil {
		log.Fatalf("video-recorder: dependencies are not ready: %v", err)
	}

	httpServer := runtime.Server(":"+strconv.Itoa(httpPort), interfaces.NewHTTPServer(svc).Routes(), interfaces.HTTPCallerRules())
	grpcServer := interfaces.NewGRPCServer(svc, runtime)
	log.Printf("video-recorder: HTTP health on :%d; gRPC on :%d", httpPort, grpcPort)
	log.Printf("  -> authorization: %s", authzURL)
	log.Printf("  -> audit: %s (every served segment is audited before decryption)", auditURL)
	log.Printf("  -> S3 endpoint: %s; bucket: %q", safeEndpoint(os.Getenv("S3_ENDPOINT")), os.Getenv("S3_BUCKET"))
	if err := serve(ctx, httpServer, grpcServer, httpPort, grpcPort, runtime.Enabled()); err != nil {
		log.Fatal(err)
	}
}

func serve(ctx context.Context, httpServer *http.Server, grpcServer interface {
	Serve(net.Listener) error
	Stop()
}, httpPort, grpcPort int, tlsEnabled bool) error {
	httpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", httpPort))
	if err != nil {
		return fmt.Errorf("listening for HTTP health: %w", err)
	}
	defer httpListener.Close()
	if tlsEnabled {
		httpListener = tls.NewListener(httpListener, httpServer.TLSConfig)
	}
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		return fmt.Errorf("listening for gRPC: %w", err)
	}
	defer grpcListener.Close()

	serveErrors := make(chan error, 2)
	go func() { serveErrors <- httpServer.Serve(httpListener) }()
	go func() { serveErrors <- grpcServer.Serve(grpcListener) }()

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serveErrors:
		if errors.Is(serveErr, http.ErrServerClosed) || serveErr == nil {
			serveErr = errors.New("listener stopped unexpectedly")
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("video-recorder: HTTP shutdown: %v", err)
	}
	grpcServer.Stop()
	return serveErr
}

func recordingKeyWrapper(ctx context.Context) domain.KeyWrapper {
	client, configured, err := transit.FromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("video-recorder: Transit configuration: %v — refusing to start", err)
	}
	if configured {
		probeCtx, cancel := context.WithTimeout(ctx, 2*transit.Timeout)
		err := client.Probe(probeCtx)
		cancel()
		if err != nil {
			log.Fatalf("video-recorder: Transit cannot wrap and unwrap with %s: %v — refusing to start", client.KeyID(), err)
		}
		go client.KeepAlive(ctx, func(format string, args ...any) { log.Printf("video-recorder: "+format, args...) })
		reload := boundedIntEnv("TRANSIT_TOKEN_RELOAD_SECONDS", int(transit.DefaultTokenReload/time.Second), 1, 3600)
		go client.WatchTokenFile(ctx, time.Duration(reload)*time.Second, func(format string, args ...any) { log.Printf("video-recorder: "+format, args...) })
		log.Printf("video-recorder: data keys are wrapped by %s at %s (Transit; token is not logged)", client.KeyID(), client.Where())
		return infrastructure.NewTransitKEK(client)
	}
	key, err := infrastructure.NewLocalKEKFromHexKey(os.Getenv("VIDEO_RECORDER_KMS_KEY_HEX"))
	if err != nil {
		log.Fatalf("video-recorder: durable recordings require Transit or VIDEO_RECORDER_KMS_KEY_HEX — refusing to start: %v", err)
	}
	log.Printf("video-recorder: data keys are wrapped by %s (local KEK; use Transit outside development)", key.KeyID())
	return key
}

func serviceClient(runtime *mtls.Runtime, peer mtls.Peer) (*http.Client, error) {
	client, err := runtime.Client(peer)
	if err != nil {
		return nil, err
	}
	copy := *client
	copy.Timeout = 5 * time.Second
	return &copy, nil
}

func boundedIntEnv(name string, fallback, min, max int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < min || number > max {
		log.Fatalf("video-recorder: %s must be between %d and %d, got %q", name, min, max, value)
	}
	return number
}

func strictBoolEnv(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	switch value {
	case "true":
		return true
	case "false":
		return false
	default:
		log.Fatalf("video-recorder: %s must be true or false, got %q", name, value)
		return false
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func redactDSN(dsn string) string {
	at := strings.LastIndexByte(dsn, '@')
	if at < 0 {
		return dsn
	}
	return "***@" + dsn[at+1:]
}

func safeEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host
}
