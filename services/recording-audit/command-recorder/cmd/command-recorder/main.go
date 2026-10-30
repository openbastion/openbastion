// Command command-recorder runs the Command Recorder (doc 00 §4.4): the
// service that stores, command by command, what operators ran in a session,
// so a session can be replayed as text.
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"
	"strconv"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// boundedIntEnv reads a number that must lie within bounds: a value that is not one stops
// the Recorder, naming the variable — there is no quiet fallback.
func boundedIntEnv(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		log.Fatalf("command-recorder: %s must be a number between %d and %d, got %q", name, min, max, v)
	}
	return n
}

func main() {
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.CommandRecorder)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := mustEnv("PORT", "8087")
	authzURL := mustEnv("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))
	// Every read of a recording is written here before it is served, and is not served
	// without it (ADR-0022): there is no setting that turns this off.
	auditURL := mustEnv("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))

	var repo domain.CommandRepository
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		// Fail closed, not open: with PostgreSQL every command is encrypted
		// under a per-session key wrapped by this key, so a missing or random
		// key would make every recording unreadable after a restart — or, if
		// we skipped encryption instead, store commands in the clear. Generate
		// one once (`openssl rand -hex 32`), keep it outside the database, and
		// give this service its OWN key, not the Password Vault's.
		kek, err := infrastructure.NewLocalKEKFromHexKey(os.Getenv("KMS_KEY_HEX"))
		if err != nil {
			log.Fatalf("command-recorder: DATABASE_URL is set, so recordings are encrypted at rest and a key is required — refusing to start: %v", err)
		}
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store, err := infrastructure.NewPostgresStore(ctx, db, kek)
		if err != nil {
			log.Fatalf("postgres store: %v", err)
		}
		repo = store
		log.Printf("command-recorder: using PostgreSQL at %s — commands encrypted at rest (AES-256-GCM, key per session wrapped by %s)", redactDSN(dsn), kek.KeyID())
	} else {
		repo = infrastructure.NewInMemoryStore()
		log.Printf("command-recorder: DATABASE_URL not set, using in-memory storage (dev/test only — recordings are lost on restart)")
	}

	authzClient, err := rt.Client(mtls.Peer{URL: authzURL, Service: mtls.Authorization})
	if err != nil {
		log.Fatalf("command-recorder: %v", err)
	}
	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authzURL, Client: authzClient}
	auditClient, err := rt.Client(mtls.Peer{URL: auditURL, Service: mtls.AuditService})
	if err != nil {
		log.Fatalf("command-recorder: %v", err)
	}
	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: auditClient}
	svc := application.NewRecorderService(repo, authz, audit)
	// What the refused reads of one user may write to the audit (ADR-0024): a burst, then a
	// steady rate. Read whether or not anyone is ever refused, so that a bad value is found
	// on the day it is written.
	svc.WithReadRefusalAudit(
		boundedIntEnv("RECORDING_READ_AUDIT_BURST", application.DefaultReadAuditBurst, 1, application.MaxReadAuditBurst),
		boundedIntEnv("RECORDING_READ_AUDIT_RATE_PER_MINUTE", application.DefaultReadAuditRatePerMinute, 1, application.MaxReadAuditRatePerMinute))
	readBurst, readRate := svc.ReadRefusalAudit()
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("command-recorder listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
	log.Printf("  -> audit: %s (every read of a recording is written there before it is served)", auditURL)
	log.Printf("command-recorder: the refusals of reads of a recording are written to the audit per user: a burst of %d, then %d a minute (per process; a refusal is the same whatever the budget says)", readBurst, readRate)
	log.Fatal(rt.ListenAndServe(":"+port, srv.Routes(), interfaces.CallerRules()))
}

func redactDSN(dsn string) string {
	at := -1
	for i, c := range dsn {
		if c == '@' {
			at = i
		}
	}
	if at == -1 {
		return dsn
	}
	return "***@" + dsn[at+1:]
}
