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

func main() {
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.CommandRecorder)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := mustEnv("PORT", "8087")
	authzURL := mustEnv("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))

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
	srv := interfaces.NewHTTPServer(application.NewRecorderService(repo, authz))

	log.Printf("command-recorder listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
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
