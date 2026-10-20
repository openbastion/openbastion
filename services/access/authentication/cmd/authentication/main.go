// Command authentication runs the Authentication Service (doc 00 §4.1).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/authentication/internal/interfaces"
)

func main() {
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.Authentication)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8086"
	}
	dsn := os.Getenv("DATABASE_URL")
	signingKeyHex := os.Getenv("TOKEN_SIGNING_KEY_HEX")

	// Fail closed, not open: a random per-process signing key
	// (SigningKeyFromHex's empty-key fallback) silently invalidates
	// every token issued by this process the moment it restarts — the
	// Authentication equivalent of the LocalKMS bug documented in
	// NOTES_SANDBOX.md. A real deployment generates this once
	// (`openssl rand -hex 32`) and keeps it outside the database.
	if dsn != "" && signingKeyHex == "" {
		log.Fatalf("authentication: DATABASE_URL is set but TOKEN_SIGNING_KEY_HEX is not — refusing to start with a random, per-process signing key that would invalidate every active session after a restart. Generate one with `openssl rand -hex 32` and set TOKEN_SIGNING_KEY_HEX.")
	}
	key, err := infrastructure.SigningKeyFromHex(signingKeyHex)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}

	var store domain.UserRepository
	if dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(db)
		log.Printf("authentication: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewInMemoryStore()
		log.Printf("authentication: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	hasher := infrastructure.Argon2Hasher{}
	tokens := infrastructure.NewTokenIssuer(key)
	svc := application.NewAuthenticationService(store, hasher, tokens, time.Hour)

	// Demo seed — real onboarding goes through POST /auth/v1/users.
	if os.Getenv("SKIP_DEMO_SEED") == "" {
		ctx := context.Background()
		if _, err := svc.CreateUser(ctx, "demo-dba", "Demo DBA", "demo-password", []string{"dba"}); err != nil {
			log.Fatalf("seed: %v", err)
		}
	}

	srv := interfaces.NewHTTPServer(svc)
	log.Printf("authentication listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
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
