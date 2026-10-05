// Command password-vault runs the Password Vault service (doc 00 §4.3).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see
// internal/interfaces/http.go and /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := mustEnv("PORT", "8081")
	authorizationURL := mustEnv("AUTHORIZATION_URL", "http://127.0.0.1:8083")

	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		log.Fatalf("kms: %v", err)
	}

	var accounts domain.AccountRepository
	var secrets domain.SecretRepository
	var scopes domain.ScopeRepository

	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store := infrastructure.NewPostgresStore(db)
		accounts, secrets, scopes = store, store, store
		log.Printf("password-vault: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store := infrastructure.NewInMemoryStore()
		accounts, secrets, scopes = store, store, store
		log.Printf("password-vault: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authorizationURL}
	svc := application.NewVaultService(accounts, secrets, scopes, kms, authz)

	if os.Getenv("SKIP_DEMO_SEED") == "" {
		ctx := context.Background()
		if err := svc.OnboardAccount(ctx, []string{"vault-admin"}, "acc_demo", "prod-db-01-root", "root", "10.0.4.12:22", "ssh",
			domain.RotationPostUse, []byte("demo-only-do-not-use-in-prod")); err != nil {
			log.Printf("demo seed skipped (non-fatal): %v", err)
		}
	}

	srv := interfaces.NewHTTPServer(svc)
	log.Printf("password-vault listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authorizationURL)
	log.Fatal(http.ListenAndServe(":"+port, srv.Routes()))
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
