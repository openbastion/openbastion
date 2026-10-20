// Command password-vault runs the Password Vault service (doc 00 §4.3).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see
// internal/interfaces/http.go and /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"

	"github.com/openbastion/openbastion/pkg/mtls"
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
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.PasswordVault)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := mustEnv("PORT", "8081")
	authorizationURL := mustEnv("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))
	dsn := os.Getenv("DATABASE_URL")
	kmsKeyHex := os.Getenv("KMS_KEY_HEX")

	// Fail closed, not open: a random per-process key (NewLocalKMS's
	// fallback) silently makes every secret unreadable the moment this
	// process restarts, which is exactly the failure mode PostgreSQL
	// persistence exists to avoid. A real deployment generates this once
	// (`openssl rand -hex 32`) and keeps it outside the database — see
	// infrastructure.NewLocalKMSFromHexKey's doc comment and
	// NOTES_SANDBOX.md for the bug this closes.
	if dsn != "" && kmsKeyHex == "" {
		log.Fatalf("password-vault: DATABASE_URL is set but KMS_KEY_HEX is not — refusing to start with a random, per-process encryption key that would make every secret unreadable after a restart. Generate one with `openssl rand -hex 32` and set KMS_KEY_HEX.")
	}
	kms, err := infrastructure.NewLocalKMSFromHexKey(kmsKeyHex)
	if err != nil {
		log.Fatalf("kms: %v", err)
	}

	var accounts domain.AccountRepository
	var secrets domain.SecretRepository
	var scopes domain.ScopeRepository

	if dsn != "" {
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

	authzClient, err := rt.Client(mtls.Peer{URL: authorizationURL, Service: mtls.Authorization})
	if err != nil {
		log.Fatalf("password-vault: %v", err)
	}
	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authorizationURL, Client: authzClient}
	svc := application.NewVaultService(accounts, secrets, scopes, kms, authz)

	if os.Getenv("SKIP_DEMO_SEED") == "" {
		ctx := context.Background()
		if err := svc.OnboardAccount(ctx, []string{"vault-admin"}, "acc_demo", "prod-db-01-root", "root", "10.0.4.12:22", "ssh",
			domain.RotationPostUse, []byte("demo-only-do-not-use-in-prod")); err != nil {
			log.Printf("demo seed skipped (non-fatal): %v", err)
		}
	}

	srv := interfaces.NewHTTPServer(svc)
	// Under mutual TLS, who redeems a scope is whoever the certificate says.
	srv.CallerFromCertificate = rt.Enabled()
	log.Printf("password-vault listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authorizationURL)
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
