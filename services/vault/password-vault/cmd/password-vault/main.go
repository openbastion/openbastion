// Command password-vault runs the Password Vault service (doc 00 §4.3).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see
// internal/interfaces/http.go and /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

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

	// Rotation reaches the target (ADR-0037): the Vault logs in over SSH with the account's
	// reconciliation account, and writes every rotation to the audit — before it touches the
	// target, fail-closed.
	auditURL := mustEnv("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))
	auditClient, err := rt.Client(mtls.Peer{URL: auditURL, Service: mtls.AuditService})
	if err != nil {
		log.Fatalf("password-vault: %v", err)
	}
	svc.WithRotation(infrastructure.SSHTargetChanger{}, &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: auditClient})

	// Scheduled accounts rotate when due (ADR-0040): a sweep, no switch to turn it off.
	sweep := boundedIntEnv("ROTATION_SWEEP_SECONDS", 300, 1, 86400)
	go rotateEvery(svc, time.Duration(sweep)*time.Second)
	log.Printf("password-vault: scheduled accounts that are due are rotated every %ds (at most %d a sweep; one that failed waits %s)",
		sweep, application.RotationsPerSweep, application.RotationRetryAfter)

	if os.Getenv("SKIP_DEMO_SEED") == "" {
		ctx := context.Background()
		// The demonstration target is fictitious: its pinned host key (ADR-0039) is one whose
		// private half was thrown away, so no machine can ever be sent this secret.
		if err := svc.OnboardPinned(ctx, []string{"vault-admin"}, application.OnboardInput{
			ID: "acc_demo", Name: "prod-db-01-root", Username: "root", TargetHost: "10.0.4.12:22", Protocol: "ssh",
			Policy: domain.RotationPostUse, InitialSecret: []byte("demo-only-do-not-use-in-prod"), HostKey: demoHostKey,
		}); err != nil {
			log.Printf("demo seed skipped (non-fatal): %v", err)
		}
	}

	srv := interfaces.NewHTTPServer(svc)
	// Under mutual TLS, who redeems a scope is whoever the certificate says.
	srv.CallerFromCertificate = rt.Enabled()
	log.Printf("password-vault listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authorizationURL)
	log.Printf("  -> audit:         %s (rotations; the targets are reached over SSH, their pinned host keys verified — ADR-0037, ADR-0039)", auditURL)
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

// demoHostKey is the pinned host key of the demonstration account: its private key was
// discarded when it was generated, so it identifies no machine.
const demoHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC+pXuNMSq8lVqUNZ0A+gFlXPmbP+09vCp5Y/mHuzYpS"

func boundedIntEnv(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		log.Fatalf("password-vault: %s must be a number between %d and %d, got %q", name, min, max, v)
	}
	return n
}

// rotateEvery runs one sweep of scheduled rotations every interval, each bounded in time.
func rotateEvery(svc *application.VaultService, every time.Duration) {
	for range time.Tick(every) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		res, err := svc.RotateDue(ctx)
		cancel()
		if res.Rotated > 0 || res.Failed > 0 {
			log.Printf("password-vault: scheduled rotations: %d rotated, %d failed", res.Rotated, res.Failed)
		}
		if err != nil {
			log.Printf("password-vault: the scheduled rotation sweep stopped: %v", err)
		}
	}
}
