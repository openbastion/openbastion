// Command password-vault runs the Password Vault service (docs/architecture/system-overview.md).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see
// internal/interfaces/http.go and /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/transit"
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

	kms := keyring(dsn, kmsKeyHex)

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

	// Scheduled accounts rotate when due (ADR-0040): a sweep, no switch to turn it off; within
	// ROTATION_WINDOW_UTC if set, and failures in a row raise an alert to the audit (ADR-0041).
	window, err := application.ParseRotationWindow(os.Getenv("ROTATION_WINDOW_UTC"))
	if err != nil {
		log.Fatalf("password-vault: ROTATION_WINDOW_UTC: %v", err)
	}
	alertAfter := boundedIntEnv("ROTATION_ALERT_AFTER_FAILURES", application.DefaultRotationAlertAfter, 1, application.MaxRotationAlertAfter)
	if _, err := svc.WithRotationSchedule(window, alertAfter); err != nil {
		log.Fatalf("password-vault: %v", err)
	}
	sweep := boundedIntEnv("ROTATION_SWEEP_SECONDS", 300, 1, 86400)
	go rotateEvery(svc, time.Duration(sweep)*time.Second)
	log.Printf("password-vault: scheduled accounts that are due are rotated every %ds, %s (at most %d a sweep; one that failed waits %s; %d failures in a row write vault.rotation_overdue)",
		sweep, window, application.RotationsPerSweep, application.RotationRetryAfter, alertAfter)

	// What an earlier key still protects is re-sealed under the current one (ADR-0055).
	if previous := kms.PreviousKeyIDs(); len(previous) > 0 {
		every := boundedIntEnv("KEY_REWRAP_SWEEP_SECONDS", 60, 1, 3600)
		go rewrapEvery(svc, time.Duration(every)*time.Second, previous)
		log.Printf("password-vault: secrets under %s are re-sealed under %s, %d a batch, every %ds", strings.Join(previous, ", "), kms.KeyID(), application.RewrapBatch, every)
	}

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

// keyring builds what seals the secrets (ADR-0049). With Transit configured (TRANSIT_ADDR,
// TRANSIT_KEY, TRANSIT_TOKEN_FILE), new secrets are sealed under it, after a real round trip
// proves the key and the token work; KMS_KEY_HEX, if still given, opens what was sealed before
// and seals nothing. Without Transit, KMS_KEY_HEX is the key, as before — required with a
// database: a random per-process key would make every secret unreadable after a restart.
func keyring(dsn, kmsKeyHex string) *infrastructure.Keyring {
	client, configured, err := transit.FromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("password-vault: %v — refusing to start", err)
	}
	if !configured {
		if dsn != "" && kmsKeyHex == "" {
			log.Fatalf("password-vault: DATABASE_URL is set but neither Transit (TRANSIT_ADDR, TRANSIT_KEY, TRANSIT_TOKEN_FILE) nor KMS_KEY_HEX is — refusing to start with a random, per-process encryption key that would make every secret unreadable after a restart")
		}
		local, err := infrastructure.NewLocalKMSFromHexKey(kmsKeyHex)
		if err != nil {
			log.Fatalf("kms: %v", err)
		}
		ring, _ := infrastructure.NewKeyring(local)
		log.Printf("password-vault: secrets are sealed under the local key %s (KMS_KEY_HEX; no Transit configured)", local.KeyID())
		return ring
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*transit.Timeout)
	defer cancel()
	if err := client.Probe(ctx); err != nil {
		log.Fatalf("password-vault: Transit cannot wrap and unwrap with %s: %v — refusing to start", client.KeyID(), err)
	}
	// The token renews itself at half its life (ADR-0053): a periodic token would otherwise end,
	// and with it every secret's delivery.
	go client.KeepAlive(context.Background(), func(f string, a ...any) { log.Printf("password-vault: "+f, a...) })
	current := infrastructure.NewTransitKMS(client)
	var previous []infrastructure.Sealer
	if kmsKeyHex != "" {
		local, err := infrastructure.NewLocalKMSFromHexKey(kmsKeyHex)
		if err != nil {
			log.Fatalf("kms: %v", err)
		}
		previous = append(previous, local)
	}
	ring, err := infrastructure.NewKeyring(current, previous...)
	if err != nil {
		log.Fatalf("password-vault: %v", err)
	}
	log.Printf("password-vault: secrets are sealed under %s at %s (Transit; the token is not logged)", current.KeyID(), client.Where())
	for _, id := range ring.PreviousKeyIDs() {
		log.Printf("password-vault: secrets sealed under %s are still read (KMS_KEY_HEX), and re-sealed under %s in the background (ADR-0055); nothing new is sealed under it", id, current.KeyID())
	}
	return ring
}

// rewrapEvery re-seals under the current key what the earlier keys still protect (ADR-0055):
// page after page, a pass every period. A pass that finds nothing says, once, that the earlier
// keys protect nothing any more; versions that do not open are said at the end of each pass.
func rewrapEvery(svc *application.VaultService, every time.Duration, previous []string) {
	time.Sleep(every) // a first period first: a Vault just started has other work
	said := false
	for {
		found, skipped, cursor := 0, 0, ""
		for {
			r, err := svc.RewrapDue(context.Background(), cursor)
			if err != nil {
				log.Printf("password-vault: re-sealing paused until the next pass: %v", err)
				found = -1
				break
			}
			found, skipped = found+r.Found, skipped+r.Skipped
			if r.Resealed > 0 {
				log.Printf("password-vault: %d secret version(s) re-sealed under the current key", r.Resealed)
			}
			if cursor = r.Next; cursor == "" {
				break
			}
		}
		switch {
		case found == 0 && !said:
			said = true
			log.Printf("password-vault: nothing is sealed under %s any more: KMS_KEY_HEX can be removed", strings.Join(previous, ", "))
		case found > 0:
			said = false
			if skipped > 0 {
				log.Printf("password-vault: %d version(s) under %s do not open with the key held: they stay, and KMS_KEY_HEX cannot be removed yet", skipped, strings.Join(previous, ", "))
			}
		}
		time.Sleep(every)
	}
}
