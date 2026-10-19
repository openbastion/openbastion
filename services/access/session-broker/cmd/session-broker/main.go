// Command session-broker runs the Session Broker (doc 00 §4.1) — the
// orchestrator that never sees a secret (ADR-0003).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := mustEnv("PORT", "8084")
	authzURL := mustEnv("AUTHORIZATION_URL", "http://127.0.0.1:8083")
	vaultURL := mustEnv("VAULT_URL", "http://127.0.0.1:8081")
	auditURL := mustEnv("AUDIT_URL", "http://127.0.0.1:8082")
	sshProxyURL := mustEnv("SSH_PROXY_URL", "http://127.0.0.1:8085")

	var store domain.SessionRepository
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(db)
		log.Printf("session-broker: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewInMemoryStore()
		log.Printf("session-broker: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authzURL}
	vault := &infrastructure.VaultAuthorizationHTTPClient{BaseURL: vaultURL}
	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL}
	accounts := &infrastructure.AccountLookupHTTPClient{BaseURL: vaultURL}
	proxy := &infrastructure.ProxyClientHTTPClient{BaseURL: sshProxyURL}

	svc := application.NewSessionBrokerService(store, authz, vault, audit, accounts, proxy)

	// Break-glass (ADR-0009) is off unless a limit is given: the maximum number of
	// minutes a break-glass session may last. A value that is not a number is an
	// error, not a quiet "off" — or worse, a quiet "on".
	if v := os.Getenv("BREAKGLASS_MAX_MINUTES"); v != "" {
		max, err := strconv.Atoi(v)
		if err != nil || max < 0 {
			log.Fatalf("session-broker: BREAKGLASS_MAX_MINUTES must be a number of minutes (0 disables break-glass), got %q", v)
		}
		svc.WithBreakGlass(max)
		if max > 0 {
			log.Printf("session-broker: BREAK-GLASS ENABLED (at most %d minutes) — an actor with a policy on breakglass:account:* can request a session that runs while the Command Recorder is down", max)
		}
	}
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("session-broker listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
	log.Printf("  -> vault:         %s", vaultURL)
	log.Printf("  -> audit:         %s", auditURL)
	log.Printf("  -> ssh-proxy:     %s", sshProxyURL)
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
