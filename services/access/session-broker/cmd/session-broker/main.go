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
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
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
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.SessionBroker)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := mustEnv("PORT", "8084")
	authzURL := mustEnv("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))
	vaultURL := mustEnv("VAULT_URL", rt.DefaultURL("127.0.0.1:8081"))
	auditURL := mustEnv("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))
	sshProxyURL := mustEnv("SSH_PROXY_URL", rt.DefaultURL("127.0.0.1:8085"))

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

	// Each client is pinned to the identity of the one service it calls: the
	// Broker never hands a scope to anything but the Vault, nor a break-glass
	// flag to anything but the SSH Proxy (ADR-0009, ADR-0010).
	peer := func(url, service string) *http.Client {
		c, err := rt.Client(mtls.Peer{URL: url, Service: service})
		if err != nil {
			log.Fatalf("session-broker: %v", err)
		}
		return c
	}
	vaultClient := peer(vaultURL, mtls.PasswordVault)
	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authzURL, Client: peer(authzURL, mtls.Authorization)}
	vault := &infrastructure.VaultAuthorizationHTTPClient{BaseURL: vaultURL, Client: vaultClient}
	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: peer(auditURL, mtls.AuditService)}
	accounts := &infrastructure.AccountLookupHTTPClient{BaseURL: vaultURL, Client: vaultClient}
	proxy := &infrastructure.ProxyClientHTTPClient{BaseURL: sshProxyURL, Client: peer(sshProxyURL, mtls.SSHProxy)}

	svc := application.NewSessionBrokerService(store, authz, vault, audit, accounts, proxy)

	// Break-glass (ADR-0009) is off unless a limit is given: the maximum number of
	// minutes a break-glass session may last. A value that is not a number is an
	// error, not a quiet "off" — or worse, a quiet "on".
	breakGlassMax := 0
	if v := os.Getenv("BREAKGLASS_MAX_MINUTES"); v != "" {
		max, err := strconv.Atoi(v)
		if err != nil || max < 0 {
			log.Fatalf("session-broker: BREAKGLASS_MAX_MINUTES must be a number of minutes (0 disables break-glass), got %q", v)
		}
		breakGlassMax = max
		svc.WithBreakGlass(max)
	}

	// The double validation (ADR-0011) is required unless it is turned off by name:
	// anything else than the two known words is an error, so that a typo does not pick
	// a side — and it is read whether or not break-glass is on, so that a bad value
	// is found on the day it is written, not on the day break-glass is enabled.
	approvalWindow := application.DefaultBreakGlassApprovalWindow
	if v := os.Getenv("BREAKGLASS_APPROVAL_WINDOW_MINUTES"); v != "" {
		minutes, err := strconv.Atoi(v)
		if err != nil || minutes < 1 || minutes > 1440 {
			log.Fatalf("session-broker: BREAKGLASS_APPROVAL_WINDOW_MINUTES must be a number of minutes between 1 and 1440, got %q", v)
		}
		approvalWindow = time.Duration(minutes) * time.Minute
	}
	svc.WithBreakGlassApprovalWindow(approvalWindow)
	approvalRequired := true
	switch v := os.Getenv("BREAKGLASS_APPROVAL"); v {
	case "", "required":
	case "disabled":
		approvalRequired = false
		svc.WithoutBreakGlassApproval()
	default:
		log.Fatalf("session-broker: BREAKGLASS_APPROVAL must be %q (the default) or %q, got %q", "required", "disabled", v)
	}

	switch {
	case breakGlassMax > 0 && approvalRequired:
		log.Printf("session-broker: BREAK-GLASS ENABLED (at most %d minutes) — a request needs the approval of a second user, within %s; an approved session runs while the Command Recorder is down", breakGlassMax, approvalWindow)
	case breakGlassMax > 0:
		log.Printf("session-broker: BREAK-GLASS ENABLED (at most %d minutes) WITHOUT APPROVAL (BREAKGLASS_APPROVAL=disabled) — a single actor with a policy on breakglass:account:* can obtain a session that runs while the Command Recorder is down", breakGlassMax)
	}
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("session-broker listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
	log.Printf("  -> vault:         %s", vaultURL)
	log.Printf("  -> audit:         %s", auditURL)
	log.Printf("  -> ssh-proxy:     %s", sshProxyURL)
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
