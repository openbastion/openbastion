// Command session-broker runs the Session Broker (doc 00 §4.1) — the
// orchestrator that never sees a secret (ADR-0003).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
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

	store := infrastructure.NewInMemoryStore()
	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authzURL}
	vault := &infrastructure.VaultAuthorizationHTTPClient{BaseURL: vaultURL}
	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL}
	accounts := &infrastructure.AccountLookupHTTPClient{BaseURL: vaultURL}
	proxy := &infrastructure.ProxyClientHTTPClient{BaseURL: sshProxyURL}

	svc := application.NewSessionBrokerService(store, authz, vault, audit, accounts, proxy)
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("session-broker listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
	log.Printf("  -> vault:         %s", vaultURL)
	log.Printf("  -> audit:         %s", auditURL)
	log.Printf("  -> ssh-proxy:     %s", sshProxyURL)
	log.Fatal(http.ListenAndServe(":"+port, srv.Routes()))
}
