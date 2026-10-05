// Command ssh-proxy runs the SSH Proxy (doc 00 §4.2) — the first proxy
// with a real protocol implementation, using golang.org/x/crypto/ssh (see
// /NOTES_SANDBOX.md for how it's fetched in this build sandbox).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	sshPort := mustEnv("SSH_PORT", "2222")
	httpPort := mustEnv("PORT", "8085")
	vaultURL := mustEnv("VAULT_URL", "http://127.0.0.1:8081")
	auditURL := mustEnv("AUDIT_URL", "http://127.0.0.1:8082")
	proxyID := mustEnv("PROXY_SERVICE_ID", "ssh-proxy")

	// MVP: an ephemeral host key generated at process start. Production
	// needs a persisted, rotated identity (Guide Sécurité §3) — this is a
	// deliberate simplification, not an oversight.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generating host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatalf("host signer: %v", err)
	}

	vaultClient := &infrastructure.VaultCredentialHTTPClient{BaseURL: vaultURL}
	auditClient := &infrastructure.AuditHTTPClient{BaseURL: auditURL}
	fetcher := proxycore.NewCredentialFetcher(vaultClient, proxyID)
	terminator := proxycore.NewTerminator(auditClient)
	listener := proxycore.NewListener(fetcher, terminator)

	pending := infrastructure.NewPendingSessions()

	ln, err := net.Listen("tcp", ":"+sshPort)
	if err != nil {
		log.Fatalf("ssh listen: %v", err)
	}

	server := &interfaces.SSHServer{
		HostSigner:  hostSigner,
		Pending:     pending,
		Listener:    listener,
		DialTimeout: 10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		log.Printf("ssh-proxy: SSH listener on :%s", sshPort)
		if err := server.Serve(ctx, ln); err != nil {
			log.Printf("ssh-proxy: SSH server stopped: %v", err)
		}
	}()

	httpServer := interfaces.NewHTTPServer(pending, "127.0.0.1:"+sshPort)
	log.Printf("ssh-proxy: internal API on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", httpPort)
	log.Printf("  -> vault: %s", vaultURL)
	log.Printf("  -> audit: %s", auditURL)
	log.Fatal(http.ListenAndServe(":"+httpPort, httpServer.Routes()))
}
