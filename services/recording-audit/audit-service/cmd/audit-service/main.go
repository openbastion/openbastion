// Command audit-service runs the Audit Service (doc 00 §4.4).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see
// internal/interfaces/http.go and /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/interfaces"
)

func main() {
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.AuditService)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	var store application.Store
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(db)
		log.Printf("audit-service: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewInMemoryStore()
		log.Printf("audit-service: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	// The chain is keyed (ADR-0027). With a database the key is required: a chain that
	// outlives the process must be verifiable by the next one, and a key made up at start
	// would make yesterday's chain unverifiable. In memory the chain dies with the process,
	// and so may its key.
	svc := application.NewAuditService(store)
	keyHex, previousHex := os.Getenv("AUDIT_CHAIN_KEY_HEX"), os.Getenv("AUDIT_CHAIN_PREVIOUS_KEYS_HEX")
	switch {
	case keyHex != "":
		keys, err := application.ParseChainKeys(keyHex, previousHex)
		if err != nil {
			// The error never repeats the value.
			log.Fatalf("audit-service: AUDIT_CHAIN_KEY_HEX / AUDIT_CHAIN_PREVIOUS_KEYS_HEX: %v — refusing to start", err)
		}
		svc.WithChainKeys(keys)
		log.Printf("audit-service: the chain is signed with key %s (%d key(s) held for verification)", keys.CurrentID(), keys.Count())
	case os.Getenv("DATABASE_URL") != "":
		log.Fatalf("audit-service: DATABASE_URL is set, so the chain outlives this process and AUDIT_CHAIN_KEY_HEX is required (64 hex digits, kept outside the database; `openssl rand -hex 32`) — refusing to start")
	case previousHex != "":
		log.Fatalf("audit-service: AUDIT_CHAIN_PREVIOUS_KEYS_HEX is set without AUDIT_CHAIN_KEY_HEX — refusing to start")
	default:
		log.Printf("audit-service: in-memory chain signed with a random key that lives as long as this process (dev/test only)")
	}
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("audit-service listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
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
