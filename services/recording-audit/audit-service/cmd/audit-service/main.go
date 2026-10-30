// Command audit-service runs the Audit Service (doc 00 §4.4).
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
	// The head of the chain is anchored outside the database (ADR-0028). With a database the
	// anchors are required: they are what a chain rewritten entirely, or cut at its end, cannot
	// survive. In memory there is nothing to rewrite behind the process's back.
	if path := os.Getenv("AUDIT_ANCHOR_FILE"); path != "" || os.Getenv("DATABASE_URL") != "" {
		if path == "" {
			log.Fatalf("audit-service: DATABASE_URL is set, so AUDIT_ANCHOR_FILE is required (an absolute path the database does not control: another volume, an append-only mount) — refusing to start")
		}
		interval := 60
		if v := os.Getenv("AUDIT_ANCHOR_INTERVAL_SECONDS"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 3600 {
				log.Fatalf("audit-service: AUDIT_ANCHOR_INTERVAL_SECONDS must be a number between 1 and 3600, got %q", v)
			}
			interval = n
		}
		sink, err := infrastructure.NewFileAnchorSink(path)
		if err != nil {
			log.Fatalf("audit-service: AUDIT_ANCHOR_FILE: %v — refusing to start", err)
		}
		svc.WithAnchors(sink)
		go anchorEvery(svc, time.Duration(interval)*time.Second)
		log.Printf("audit-service: the head of the chain is anchored to %s every %ds (anchors verified by verify-chain)", path, interval)
	} else {
		log.Printf("audit-service: in-memory chain, not anchored (dev/test only)")
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

// anchorEvery anchors the head of the chain at every tick. A failure is written once per
// episode, not once per tick: anchoring is out of band, events are still written and signed.
func anchorEvery(svc *application.AuditService, every time.Duration) {
	failing := false
	for range time.Tick(every) {
		if _, err := svc.Anchor(context.Background()); err != nil {
			if !failing {
				log.Printf("audit-service: anchoring the head of the chain failed (written once until it works again): %v", err)
			}
			failing = true
			continue
		}
		if failing {
			log.Printf("audit-service: anchoring the head of the chain works again")
		}
		failing = false
	}
}
