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

	svc := application.NewAuditService(store)
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
