// Command authorization runs the Authorization Service (doc 00 §4.1) — the
// single policy decision point every other service defers to.
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/openbastion/openbastion/services/access/authorization/internal/application"
	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
	"github.com/openbastion/openbastion/services/access/authorization/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/authorization/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := mustEnv("PORT", "8083")
	bootstrapRole := mustEnv("BOOTSTRAP_ADMIN_ROLE", "platform-admin")

	var store domain.PolicyRepository
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(db)
		log.Printf("authorization: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewInMemoryStore()
		log.Printf("authorization: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	svc := application.NewAuthorizationService(store)

	// BootstrapAdminPolicy is a deliberate no-op on any store that already
	// has at least one policy — safe to call on every single startup,
	// including every restart of an already-initialized deployment (see
	// the method's doc comment and NOTES_SANDBOX.md). This is this
	// system's one break-glass seam: the operator who controls
	// BOOTSTRAP_ADMIN_ROLE at first boot controls who can create every
	// policy thereafter.
	if created, err := svc.BootstrapAdminPolicy(context.Background(), bootstrapRole, "system-bootstrap"); err != nil {
		log.Printf("bootstrap admin policy skipped (non-fatal): %v", err)
	} else if created {
		log.Printf("authorization: bootstrapped role %q with %s (first boot of an empty policy store)", bootstrapRole, application.PolicyAdminResource)
	} else {
		log.Printf("authorization: policy store already initialized, bootstrap is a no-op")
	}

	srv := interfaces.NewHTTPServer(svc)
	log.Printf("authorization listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
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
