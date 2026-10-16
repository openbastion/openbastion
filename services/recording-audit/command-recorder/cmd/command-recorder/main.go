// Command command-recorder runs the Command Recorder (doc 00 §4.4): the
// service that stores, command by command, what operators ran in a session,
// so a session can be replayed as text.
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := mustEnv("PORT", "8087")
	authzURL := mustEnv("AUTHORIZATION_URL", "http://127.0.0.1:8083")

	var repo domain.CommandRepository
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		db, err := infrastructure.OpenPostgres(context.Background(), dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		repo = infrastructure.NewPostgresStore(db)
		log.Printf("command-recorder: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		repo = infrastructure.NewInMemoryStore()
		log.Printf("command-recorder: DATABASE_URL not set, using in-memory storage (dev/test only — recordings are lost on restart)")
	}

	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authzURL}
	srv := interfaces.NewHTTPServer(application.NewRecorderService(repo, authz))

	log.Printf("command-recorder listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
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
