// Command authorization runs the Authorization Service (doc 00 §4.1) — the
// single policy decision point every other service defers to.
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/openbastion/openbastion/services/access/authorization/internal/application"
	"github.com/openbastion/openbastion/services/access/authorization/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/authorization/internal/interfaces"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}

	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuthorizationService(store)
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("authorization listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Fatal(http.ListenAndServe(":"+port, srv.Routes()))
}
