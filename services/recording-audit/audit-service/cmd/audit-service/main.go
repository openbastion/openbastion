// Command audit-service runs the Audit Service (doc 00 §4.4).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see
// internal/interfaces/http.go and /NOTES_SANDBOX.md.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/interfaces"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("audit-service listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Fatal(http.ListenAndServe(":"+port, srv.Routes()))
}
