// Command authentication runs the Authentication Service (doc 00 §4.1).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/authentication/internal/interfaces"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8086"
	}

	key, err := infrastructure.GenerateSigningKey()
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	hasher := infrastructure.Argon2Hasher{}
	tokens := infrastructure.NewTokenIssuer(key)
	svc := application.NewAuthenticationService(store, hasher, tokens, time.Hour)

	// Demo seed — real onboarding goes through POST /auth/v1/users.
	if os.Getenv("SKIP_DEMO_SEED") == "" {
		ctx := context.Background()
		if _, err := svc.CreateUser(ctx, "demo-dba", "Demo DBA", "demo-password", []string{"dba"}); err != nil {
			log.Fatalf("seed: %v", err)
		}
	}

	srv := interfaces.NewHTTPServer(svc)
	log.Printf("authentication listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Fatal(http.ListenAndServe(":"+port, srv.Routes()))
}
