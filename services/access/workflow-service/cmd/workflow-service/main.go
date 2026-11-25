package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/command"
	"github.com/openbastion/openbastion/pkg/dbpool"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/application"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/interfaces"
)

func runService() {
	log.Printf("workflow-service %s", buildinfo.String())
	rt, err := mtls.Setup(mtls.WorkflowService)
	if err != nil {
		log.Fatalf("workflow-service: %v", err)
	}

	port := env("PORT", "8091")
	authenticationURL := env("AUTHENTICATION_URL", rt.DefaultURL("127.0.0.1:8086"))
	authorizationURL := env("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))
	auditURL := env("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))

	upstreams, err := rt.Client(
		mtls.Peer{URL: authenticationURL, Service: mtls.Authentication},
		mtls.Peer{URL: authorizationURL, Service: mtls.Authorization},
		mtls.Peer{URL: auditURL, Service: mtls.AuditService},
	)
	if err != nil {
		log.Fatalf("workflow-service: upstream mTLS clients: %v", err)
	}

	var poolDB *sql.DB
	var poolConfig dbpool.Config
	var store interface {
		domain.HierarchyRepository
		domain.ApprovalRepository
		domain.AuditOutboxRepository
	}
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		poolConfig, err = dbpool.ParseEnv(os.LookupEnv)
		if err != nil {
			log.Fatalf("workflow-service: database pool configuration: %v", err)
		}
		poolDB, err = infrastructure.OpenPostgres(context.Background(), dsn, poolConfig)
		if err != nil {
			log.Fatalf("workflow-service: postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(poolDB)
		log.Printf("workflow-service: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewMemoryStore()
		log.Printf("workflow-service: DATABASE_URL not set, using in-memory storage (development/test only)")
	}

	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: upstreams}
	users := &infrastructure.UserDirectoryHTTPClient{BaseURL: authenticationURL, Client: upstreams}
	authorizer := &infrastructure.AuthorizationHTTPClient{BaseURL: authorizationURL, Client: upstreams}
	svc := application.NewHierarchyService(store, users, authorizer, audit)
	approvals := application.NewApprovalService(store, store, users, authorizer, audit)
	dispatcher := application.NewAuditOutboxDispatcher(store, audit)
	expiryWorker := application.NewApprovalExpiryWorker(approvals)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go dispatcher.Run(ctx)
	go expiryWorker.Run(ctx)

	srv := interfaces.NewHTTPServer(svc).WithApprovalService(approvals)
	if poolDB != nil {
		srv.WithMetrics(dbpool.MetricsHandler("workflow-service", poolDB, poolConfig))
		log.Printf("workflow-service: PostgreSQL pool max_open=%d max_idle=%d", poolConfig.MaxOpenConns, poolConfig.MaxIdleConns)
	}
	log.Printf("workflow-service listening on :%s", port)
	if err := rt.ListenAndServe(":"+port, srv.Routes(), interfaces.CallerRules()); err != nil {
		log.Fatalf("workflow-service: %v", err)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func redactDSN(dsn string) string {
	if at := strings.LastIndex(dsn, "@"); at >= 0 {
		return "***@" + dsn[at+1:]
	}
	return dsn
}

func main() {
	if err := command.NewServiceCommand("workflow-service", runService).Execute(); err != nil {
		log.Fatalf("workflow-service: %v", err)
	}
}
