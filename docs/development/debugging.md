# Observabilité en développement

La stack locale (`make dev-up`) inclut Prometheus, Grafana, Loki et Tempo (`docs/architecture/system-overview.md`). Chaque service émet ses traces via OpenTelemetry dès son démarrage — inutile d'instrumenter manuellement un nouvel endpoint, l'instrumentation est portée par `pkg/telemetry` (`docs/development/repository-structure.md` §3), déjà branchée sur le middleware gRPC/HTTP commun.
