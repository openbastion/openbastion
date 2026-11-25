# Budget de connexions PostgreSQL

Ce document décrit l'implémentation de [ADR-0135](../adr/0135-borner-les-pools-postgresql-par-service-dans-un-budget-de-deploiement.md). Le budget est défini par cluster PostgreSQL ; les pools restent bornés localement par processus.

## Périmètre

Huit services possèdent un pool `database/sql` PostgreSQL : Authentication, Authorization, Session Broker, Workflow Service, Audit Service, Password Vault, Command Recorder et Video Recorder. `MaxIdleConns` est un sous-ensemble de `MaxOpenConns` : il ne s'ajoute jamais au budget de connexions ouvertes.

## Configuration par processus

Chaque service lit ces variables au démarrage et transmet le résultat à son constructeur PostgreSQL :

| Variable | Défaut du binaire | Bornes |
|---|---:|---|
| `DB_POOL_MAX_OPEN_CONNS` | `10` | entier décimal strict de 1 à 1 000 |
| `DB_POOL_MAX_IDLE_CONNS` | `min(max_open, 10)` | entier décimal strict de 0 à `max_open` |

Une variable absente prend son défaut. Une variable présente mais vide, signée, contenant des espaces, non entière ou hors bornes fait échouer le démarrage ; aucune valeur invalide ne déclenche un fallback silencieux. `0` n'est jamais admis pour `max_open`, car `database/sql` l'interprète comme aucune limite.

Les deux variables sont définies par service, pas globalement. Dans les fichiers Compose, elles sont alimentées par des variables hôte distinctes :

| Service | Variables hôte Compose |
|---|---|
| Authentication | `AUTHENTICATION_DB_POOL_MAX_OPEN_CONNS`, `AUTHENTICATION_DB_POOL_MAX_IDLE_CONNS` |
| Authorization | `AUTHORIZATION_DB_POOL_MAX_OPEN_CONNS`, `AUTHORIZATION_DB_POOL_MAX_IDLE_CONNS` |
| Session Broker | `SESSION_BROKER_DB_POOL_MAX_OPEN_CONNS`, `SESSION_BROKER_DB_POOL_MAX_IDLE_CONNS` |
| Workflow Service | `WORKFLOW_SERVICE_DB_POOL_MAX_OPEN_CONNS`, `WORKFLOW_SERVICE_DB_POOL_MAX_IDLE_CONNS` |
| Audit Service | `AUDIT_SERVICE_DB_POOL_MAX_OPEN_CONNS`, `AUDIT_SERVICE_DB_POOL_MAX_IDLE_CONNS` |
| Password Vault | `PASSWORD_VAULT_DB_POOL_MAX_OPEN_CONNS`, `PASSWORD_VAULT_DB_POOL_MAX_IDLE_CONNS` |
| Command Recorder | `COMMAND_RECORDER_DB_POOL_MAX_OPEN_CONNS`, `COMMAND_RECORDER_DB_POOL_MAX_IDLE_CONNS` |
| Video Recorder | `VIDEO_RECORDER_DB_POOL_MAX_OPEN_CONNS`, `VIDEO_RECORDER_DB_POOL_MAX_IDLE_CONNS` |

Les valeurs Compose par défaut restent 10/10. Si un opérateur abaisse `max_open` sous 10 dans Compose, il doit également abaisser `max_idle` à une valeur inférieure ou égale. Dans un Deployment Kubernetes qui omet `DB_POOL_MAX_IDLE_CONNS`, le défaut du binaire calcule `min(max_open, 10)`.

Exemple d'override Compose pour Authentication :

```dotenv
AUTHENTICATION_DB_POOL_MAX_OPEN_CONNS=12
AUTHENTICATION_DB_POOL_MAX_IDLE_CONNS=10
```

Après tout override, le manifeste de capacité du cluster doit être ajusté avec le même `max_open_per_instance` et le validateur doit repasser.

## Budget d'un cluster

Le manifeste d'exemple versionné est [`deploy/postgresql/capacity.yaml`](../../deploy/postgresql/capacity.yaml). Il déclare les huit services et la capacité du serveur PostgreSQL :

```yaml
postgres:
  max_connections: 100
  reserved_connections: 20 # exemple uniquement : à dimensionner pour le cluster réel
services:
  authentication: { max_instances: 1, max_open_per_instance: 10 }
  authorization: { max_instances: 1, max_open_per_instance: 10 }
  session-broker: { max_instances: 1, max_open_per_instance: 10 }
  workflow-service: { max_instances: 1, max_open_per_instance: 10 }
  audit-service: { max_instances: 1, max_open_per_instance: 10 }
  password-vault: { max_instances: 1, max_open_per_instance: 10 }
  command-recorder: { max_instances: 1, max_open_per_instance: 10 }
  video-recorder: { max_instances: 1, max_open_per_instance: 10 }
```

Le contrôle applique :

```text
Σ(max_instances × max_open_per_instance) + reserved_connections <= max_connections
```

Pour l'exemple actuel : `8 × 10 + 20 = 100 <= 100`, soit aucune connexion restante dans cette topologie illustrative. L'exploitant doit augmenter `max_connections`, réduire les plafonds ou ajuster la réserve avant d'ajouter des réplicas. Les 20 connexions réservées sont illustratives, pas une valeur imposée. `reserved_connections` couvre les clients hors pools applicatifs et les besoins d'exploitation. Les bases séparées d'un même serveur PostgreSQL partagent le même budget.

`max_instances` doit inclure le maximum HPA, les réplicas temporaires du rollout (`maxSurge`), les jobs/migrations et les clients temporaires. L'exemple Compose suppose une instance de chaque service ; Video Recorder est compté même si son profil Compose `recording` n'est pas activé. Un manifeste distinct est nécessaire pour chaque cluster PostgreSQL.

## Validateur CI

Lancer depuis la racine :

```sh
make db-pool-budget-check
```

Le validateur Go :

- refuse les champs YAML inconnus, clés dupliquées et documents multiples ;
- exige exactement les huit services PostgreSQL connus ;
- vérifie les bornes et les débordements de multiplication/addition ;
- refuse tout dépassement de `max_connections` après réserve ;
- vérifie que les valeurs par défaut `DB_POOL_MAX_OPEN_CONNS` et `DB_POOL_MAX_IDLE_CONNS` injectées dans les services correspondent aux valeurs attendues dans les fichiers `deploy/docker-compose/docker-compose.yml` et `deploy/base44/docker-compose.yml` ;
- est exécuté dans le workflow Go requis de la CI.

Le contrôle statique ne peut pas lire les variables d'environnement privées d'un déploiement au moment de la CI, ni découvrir le nombre réel de réplicas d'un cluster Kubernetes. L'exploitant doit donc synchroniser le manifeste avec les overrides et la capacité maximale réelle du déploiement. Un dépassement détecté bloque le contrôle CI ; aucun ajustement automatique du pool n'est fait.

## Observabilité

Chaque service expose `GET /metrics` sur son listener HTTP interne, autorisé par l'allowlist mTLS du service. Les métriques Prometheus à cardinalité bornée portent uniquement le label `service` :

- `openbastion_db_connections_open`, `..._in_use`, `..._idle` ;
- `openbastion_db_connections_max_open`, `..._max_idle` ;
- `openbastion_db_pool_wait_count_total`, `..._wait_duration_seconds_total`.

Elles proviennent de `sql.DB.Stats()` et de la configuration validée. Aucun DSN, nom d'utilisateur, secret ou paramètre de connexion n'est exposé. Si un service fonctionne sans `DATABASE_URL` en mode mémoire, `/metrics` répond `503`. Le endpoint n'est pas relayé par la Gateway et n'est pas accessible sans identité mTLS interne.

Les métriques éclairent un redimensionnement explicite ; elles ne déclenchent aucun autoscaling du pool. `MaxIdleConns` ne se cumule pas avec `MaxOpenConns`.

## Garanties préservées et hors périmètre

- Les huit défauts restent à 10/10 ; aucun gain de performance mesuré localement n'est transformé en défaut de production.
- Aucun cache de la tête Audit et aucun relâchement des vérifications d'intégrité ADR-0116.
- Aucun PgBouncer introduit ; un pool serveur PgBouncer demanderait un budget séparé.
- Aucun benchmark multi-hôte lancé ; il reste différé à la demande de l'utilisateur.
