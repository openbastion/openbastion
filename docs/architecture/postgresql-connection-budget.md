# Budget de connexions PostgreSQL

Ce document décrit le contrat de dimensionnement proposé par [ADR-0135](../adr/0135-borner-les-pools-postgresql-par-service-dans-un-budget-de-deploiement.md). L'ADR est accepté. Les variables et le validateur décrits ici ne sont pas encore implémentés ; leur réalisation constitue l'incrément suivant.

## Périmètre

Sept services possèdent aujourd'hui un pool `database/sql` PostgreSQL :

| Service | Pool ouvert actuel | Pool inactif actuel |
|---|---:|---:|
| Authentication | 10 | 10 |
| Authorization | 10 | 10 |
| Session Broker | 10 | 10 |
| Audit Service | 10 | 10 |
| Password Vault | 10 | 10 |
| Command Recorder | 10 | 10 |
| Video Recorder | 10 | 10 |
| **Total à une instance de chaque service** | **70** | **70 maximum conservées** |

`MaxIdleConns` ne s'ajoute pas à `MaxOpenConns` : les connexions inactives font partie des connexions ouvertes et ne sont pas toutes établies au démarrage.

## Configuration par processus

Les variables sont lues par le `main.go` du service puis transmises à son constructeur de pool :

| Variable | Défaut | Bornes |
|---|---:|---|
| `DB_POOL_MAX_OPEN_CONNS` | `10` | entier strict de 1 à 1 000 |
| `DB_POOL_MAX_IDLE_CONNS` | `min(max_open, 10)` | entier strict de 0 à `max_open` |

Une valeur absente prend le défaut. Une valeur mal formée ou hors borne refuse le démarrage. `0` n'est jamais admis pour `max_open`, car `database/sql` l'interprète comme aucune limite. Chaque Deployment définit ses propres valeurs ; il n'existe pas de variable globale qui configure indistinctement tous les services.

## Budget d'un cluster

Le manifeste de capacité à introduire par cluster déclare :

```yaml
postgres:
  max_connections: 100
  reserved_connections: 20 # exemple uniquement : opérations, slots réservés et clients hors pools applicatifs
services:
  authentication: { max_instances: 1, max_open_per_instance: 10 }
  authorization: { max_instances: 1, max_open_per_instance: 10 }
  session-broker: { max_instances: 1, max_open_per_instance: 10 }
  audit-service: { max_instances: 1, max_open_per_instance: 10 }
  password-vault: { max_instances: 1, max_open_per_instance: 10 }
  command-recorder: { max_instances: 1, max_open_per_instance: 10 }
  video-recorder: { max_instances: 1, max_open_per_instance: 10 }
```

Le validateur calculera :

```text
Σ(max_instances × max_open_per_instance) + reserved_connections <= max_connections
```

Pour l'exemple ci-dessus : `7 × 10 + 20 = 90 <= 100`. Les 10 connexions restantes sont une marge, pas une réserve déjà consommée.

`max_instances` est le nombre maximal de processus pouvant se connecter simultanément : HPA max + capacité de rollout (`maxSurge`), jobs/migrations et consommateurs temporaires éventuels. Les bases séparées d'un même serveur PostgreSQL partagent le même budget. Un manifeste doit être distinct par cluster PostgreSQL.

## Contrôles du futur validateur

- Le cluster, les sept services et les champs requis sont déclarés une seule fois.
- `max_connections > 0`, `reserved_connections >= 0`, `max_instances > 0`, `max_open_per_instance > 0`.
- Les multiplications et additions sont contrôlées contre les débordements.
- La somme des pools ne dépasse pas `max_connections - reserved_connections`.
- Les valeurs du manifeste correspondent aux variables injectées dans chaque Deployment.
- Une configuration invalide échoue en CI et bloque le déploiement ; aucun ajustement automatique ou silencieux n'est permis.

## Observabilité

Chaque service publiera les champs `sql.DB.Stats()` sous des métriques à cardinalité bornée : connexions ouvertes, en usage, inactives, maximum configuré, attentes et durée d'attente cumulée. Les métriques guident un redimensionnement explicite ; elles ne déclenchent pas de changement automatique de pool.

## Hors périmètre

- Aucun changement des défauts 10/10 avant mesure sur une topologie représentative.
- Aucun cache de la tête Audit ni relâchement des vérifications ADR-0116.
- Aucun PgBouncer dans cette étape ; son pool serveur nécessitera un budget distinct.
- Aucun benchmark multi-hôte tant que l'utilisateur ne l'a pas autorisé.
