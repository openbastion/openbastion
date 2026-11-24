# Contrats HTTP internes — Audit Service

Toutes les routes de ce document sont internes, sous mTLS, et ne font pas partie de l'API publique Gateway. La façade publique définie par ADR-0113 est décrite plus bas.

## `GET /audit/v1/secret-injections` (ADR-0112)

- **Appelants mTLS autorisés :** `admin-cli` (CLI) et `api-gateway` (façade publique ADR-0113). Aucun autre service n’est autorisé.
- **Query :** `limit` facultatif, entier de 1 à 500 (défaut : 100) ; `before` facultatif, identifiant `injection_id` de la dernière entrée de la page précédente.
- **Réponse :** `200 application/json`, `Cache-Control: no-store`.
- **Erreur :** `400` pour une limite ou un curseur mal formé ; `409` si le curseur a disparu (par exemple après archivage), auquel cas il faut recommencer la pagination ; `405` pour une autre méthode ; `503` si la chaîne ou les checkpoints ne peuvent pas être lus.

Exemple de réponse :

```json
{
  "outcomes": [
    {
      "injection_id": "0123456789abcdef0123456789abcdef",
      "session_id": "session-123",
      "account_id": "account-prod",
      "protocol": "ssh",
      "emitter": "ssh-proxy",
      "status": "outcome_unknown",
      "reason": "missing_terminal_event",
      "started_at": "2026-11-15T10:00:00Z",
      "start_event_id": "audit-event-id"
    }
  ],
  "coverage": "verified_archives_and_retained_chain",
  "archived_history_excluded": false,
  "scanned_events": 142,
  "archived_events": 100,
  "has_more": false
}
```

Valeurs de `status` : `completed`, `failed`, `outcome_unknown`. `completed` signifie qu'un événement terminal positif cohérent existe dans l'audit ; cela ne prouve pas indépendamment que la cible a reçu le secret complet. `failed` signifie que le proxy a journalisé un échec de frappe ; une écriture partielle reste possible (`reason=proxy_reported_input_failure_may_be_partial`). Dans les deux cas, ne jamais déduire que la cible est inchangée et ne pas rejouer automatiquement le secret sans vérification. `outcome_unknown` nécessite également une vérification manuelle de la cible.

Quand `has_more` vaut `true`, `next_before` contient l'identifiant à transmettre comme paramètre `before` pour lire la page suivante. Le curseur est stable face aux nouvelles injections ; s'il n'est plus présent ni dans la chaîne retenue ni dans une archive vérifiée, l'API répond `409` plutôt que de sauter silencieusement des résultats.

`reason` peut préciser `missing_start_event`, `duplicate_start_event`, `invalid_start_evidence`, `missing_terminal_event`, `multiple_terminal_events`, `evidence_mismatch`, `invalid_terminal_evidence` ou `proxy_reported_input_failure_may_be_partial`.

Avant de construire la projection, l’Audit Service vérifie la chaîne retenue, les MAC des checkpoints et des ancres, puis relit chaque archive référencée. Le SHA-256 est calculé sur les octets exacts décodés ; le nombre d’événements, les bornes, le mois, la continuité `prev_hash`, les versions de hash et chaque hash d’événement sont vérifiés avec les clés historiques correspondantes. Les ancres couvertes doivent référencer des événements retrouvés dans ces archives. Une archive absente, illisible, altérée, tronquée, non référencée ou signée avec une clé indisponible rend la vue indisponible (fail closed), jamais partielle silencieusement.

`coverage` vaut `retained_audit_chain` lorsqu’aucune archive n’est référencée, ou `verified_archives_and_retained_chain` lorsque toutes les archives référencées ont été lues et vérifiées. `archived_events` compte les événements relus depuis les archives ; `archived_history_excluded` reste `false` uniquement après vérification complète. La route ne modifie jamais la chaîne, les archives ni les checkpoints.

Depuis le poste d'administration, avec le certificat client `admin-cli` :

```sh
curl --fail --silent --show-error \
  --cacert .pki/ca.pem \
  --cert .pki/admin-cli/cert.pem \
  --key .pki/admin-cli/key.pem \
  'https://127.0.0.1:8082/audit/v1/secret-injections?limit=100'
```


## Lectures internes de la file d’alertes de session (ADR-0117/0122)

Ces routes internes sont réservées à l’identité mTLS `api-gateway`. Elles ne sont pas des routes opérateur et ne sont jamais exposées directement. La Gateway doit vérifier le bearer token et la permission Authorization sur la ressource et l’action exactes avant chaque appel. Le certificat mTLS ne transporte que l’identité du workload ; aucun utilisateur ou rôle n’est accepté dans le corps ou la query.

### `GET /audit/v1/session-alerts`

- **Query autorisée :** `status` (`unacknowledged` ou `acknowledged`), `severity` (`info`, `low`, `medium`, `high`, `critical`), `session_id`, `since`, `until` (RFC 3339), `cursor` (opaque), `limit` (défaut 50, maximum 100). Les paramètres inconnus ou dupliqués sont refusés.
- **Tri :** `detected_at DESC, id DESC`. Le curseur encode la dernière paire `(detected_at, id)` de la page ; il est opaque pour le client et ne constitue pas un jeton d’autorisation.
- **Réponse :** `200 application/json`, `Cache-Control: no-store`, `{alerts, has_more, next_cursor?}`. Chaque occurrence expose uniquement son identifiant, sa règle/version, la référence de preuve source, la session, la sévérité, le statut, le résumé borné, les dates, la révision et les champs d’acquittement. Le contenu de l’événement source n’est jamais retourné.
- **Erreurs :** `400` filtre/cursor invalide, `405` méthode incorrecte, `503` projection indisponible. La liste vide est `200` avec `alerts: []`.

### `GET /audit/v1/session-alerts/summary`

Réponse `200` : `{unacknowledged_count, by_severity, as_of, durable}`. Les cinq sévérités sont toujours présentes dans `by_severity`, y compris avec une valeur zéro. Les compteurs sont calculés par une seule instruction SQL afin qu’ils représentent un même instantané. `durable=false` en mémoire (tests/développement) et `true` avec PostgreSQL. `Cache-Control: no-store`. Query string non vide refusée (`400`), autre méthode `405`, dépendance indisponible `503`.

### `GET /audit/v1/session-alerts/{id}`

Retourne la même projection bornée que la liste (`200`), `404` si l’identifiant valide n’existe pas, `400` si l’identifiant n’est pas au format `alert_` suivi de 32 caractères hexadécimaux minuscules, `405` pour une autre méthode et `503` si le magasin est indisponible. Aucun événement source brut ni détail de credential n’est inclus.

**Frontière de confiance :** `CallerRules()` n’autorise que `api-gateway` sur ces routes. Le service Audit ne connaît pas les rôles opérateur ; la Gateway vérifie `session-alerts:read` sur `session-alerts:all` pour la liste et le résumé, ou sur `session-alerts:{id}` pour le détail, avant d’appeler le service sous son identité mTLS. Une permission de lecture d’alerte ne confère pas `session.read`. L’acquittement audité n’est pas encore exposé.

Les DTO HTTP de ces lectures sont documentés ici plutôt que dans `proto/audit/v1/audit.proto` : le contrat interservices reste HTTP/JSON sous mTLS (ADR-0050), et aucune RPC Protobuf n’est introduite. Les tests de contrats signalent explicitement cette exception.

## Façade publique opérateur (ADR-0113)

L’Admin UI n’appelle jamais ce service directement et ne reçoit jamais le certificat `admin-cli`. Elle utilise `GET /audit/secret-injections` sur la Gateway. La Gateway vérifie le bearer token, puis appelle Authorization avec les rôles vérifiés, `action=audit:secret-injections:read` et `resource=audit:secret-injections:all`. Depuis ADR-0114, Authorization doit faire correspondre simultanément `action_pattern` et `resource_pattern` ; une politique qui ne couvre que la ressource est refusée. Le refus par défaut est `403` ; une panne d’Authorization est `503`. Après autorisation, la Gateway appelle cette route interne sous son identité mTLS `api-gateway`. Seuls `limit` et `before` sont relayés. La réponse publique est bornée à 2 Mio et porte `Cache-Control: no-store`.

Cette permission est transverse : elle donne accès à toutes les injections et tous les comptes. Elle n’est accordée implicitement à aucun rôle. La consultation n’écrit pas dans la chaîne d’audit consultée ; ce choix a été accepté dans ADR-0113.

## Les têtes des métadonnées de session (ADR-0116 §3, §4)

Réservées au certificat mTLS `session-broker` (`CallerRules`). Rien de secret ne passe : un identifiant de session, une révision, un digest et l'identifiant de la clé HMAC du Broker, jamais la clé.

### `POST /audit/v1/session-metadata/attestations`

Corps (champs inconnus refusés) : `{"session_id": "…", "revision": 3, "metadata_sha256": "<64 hex>", "key_id": "k1"}`. Le Broker l'envoie après chaque changement validé d'une ligne `sessions`.

| Réponse | Quand |
|---|---|
| `200` et la tête | La révision suit la tête (ou la session n'en a pas encore) : l'événement `session.metadata_attested` (détails `revision`, `metadata_sha256`, `key_id`) est écrit dans la chaîne **et** la tête avance, dans une seule transaction. Ou c'est la tête elle-même (même révision, même digest, même clé) : rien n'est écrit, la réponse est idempotente. |
| `409` et `{"error", "head"}` | Une révision plus ancienne que la tête (retour en arrière), la révision de la tête avec un autre digest ou une autre clé (altération), ou plus d'une révision d'avance. Rien n'est écrit. |
| `400` | Corps mal formé, révision 0, digest qui n'a pas 32 octets, identifiant de clé hors de `[A-Za-z0-9._-]{1,64}`, ou émetteur autre que le Broker. |
| `503` | La base de l'Audit Service ne répond pas. |

### `GET /audit/v1/session-metadata/head?session_id=…`

`200` et la tête (`session_id`, `revision`, `metadata_sha256`, `key_id`, `event_id`) **après vérification contre l'événement signé** : l'événement est recalculé à partir des champs de la tête et doit redonner le hash que la chaîne a signé, sous la clé de chaîne qui l'a signé. Cette vérification ne lit pas l'événement en base : une tête reste vérifiable quand son mois est archivé (ADR-0032). `404` sans tête ; `500` si la tête ne se recalcule pas (projection altérée).
