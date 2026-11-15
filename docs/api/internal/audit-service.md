# Contrats HTTP internes — Audit Service

Toutes les routes de ce document sont internes, sous mTLS, et ne font pas partie de l'API publique Gateway.

## `GET /audit/v1/secret-injections` (ADR-0112)

- **Appelant mTLS autorisé :** `admin-cli` uniquement.
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
