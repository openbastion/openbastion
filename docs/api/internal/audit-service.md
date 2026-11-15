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
  "coverage": "retained_audit_chain",
  "archived_history_excluded": false,
  "scanned_events": 42,
  "has_more": false
}
```

Valeurs de `status` : `completed`, `failed`, `outcome_unknown`. `completed` signifie qu'un événement terminal positif cohérent existe dans l'audit ; cela ne prouve pas indépendamment que la cible a reçu le secret complet. `failed` signifie que le proxy a journalisé un échec de frappe ; une écriture partielle reste possible (`reason=proxy_reported_input_failure_may_be_partial`). Dans les deux cas, ne jamais déduire que la cible est inchangée et ne pas rejouer automatiquement le secret sans vérification. `outcome_unknown` nécessite également une vérification manuelle de la cible.

Quand `has_more` vaut `true`, `next_before` contient l'identifiant à transmettre comme paramètre `before` pour lire la page suivante. Le curseur est stable face aux nouvelles injections ; s'il n'est plus présent dans la rétention active, l'API répond `409` plutôt que de sauter silencieusement des résultats.

`reason` peut préciser `missing_start_event`, `duplicate_start_event`, `invalid_start_evidence`, `missing_terminal_event`, `multiple_terminal_events`, `evidence_mismatch`, `invalid_terminal_evidence` ou `proxy_reported_input_failure_may_be_partial`.

Avant de construire la projection, l’Audit Service vérifie la chaîne et ses ancres/checkpoints ; une chaîne non vérifiable rend la vue indisponible. La projection ne lit que les événements encore présents dans la chaîne active. Si `archived_history_excluded` vaut `true`, les archives historiques ne sont pas incluses ; une consultation des archives vérifiées est nécessaire pour une enquête exhaustive. La route ne modifie jamais la chaîne.

Depuis le poste d'administration, avec le certificat client `admin-cli` :

```sh
curl --fail --silent --show-error \
  --cacert .pki/ca.pem \
  --cert .pki/admin-cli/cert.pem \
  --key .pki/admin-cli/key.pem \
  'https://127.0.0.1:8082/audit/v1/secret-injections?limit=100'
```
