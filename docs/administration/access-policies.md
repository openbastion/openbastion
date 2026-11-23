# Gestion des politiques RBAC

Une politique lie un rôle à un motif de ressource et à un motif d’action (`docs/architecture/data-architecture.md` §3, ADR-0114). Exemple : autoriser le rôle `dba` à ouvrir des sessions sur les comptes préfixés `prod-db-` :

```sh
curl -X POST https://bastion.example.com/api/v1/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dba-prod-db-access",
    "role": "dba",
    "resourcePattern": "vault:account:prod-db-*",
    "actionPattern": "session:create",
    "effect": "allow"
  }'
```

Renseignez toujours `actionPattern` pour les nouvelles politiques : une action exacte est préférable ; un joker final ne doit couvrir que la famille d’actions voulue. L’API conserve temporairement l’omission comme `*` pour les clients historiques (ADR-0114), mais cette compatibilité ne doit pas être utilisée par les nouveaux clients.

Le comportement est **deny-by-default** (`docs/security/authorization-rbac-abac.md`) : un rôle sans politique associée n'ouvre l'accès à rien. Il n'existe pas de politique implicite « administrateur = accès total » — elle doit être créée explicitement si souhaitée.
