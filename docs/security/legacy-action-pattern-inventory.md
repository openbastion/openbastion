# Inventaire des politiques `action_pattern=*`

**État :** audit du code source effectué sur `main` au 23 novembre 2026 ; inventaire des lignes d’une installation réelle encore requis.

## Constat

ADR-0114 compare bien la ressource et l’action, et la décision reste fail-closed. Le risque résiduel vient des politiques dont `action_pattern` vaut `*` : elles autorisent toutes les actions qui correspondent au motif de ressource. Ce n’est pas un contournement du moteur, mais une portée d’action volontairement large.

L’audit des clients de création a relevé :

| Surface | État avant ce changement | Traitement |
|---|---|---|
| `POST /policies` (API publique) | Omission de `actionPattern` acceptée comme `*` pour compatibilité ADR-0114 | Compatibilité conservée ; les clients nouveaux doivent fournir l’action
| Admin UI (`PolicyForm`) | Le formulaire omettait `actionPattern`, donc toute politique créée depuis l’UI devenait `*` | Champ d’action obligatoire ajouté ; aucun défaut implicite
| `deploy/base44/seed.sh` | Les politiques Vault, VNC, SSH et lecture d’enregistrement omettaient l’action | Actions explicites ; droits Vault séparés par action
| Documentation administrateur | Exemples de création sans action dans `access-policies.md`, `audit-and-compliance.md` et `approval-workflows.md` | Exemples corrigés avec les actions réellement vérifiées dans le code
| Tests d’intégration | Les helpers historiques `authzCreatePolicy` et `gatewayCreatePolicy` omettent l’action | Conservés pour éprouver la compatibilité legacy ; ils ne sont pas des clients de production

## Actions observées dans le code

Les vérifications Authorization de la version auditée utilisent notamment :

- Sessions : `session:create`, `session:read`, `session:terminate`, `session:approve`, `session:breakglass`, `session:clipboard`.
- Vault : `vault:account:list`, `vault:account:onboard`, `vault:account:rotate`, `vault:account:delete`, `vault:account:pin`, `vault:account:approval`, `vault:account:screen-profile`, `vault:account:kerberos`.
- Saisie de secrets : `secret:inject`, `secret:paste`.
- Enregistrements : `recording:session:read` ; rapprochement des injections : `audit:secret-injections:read`.
- Administration des politiques : `authz:policy:create`.

Les motifs de ressource restent indépendants : par exemple, `session:create` est vérifié sur `vault:account:<id>`, tandis que les actions d’administration du Vault sont vérifiées sur `vault:account-admin:<id>`. Une migration ne doit jamais déduire l’action à partir du seul nom de la ressource.

## Inventaire des données d’une installation

La Gateway ne fournit pas de route publique de lecture des politiques ; l’Admin UI ne peut donc pas afficher l’inventaire existant. Aucune base PostgreSQL de l’installation n’était connectée à l’environnement de cet audit. Les lignes réelles, rôles fédérés et propriétaires de droits restent donc **non vérifiés**. Ne pas extrapoler les exemples Base44 ou les tests aux données de production.

Un administrateur de base peut exécuter ces requêtes en lecture seule sur la base Authorization :

```sql
SELECT role, resource_pattern, action_pattern, effect, count(*) AS policy_count
FROM policies
WHERE action_pattern = '*'
GROUP BY role, resource_pattern, action_pattern, effect
ORDER BY role, resource_pattern, effect;

SELECT id, name, role, resource_pattern, action_pattern, effect, created_by, created_at
FROM policies
WHERE action_pattern = '*'
ORDER BY role, resource_pattern, created_at;
```

Conserver le résultat hors du dépôt, le rapprocher des propriétaires de rôles et des actions réellement utilisées, et faire approuver chaque réduction par le propriétaire métier du rôle.

## Stratégie de remédiation proposée

1. Exporter et classer les politiques `*` réelles ; distinguer les ressources exactes, les préfixes et les rôles transverses.
2. Pour chaque politique, établir les actions nécessaires à partir des appels Authorization, des workflows opérationnels et du propriétaire du rôle.
3. Ajouter les politiques à actions explicites sans retirer l’ancienne politique ; vérifier les parcours attendus et les refus hors périmètre.
4. Après validation métier et preuve d’équivalence, retirer le wildcard historique par une opération d’administration auditée et réversible. Ne pas automatiser cette étape dans une migration SQL globale.
5. Une décision ultérieure doit traiter séparément la fin de compatibilité de l’omission API : elle est contractuelle et ne doit pas être supprimée sans versionnement/plan de dépréciation.

**Aucune politique existante n’a été modifiée par cet audit.** Le changement courant réduit uniquement les créations nouvelles depuis les clients OpenBastion maintenus ; il ne prétend pas assainir les installations déjà déployées. Le seed Base44 ajoute les nouvelles politiques explicites de façon idempotente, mais ne supprime pas les anciens enregistrements wildcard déjà créés par une version antérieure : ils restent à inventorier et à traiter explicitement.
