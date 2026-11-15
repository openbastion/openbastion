# ADR-0112 — Rapprocher les injections de secrets depuis la chaîne d'audit, sans la modifier

- **Statut :** Accepté
- **Date :** 15 novembre 2026
- **Contexte :** ADR-0097, SI-03 (répudiation / résultat cible ambigu)
- **Licence :** AGPL-3.0

## Contexte

Une injection Vault produit un événement préalable `session.secret_injection_started`, puis un événement terminal `session.secret_injected` ou `session.secret_injection_failed`, corrélés par un `injection_id` aléatoire de 128 bits. L'événement préalable et les marqueurs de relecture sont append-only. Si la cible a pu recevoir tout ou partie du secret mais que l'audit terminal n'a pas été acquitté, le proxy renvoie `outcome_unknown`. Une nouvelle injection automatique serait dangereuse : elle pourrait répéter une opération privilégiée.

Il faut donner à l'opérateur une lecture corrélée des preuves disponibles, y compris après redémarrage du proxy, sans réécrire l'historique ni prétendre prouver la réception effective du secret par la cible.

## Décision

1. L'Audit Service expose `GET /audit/v1/secret-injections`, accessible uniquement à l'identité mTLS `admin-cli`.
2. La réponse est une projection en lecture seule des événements présents dans la chaîne d'audit retenue. Les entrées sont regroupées par `injection_id` et classées :
   - `completed` : exactement un début et un résultat `session.secret_injected` cohérents ;
   - `failed` : exactement un début et un résultat `session.secret_injection_failed` cohérents ; cela décrit l’échec rapporté par le proxy et n’exclut pas une frappe partielle ;
   - `outcome_unknown` : résultat terminal absent, début absent, doublon ou incohérence des preuves.
3. La cohérence exige notamment le même `session_id`, `account_id`, `protocol` et `emitter`, ainsi qu'un ordre temporel début/résultat.
4. La projection ne retourne jamais de credential, de scope Vault, de preuve MFA ni de contenu de frappe. Elle retourne uniquement les identifiants d'événements et les métadonnées nécessaires à l'investigation.
5. La réponse indique `coverage=retained_audit_chain`, `archived_history_excluded`, `has_more` et un curseur `next_before` pour la pagination stable. Si des points de contrôle d'archives existent, la vue signale explicitement que ces archives ne sont pas incluses. Elle ne présente donc jamais cette vue partielle comme un inventaire historique exhaustif.
6. `completed` décrit la preuve d’audit (résultat terminal positif), pas une attestation indépendante que la cible a reçu l’intégralité du secret. `failed` ne garantit pas que la cible est inchangée, car une frappe partielle est possible. Tout résultat exige de ne pas relancer automatiquement l’injection ; `outcome_unknown` et `failed` imposent une vérification manuelle de la cible avant toute nouvelle action. Aucun retry automatique n'est autorisé.
7. L'endpoint ne crée aucun événement et ne modifie ni événements, ni marqueurs, ni checkpoints. La chaîne et ses ancres/checkpoints sont vérifiés avant la projection. Une panne de lecture ou une chaîne non vérifiable rend la vue indisponible (`503`), jamais partielle silencieusement.
8. La réponse est `Cache-Control: no-store`, bornée à 500 résultats par appel.

## Conséquences

- L'opérateur peut corréler les tentatives récentes après redémarrage d'un proxy.
- L'accès reste hors de l'API publique Gateway : seul le certificat d'administration `admin-cli` peut appeler cette route interne.
- Les événements archivés ne sont pas encore relus par cette première version. Une évolution devra ajouter une lecture des archives avec vérification du SHA-256 référencé par les checkpoints avant de pouvoir annoncer une couverture historique complète.
- Les marqueurs de Command Recorder et Video Recorder restent des preuves latérales ; cette projection ne les confond pas avec le résultat terminal d'audit.
- L'interface opérateur et la pagination par curseur restent des incréments ultérieurs.

## Validation exigée

- Tests de classification succès, échec, absence de résultat, événement orphelin, doublon et incohérence d'émetteur.
- Tests de non-mutation de la chaîne et de refus fermé lorsque les checkpoints ne sont pas lisibles.
- Tests HTTP de méthode, borne de limite, `no-store` et autorisation mTLS `admin-cli` uniquement.
- Tests d'intégration sur PostgreSQL réel à ajouter avant clôture complète de SI-03.
