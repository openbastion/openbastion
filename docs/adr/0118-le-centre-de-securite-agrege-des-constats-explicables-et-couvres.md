# ADR-0118 — Le centre de sécurité agrège des constats explicables et mesure leur couverture

**Statut** `Proposé` · 2026-11-18 · soumis à validation du propriétaire du projet ; aucun code n'est autorisé par cet ADR seul.

**Contexte** — `web/admin-ui/src/features/security/SecurityCenter.tsx` existe déjà. Il interroge `GET /vault/accounts?page=1&pageSize=100` et calcule côté navigateur des constats concrets : clé SSH non épinglée, identité TLS RDP/VNC incomplète, rotation due, échecs de rotation et rotation planifiée échue. Il signale une pagination partielle et une erreur API sans les transformer en état sain. Ces règles sont également partagées avec `features/audit/posture.ts`.

Cette page n'est toutefois pas un centre de posture transverse : elle ne lit que le Vault. Elle ne possède ni contrat de constat normalisé, ni historique des évaluations, ni couverture par domaine. Les alertes de session relèvent de l'ADR-0117 ; les événements d'audit ne sont pas exposés par la Gateway ; aucune santé agrégée des composants n'est disponible. Le tableau de bord ne doit pas compter deux fois les mêmes signaux ni afficher des contrôles non évalués comme conformes.

**Décision**

1. Conserver le nom « Centre de sécurité » pour la supervision et distinguer cette page de `Paramètres → Sécurité`, qui décrit les mécanismes et leur configuration. Ne pas remplacer les signaux Vault déjà livrés.
2. Introduire un contrat de lecture `GET /security/posture` derrière la Gateway. La première version agrège des constats provenant de sources propriétaires, sans déplacer leur logique métier : Vault pour les comptes et rotations ; Audit Service pour l'intégrité ; ADR-0117 pour les alertes ; supervision des services pour leur disponibilité.
3. Un constat est un objet borné : `id`, `kind`, `source`, `resource_ref` opaque, `severity` (`info|low|medium|high|critical`), `status` (`open|acknowledged|resolved` uniquement si la source possède réellement ce cycle), `title_code`, `detected_at`, `last_seen_at`, `evidence_summary` expurgé et `remediation_code`. Aucun secret, commande brute, contenu clipboard, valeur de credential ou donnée personnelle superflue n'est exposé.
4. Chaque domaine fournit une couverture explicite : `available`, `partial`, `unavailable`, `not_configured`, `not_evaluated`, accompagnée de `evaluated_at`, `items_examined`, `items_total` quand ces nombres existent, et d'une raison stable. Une source en erreur ou partielle ne contribue jamais à un indicateur « sain ».
5. Le résumé expose les compteurs par sévérité et domaine, la couverture et `as_of`. Les compteurs sont calculés côté serveur sur le même instantané que la liste. Les constats Vault existants conservent leurs identifiants de compte et leur sémantique ; la migration ne doit pas créer de doublons avec les constats d'origine.
6. Les règles sont déterministes, versionnées et testées. Pas de score global opaque, pas de ML, pas de géolocalisation, pas de baseline comportementale et pas de recommandation générée sans signal source vérifiable dans cette version.
7. La lecture de posture exige une permission dédiée `security-posture:read` selon ADR-0114. Les accès aux ressources liées restent soumis à leurs propres permissions. La Gateway ne contourne jamais l'autorisation d'un service source.
8. La page SVG `docs/ui/reference-screens/openbastion-securite.svg` doit distinguer visuellement les capacités livrées des domaines planifiés ou non évalués. Les valeurs d'exemple sont explicitement fictives ; aucune métrique illustrative ne doit être présentée comme télémétrie réelle.

**Conséquences**

- (+) La page devient un point d'entrée cohérent sans devenir propriétaire des règles Vault, Audit ou Session.
- (+) L'opérateur distingue un résultat sain d'une absence de données, d'une panne et d'une couverture partielle.
- (+) Les constats sont explicables, traçables à une source et actionnables sans divulguer de secrets.
- (−) **Aucun gain n'est encore mesuré** : ce contrat est proposé et n'est pas implémenté.
- (−) Les données d'intégrité et de santé restent indisponibles tant que les ADR associés et leurs producteurs ne sont pas réalisés.
- (−) Le premier incrément ne fournit ni score de risque, ni conformité ISO/SOC2/NIS2, ni moteur de détection comportementale.

**Alternatives envisagées**

- **Déplacer toutes les règles dans un nouveau Security Service** : rejeté pour le premier incrément ; cela dupliquerait les responsabilités des services propriétaires et multiplierait les écritures/projections.
- **Calculer tous les indicateurs dans React** : rejeté ; la pagination, l'autorisation et la cohérence des compteurs ne peuvent pas être garanties par le navigateur.
- **Afficher un score 0–100** : rejeté tant que pondérations, couverture et calibration ne sont pas définies et validées.

**Critères de validation**

- Les tests prouvent que `partial`, `unavailable` et `not_evaluated` ne sont jamais rendus comme `healthy`.
- Les compteurs, la liste et `as_of` correspondent au même instantané ; les pages et filtres sont bornés.
- Les constats Vault sont équivalents à ceux de `findingsFor` pour les mêmes métadonnées et ne sont pas dupliqués.
- Les permissions de posture et les permissions des ressources liées sont testées indépendamment.
- Aucun champ secret ou non autorisé n'apparaît dans les réponses ni dans les journaux.
