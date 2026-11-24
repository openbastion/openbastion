# ADR-0117 — Les alertes de session sont durables, autorisées et acquittées dans la chaîne d'audit

**Statut** `Accepté` · 2026-11-23 · contrat de référence fonctionnel et technique de la file d’alertes de session.

**Contexte** — L'Admin UI possède un onglet « Alertes » mais aucun contrat public ne permet aujourd'hui de l'alimenter : ni file d'alertes de session, ni sévérité, ni compteur non traité, ni acquittement. L'interface affiche donc honnêtement « API requise ».

Les mécanismes existants ne couvrent pas ce besoin :

- ADR-0045 définit l'envoi de certaines alertes d'audit vers un webhook signé. Il s'agit d'une notification sortante, pas d'une file opérateur consultable et acquittable.
- ADR-0057 rend durable `alert_outbox`, la file de livraison webhook. Cette table ne représente pas le cycle de traitement d'une alerte de session.
- La chaîne d'audit (ADR-0025 à ADR-0028) est la preuve immuable des événements, mais elle n'est pas un modèle de travail permettant de compter les alertes non traitées.
- `GET /sessions` ne fournit que les demandes `pending_approval` (ADR-0023). Il n'existe pas de flux global de sessions actives, et les alertes ne doivent pas être déduites d'une liste de sessions que l'appelant n'est pas autorisé à lire.

Il faut donc séparer trois choses : l'événement source signé, l'occurrence d'alerte créée par une règle, et le traitement humain de cette occurrence. La projection d'alerte peut évoluer ; la chaîne d'audit, elle, reste la preuve du fait détecté et de l'action de l'opérateur.

**Décision**

1. **Le composant propriétaire est l'Audit Service.** Il possède le catalogue de règles, la détection, le stockage des occurrences, les lectures, le résumé des compteurs et l'acquittement. Aucun nouveau microservice n'est ajouté. Le Session Broker et les proxys continuent d'émettre leurs événements selon leurs contrats actuels ; ils ne créent pas directement des lignes d'alerte et ne choisissent jamais leur sévérité.

2. **La détection est déterministe, versionnée et fondée sur les événements de la chaîne.** Une règle est un triplet déclaré dans le code : `rule_id`, `rule_version`, couples autorisés `(emitter mTLS, action)`, avec ses prédicats sur `resource_type`, `success` et les champs structurés bornés. Le nom d'émetteur vient du certificat mTLS (ADR-0027), jamais du corps de la requête. Un événement refusé par la chaîne, un émetteur non déclaré, une action inconnue ou un champ hors contrat ne produit aucune alerte.

   Le premier catalogue activable est limité aux signaux déjà émis et vérifiés :
   - `session.breakglass_requested` par `session-broker` : sévérité `high` ;
   - `session.secret_injection_failed` par le proxy qui a réellement émis l'événement : sévérité `high` ;
   - `session.read` avec `success=false` : pas d'alerte unitaire ; une règle de rafale pourra être activée uniquement quand son seuil, sa fenêtre et son agrégat seront couverts par des tests de concurrence et de rejeu.

   Les règles `host_key_mismatch`, `tls_certificate_mismatch`, `target_auth_failed`, `recording_lost` et `recording_unavailable` sont des candidates de la première évolution, mais restent désactivées tant que le producteur concerné n'émet pas l'action avec un couple émetteur/action testé. L'ADR ne permet pas de simuler un signal absent. Chaque règle activée fixe sa sévérité ; le client ne peut jamais la choisir ou la diminuer.

3. **Les niveaux de sévérité sont stables :** `info`, `low`, `medium`, `high`, `critical`. Ils ne sont ni des statuts ni des priorités modifiables par l'opérateur. La première version n'introduit ni score numérique de risque, ni apprentissage automatique, ni règle modifiable depuis l'UI. Les anomalies de pays, d'horaire, de commande inhabituelle et de volume de transfert restent hors périmètre tant que les signaux et baselines nécessaires ne sont pas spécifiés.

4. **Une occurrence est un enregistrement opérationnel distinct de l'événement source.** La table PostgreSQL `session_alerts` contient au minimum :
   - `id` (identifiant opaque), `rule_id`, `rule_version`, `source_event_id` ;
   - `session_id`, `severity`, `status`, `summary` ;
   - `detected_at`, `created_at`, `revision` ;
   - `acknowledged_at`, `acknowledged_by`, `acknowledgement_event_id` (nuls tant que l'alerte n'est pas acquittée).

   `status` vaut uniquement `unacknowledged` ou `acknowledged` dans cette version. Une occurrence est unique par `(source_event_id, rule_id)` ; la reprise d'un traitement ne crée pas de doublon. `severity` et `status` ont des contraintes `CHECK`, `summary` est borné à 512 octets, `revision` commence à 1, et une contrainte impose que les trois champs d'acquittement soient tous nuls ou tous renseignés. Les index couvrent `(status, detected_at DESC, id)` et `(severity, status, detected_at DESC)`. Les détails sont bornés, structurés et expurgés de tout secret, valeur de credential, contenu de presse-papiers ou ligne de commande brute. L'alerte référence la session, mais ne copie pas ses métadonnées privilégiées.

5. **La détection ne peut pas perdre un événement entre la chaîne et la projection.** L'ajout d'un événement source et l'ajout de son identifiant dans `session_alert_detection_outbox` sont atomiques dans le magasin PostgreSQL de l'Audit Service. Un worker reprend cette outbox au redémarrage, relit et vérifie l'événement source, évalue les règles, puis crée l'occurrence et son événement `session.alert.detected` dans une transaction. La contrainte unique `(source_event_id, rule_id)` rend le traitement idempotent. La file de détection est distincte de `alert_outbox` (ADR-0057), qui reste exclusivement la file de livraison webhook.

   La table `session_alert_detection_outbox` contient l'identifiant de l'événement source, la version du catalogue à appliquer, le nombre de tentatives, la prochaine échéance et un code d'erreur interne borné ; elle ne copie pas le corps de l'événement. La version du catalogue est conservée jusqu'au traitement, afin qu'un déploiement ne réinterprète pas silencieusement une file ancienne avec de nouvelles règles. La file a une limite initiale de 4 096 éléments en attente. Si elle atteint cette limite, l'Audit Service refuse l'ajout d'un événement source qui doit être évalué, avant le commit de cet événement, avec un code d'erreur stable. L'action PAM qui dépend de cet audit échoue alors fermée ; aucune alerte n'est silencieusement abandonnée. Le mode mémoire reste réservé aux tests et au développement : le résumé expose `durable=false` et la readiness de production doit rester négative ; il ne constitue pas un mode de production conforme à cet ADR.

6. **Les routes REST publiques passent par l'API Gateway.** Elles sont exposées en HTTP/JSON ; les appels internes à l'Audit Service restent sous mTLS et suivent ADR-0050.

   - `GET /session-alerts` : liste paginée, triée par `detected_at DESC` puis `id`, filtres optionnels `status`, `severity`, `session_id`, `since`, `until`, `cursor` et `limit` (défaut 50, maximum 100). Les bornes de dates sont explicites et les curseurs opaques.
   - `GET /session-alerts/summary` : renvoie un instantané cohérent `{unacknowledged_count, by_severity, as_of, durable}`. `by_severity` compte les occurrences non acquittées par niveau. `unacknowledged_count` est la somme de ces niveaux et compte exactement les occurrences visibles dans le même instantané ; il ne s'agit pas du nombre d'événements webhook en attente.
   - `GET /session-alerts/{id}` : détail borné d'une occurrence.
   - `POST /session-alerts/{id}/acknowledge` : acquitte une occurrence ouverte. Le corps porte `expected_revision` pour éviter qu'une action basée sur une vue obsolète écrase une évolution concurrente. Le serveur détermine l'acteur et l'heure ; le client ne les fournit jamais.

   Exemple de résumé :
   ```json
   {
     "unacknowledged_count": 3,
     "by_severity": {"info": 0, "low": 0, "medium": 1, "high": 2, "critical": 0},
     "as_of": "2026-11-17T12:00:00Z",
     "durable": true
   }
   ```

   Réponses attendues : `200` pour lecture et acquittement réussi ou déjà acquitté (idempotence), `400` pour filtre invalide, `401` sans authentification, `403` si l'action est interdite, `404` pour une occurrence inexistante ou non visible, `409` pour une révision périmée sur une occurrence encore ouverte, `503` si l'autorisation, la chaîne ou le magasin requis est indisponible. Les codes d'erreur sont stables et ne révèlent pas les détails internes.

7. **L'accès à la file est une permission distincte de la lecture d'une session.** `session-alerts:read` autorise la lecture de la file, des occurrences et du résumé ; `session-alerts:acknowledge` autorise leur acquittement. Les décisions utilisent les deux dimensions d'ADR-0114 : ressource `session-alerts:all` pour la collection ou `session-alerts:<id>` pour une occurrence, et action exacte correspondante. Un rôle opérateur peut recevoir `resource_pattern=session-alerts:*` avec `action_pattern=session-alerts:read`, sans recevoir l'action d'acquittement. Le compteur ne révèle que les alertes visibles par le principal appelant. Voir ou acquitter une alerte ne confère pas `session.read` : ouvrir le détail de la session reste soumis à ADR-0019 et à sa politique propre.

8. **L'acquittement est un acte audité, pas une simple mise à jour SQL.** Dans une même transaction du magasin de l'Audit Service, l'opération : vérifie `expected_revision`, écrit `session.alert.acknowledged` dans la chaîne, met à jour `status`, `acknowledged_at`, `acknowledged_by`, `acknowledgement_event_id` et incrémente `revision`. L'acteur provient de l'identité authentifiée ; l'émetteur est le certificat mTLS de l'Audit Service. L'événement d'audit contient l'identifiant d'alerte, l'identifiant de session, la règle, la sévérité et la révision, jamais un commentaire libre ni un secret.

   Si l'écriture de la chaîne ou la transaction échoue, l'acquittement n'est pas confirmé et l'alerte reste non acquittée ; l'append suit l'ordre et les garanties d'ancrage déjà définis par ADR-0028. Un acquittement répété retourne l'état existant sans produire un second événement. En cas de course, le premier commit gagne ; une révision périmée sur une alerte encore ouverte reçoit `409`.

9. **Le cycle de vie est volontairement court.** Une alerte est une occurrence, pas un ticket de workflow. Cette version permet uniquement `unacknowledged → acknowledged`. Elle n'ajoute ni résolution, ni fermeture, ni réouverture, ni assignation, ni commentaire, ni acquittement groupé. Un nouveau fait détecté produit une nouvelle occurrence, pas la réouverture silencieuse d'une ancienne. La conservation des occurrences et des événements de traitement suit la politique de rétention et d'archivage de l'Audit Service ; aucune purge indépendante des preuves n'est autorisée.

10. **Le webhook reste hors du premier incrément.** La création et l'acquittement d'une alerte ne déclenchent pas automatiquement de webhook. Une évolution ultérieure pourra ajouter explicitement le couple `(audit-service, session.alert.detected)` à la liste autorisée d'ADR-0045 et utiliser `alert_outbox` (ADR-0057). La livraison ou l'échec d'un webhook ne changera jamais `status` et n'acquittera jamais l'alerte. L'Admin UI lit la file opérateur, pas `alert_outbox`.

**Conséquences**

- (+) Une occurrence est reliée à un événement source vérifiable, à une règle versionnée et à une sévérité décidée côté serveur.
- (+) La file de détection survit au redémarrage en mode PostgreSQL ; la contrainte d'unicité permet la reprise sans doublon.
- (+) Le compteur non traité est une requête de données métier sur les occurrences visibles, pas un comptage de notifications webhook ni une estimation côté navigateur.
- (+) Un acquittement ne peut être annoncé sans preuve correspondante dans la chaîne d'audit ; acteur, heure, ressource et règle sont attribués côté serveur.
- (+) Les permissions d'alerte restent distinctes de `session.read`, ce qui permet une supervision SOC sans ouvrir implicitement l'accès aux détails de session.
- (−) **Aucun gain de performance n'est encore mesuré**. Les seuils, la capacité de l'outbox et le coût des requêtes de résumé devront être mesurés avant production.
- (−) Le premier catalogue est volontairement petit. Les signaux géographiques, horaires, comportementaux, commandes inhabituelles, transferts massifs et corrélations multi-sessions ne sont pas disponibles sans nouvelles données, règles et tests.
- (−) Le mode mémoire ne garantit ni la reprise ni la persistance ; une installation de production doit utiliser PostgreSQL pour activer le contrat durable.
- (−) La liste est globale pour les principaux autorisés par `session-alerts:read`, mais elle ne donne pas automatiquement le droit de lire les sessions associées. L'UI doit traiter séparément les refus de `session.read`.
- (−) Pas de workflow d'assignation, de commentaire, de résolution ou de réouverture ; pas de ML ; pas de notification garantie par webhook. Aucune notification webhook n'est activée dans ce premier incrément.
- (−) Une saturation de la file de détection peut bloquer une opération PAM qui exige l'écriture de l'événement source. C'est un choix fail-closed qui nécessite des métriques et une alerte d'exploitation dédiées.

**Alternatives envisagées**

- **Réutiliser `alert_outbox` comme file d'alertes opérateur** : rejeté, car elle suit les tentatives de livraison webhook et supprime les éléments livrés ou abandonnés ; elle ne porte ni statut de traitement, ni sévérité, ni permission de lecture.
- **Créer un Session Alert Service séparé** : rejeté pour cette première version ; l'Audit Service possède déjà la chaîne, les événements vérifiés et les frontières d'émetteurs. Un service séparé multiplierait les identités, transports et points de cohérence sans nécessité démontrée.
- **Déduire les alertes depuis les sessions du Broker** : rejeté, car le Broker ne voit pas tous les événements des proxys/recorders et sa liste de sessions n'est pas un flux global. La chaîne d'audit est le point commun vérifiable.
- **Compter les événements côté Admin UI** : rejeté, car le navigateur ne dispose pas d'une source complète, ferait varier le compteur selon les pages chargées et pourrait compter des sessions non autorisées.
- **Acquitter uniquement par un champ SQL** : rejeté, car l'action opérateur serait modifiable sans preuve append-only. L'événement d'acquittement doit être écrit à l'audit avant confirmation.
- **Ajouter `resolved`, `dismissed`, assignation et commentaires dès la première version** : rejeté, car ces états constituent un workflow de traitement distinct, avec des règles de clôture et de responsabilité qui ne sont pas encore définies.
- **Activer un moteur ML ou des règles configurables dans l'UI** : rejeté, car les baselines, les données d'entraînement, les explications, la gouvernance et les permissions de configuration ne sont pas définies.

**Critères de validation**

- Une paire `(emitter, action)` non déclarée, un événement source refusé ou un événement dont la chaîne ne se vérifie pas ne produit aucune alerte.
- Chaque règle activée a un test positif, un test négatif, un test de mauvaise sévérité et un test de rejeu ; un `source_event_id` rejoué ne crée jamais deux occurrences.
- Un crash entre l'écriture source et le traitement worker reprend l'outbox et crée exactement une occurrence ; un crash pendant la création ne laisse ni ligne sans événement `session.alert.detected`, ni événement sans ligne.
- Une outbox pleine refuse l'événement source dans la même transaction ; aucun événement source accepté ne perd silencieusement son évaluation.
- Le résumé et la liste sont cohérents sur un même instantané, bornés par pagination, et ne comptent aucune alerte non visible par `session-alerts:read`.
- Un principal sans `session-alerts:read` ne lit ni liste, ni détail, ni compteur ; un principal sans `session-alerts:acknowledge` ne peut pas acquitter ; aucun de ces droits ne confère `session.read`.
- Deux acquittements concurrents ne produisent qu'un seul événement `session.alert.acknowledged`. Un retry retourne le même état sans second événement ; une révision périmée retourne `409`.
- Une panne de la chaîne, de l'ancre ou de PostgreSQL ne laisse pas un acquittement confirmé sans événement audité.
- Les tests PostgreSQL couvrent transactions, contraintes uniques, reprise après redémarrage et isolation des rôles ; les tests HTTP couvrent les codes stables, les filtres, la pagination, le compteur et les refus d'autorisation.
- Aucune notification webhook n'est envoyée dans la première version ; les tests d'ADR-0045 et ADR-0057 restent inchangés et verts.


**État d’implémentation — 24 novembre 2026** — Le backend de détection est livré (`feat/session-alert-detection`) : migration PostgreSQL, catalogue v1, insertion atomique de l’outbox, worker de détection, projection idempotente et événement `session.alert.detected` dans la chaîne. L’incrément `feat/session-alert-api` ajoute les lectures internes mTLS de liste paginée, résumé et détail, réservées à `api-gateway`. Les routes publiques Gateway, les permissions ABAC, l’acquittement audité et l’intégration Admin UI restent à réaliser ; cet état ne modifie pas la décision ci-dessus.
