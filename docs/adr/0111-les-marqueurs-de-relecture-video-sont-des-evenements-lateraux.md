# ADR-0111 — Les marqueurs de relecture vidéo sont des événements latéraux, indépendants des images

**Statut** Accepté · 15 novembre 2026

**Contexte**

ADR-0097 exige qu'une injection de secret soit auditée et laisse une référence durable dans l'enregistrement avant toute frappe vers la cible. Le parcours SSH peut placer un marqueur dans le Command Recorder. Le parcours VNC/RDP est différent : le Video Recorder stocke des segments d'images, des images partielles et des événements de presse-papiers dans une séquence continue (ADR-0070, ADR-0092, ADR-0096).

Insérer un marqueur d'injection comme une image ou un faux événement presse-papiers serait sémantiquement faux. L'ajouter à la séquence d'images perturberait les numéros de séquence et la compatibilité des lecteurs. Un nouveau message dans le flux WebSocket exigerait une évolution du protocole écran et de tous ses clients. Le journal d'audit, lui, possède déjà l'événement `session.secret_injection_started`, mais il ne constitue pas à lui seul une donnée de timeline servie avec la relecture vidéo.

**Décision proposée**

1. Ajouter une table append-only `video_recording_events`, séparée de `video_recording_segments` et sans clé étrangère vers `video_recordings`, afin qu’un marqueur puisse précéder la première image persistée. Elle conserve uniquement : identifiant d'événement idempotent, session, type d'événement, protocole, source, identifiant de compte et horodatage attribué par le Video Recorder.
2. Le premier type autorisé est `secret_injection_started`. La seule source admise dans cet incrément est `vault`. Aucun contenu, longueur, empreinte, extrait, ni donnée dérivée du secret n'est conservé.
3. L'événement n'a pas de numéro de séquence d'image. Il est ordonné par `occurred_at`, puis `event_id`. Il ne modifie ni `last_sequence`, ni les segments chiffrés, ni le protocole `openbastion.screen.v1`.
4. Ajouter `VideoRecording.RecordVideoEvent`, RPC unaire accessible exclusivement à l'identité mTLS `rdp-vnc-proxy`. Le proxy écrit le marqueur avant la frappe ; toute erreur ou absence d'accusé refuse l'injection.
5. Ajouter `VideoRecording.GetVideoEvents`, accessible exclusivement à `api-gateway`. La Gateway transmet l'utilisateur et les rôles issus du jeton vérifié. Le Video Recorder impose `recording:session:read` sur `recording:session:{id}` et écrit `recording.read` à l'audit avant de servir chaque page, y compris une page vide ; l'identité et les rôles viennent exclusivement de la Gateway authentifiée.
6. Exposer `GET /sessions/{id}/recording/video/events` avec curseur opaque, ordre stable (`occurred_at`, puis `event_id`) et limite strictement bornée. Réponses et erreurs sont `Cache-Control: no-store`. L'Admin UI pourra afficher ces événements comme marqueurs de timeline dans un incrément ultérieur.
7. Le marqueur est une preuve de tentative, pas de réussite. Le résultat reste dans les événements d'audit `session.secret_injected` ou `session.secret_injection_failed`. Les deux sources sont corrélées par session et horodatage.
8. La migration est additive. Les événements sont append-only ; aucune route ne permet de les modifier ou supprimer. Les règles de rétention suivent celles des enregistrements vidéo.

**Conséquences**

- (+) Un marqueur est durable avant la frappe et reste indépendant du flux image et de ses séquences.
- (+) Le Video Recorder reste l'autorité de lecture des marqueurs vidéo ; le journal d'audit demeure l'autorité de preuve et d'attribution.
- (+) L'ajout est compatible avec les anciens lecteurs d'images et le flux écran v1.
- (+) Le même contrat sera réutilisable par VNC puis RDP, sans ajouter de secret au control plane.
- (−) Une table, deux RPC et une route REST supplémentaires sont à maintenir.
- (−) Les marqueurs sont enregistrés mais ne sont pas visibles dans l'Admin UI tant que la timeline n'est pas raccordée.
- (−) L'identité de l'opérateur reste portée par la chaîne d'audit ; la table de timeline ne duplique pas l'acteur.
- (−) Un événement peut exister avant la première image persistée ; il indique une action tentée dans une session admise, pas qu'une image est nécessairement disponible.

**Alternatives envisagées**

- **Encoder le marqueur comme une image ou un événement presse-papiers** : rejeté, cela falsifie la sémantique des codecs et/ou des transferts et perturbe la séquence vidéo.
- **Ajouter un nouveau message au protocole écran v1** : rejeté, cela couple le marqueur d'audit à tous les clients WebSocket et aux versions de protocole.
- **Ne conserver le marqueur que dans Audit Service** : rejeté pour la timeline vidéo, car chaque lecteur devrait faire une jointure distincte et les événements ne seraient pas servis par le contrat de relecture vidéo.

## État d'implémentation — 15 novembre 2026

- **Backend livré (PR #206)** : migration append-only, RPC mTLS `RecordVideoEvent` / `GetVideoEvents`, contrôle `recording:session:read` et audit préalable de chaque page, route Gateway paginée et `no-store`.
- **Admin UI — incrément 2 en cours** : la relecture demande les événements séparément des segments d'images, affiche les tentatives d'injection Vault dans une timeline dédiée et synchronise le marqueur courant avec l'image relue. La lecture des événements est paginée (100 par page), plafonnée à 1 000 marqueurs côté navigateur et échoue indépendamment de la relecture vidéo.
- **Non livré** : les marqueurs ne seront produits par VNC/RDP qu'une fois le `SecretInputRecorder` branché au chemin d'injection de ces protocoles. L'intégration du `SecretTyper` VNC/RDP reste donc un incrément distinct d'ADR-0097 ; aucun marqueur ne doit être simulé côté UI.
