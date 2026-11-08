# ADR-0085 — La bibliothèque VNC OpenBastion sépare RFB des contrôles PAM et de l'enregistrement

- **Statut** : Proposé
- **Date** : 2026-11-08
- **Décideurs** : Mainteneurs OpenBastion
- **Périmètre** : future bibliothèque Go publique `github.com/openbastion/vnc`, RDP/VNC Proxy, Session Broker et Video Recorder

## Contexte

Le parcours VNC d'OpenBastion a été validé de bout en bout avec TigerVNC 1.13.1. Le proxy termine la connexion vers la cible, sert un flux écran acquitté et s'intègre au Video Recorder. Les limites fonctionnelles restantes sont suivies dans `docs/security/known-limitations.md`. La logique RFB et son instrumentation sont aujourd'hui intégrées au proxy commun RDP/VNC ; une bibliothèque autonome permettrait de réutiliser et de tester le protocole indépendamment de la plateforme PAM.

VNC repose sur RFB et présente une sémantique distincte de RDP : négociation de version et de sécurité, pixel formats, encodings, framebuffer updates, événements clavier/souris et messages clipboard. Les extensions varient selon les implémentations ; certaines fonctions comme le transfert de fichiers ne sont pas universelles et ne doivent pas être présumées disponibles.

## Décision

1. **Créer une bibliothèque Go autonome** sous le module public `github.com/openbastion/vnc`, sous AGPL-3.0, avec implémentation originale, documentation, exemples et politique de compatibilité. Elle ne copiera pas de code propriétaire ni d'implémentation tierce.
2. **Séparer les couches** :
   - cœur RFB : transport, négociation de version et de sécurité, authentification explicitement admise, pixel formats, encodings, framebuffer updates, clavier, pointeur et messages standard ;
   - extensions : clipboard et extensions spécifiques, chacune identifiée par capacité, version et direction ;
   - session et instrumentation : événements d'entrée, mises à jour d'écran, flux, horodatage, limites et backpressure ;
   - ports PAM : Policy, Recorder, Auditor, vérificateur d'identité de cible et cycle de vie ;
   - adaptateur : intégration au proxy RDP/VNC et au Video Recorder.
3. **Ne pas introduire de dépendance directe** vers PostgreSQL, Redis, NATS, Kafka, OpenSearch, MinIO ou les microservices. Les ports publics seront injectés et resteront compatibles dans leur intention avec les bibliothèques SSH et RDP : décision de politique, acquittement d'enregistrement, clôture, audit et vérification de cible. Leurs types définitifs seront stabilisés après validation de l'API de chaque moteur ; aucune bibliothèque ne devra importer les autres pour obtenir ces contrats.
4. **Sécuriser la négociation RFB** :
   - versions et types de sécurité explicitement autorisés ; aucun choix permissif implicite ;
   - TLS avec validation de certificat et identité de cible obligatoires lorsque le profil TLS est utilisé ; pinning selon la configuration du compte ;
   - aucune désactivation de validation TLS en production ;
   - authentifications faibles, obsolètes ou non chiffrées refusées par défaut ; leur éventuel support devra être un profil nommé, explicitement activé et justifié par une ADR ;
   - tailles de messages, dimensions framebuffer, nombre de rectangles, encodings, délais et consommation mémoire strictement bornés.
5. **Contrôler les interactions** : chaque événement clavier, pointeur, clipboard ou extension est soumis à la politique correspondante ; l'événement de capture est acquitté avant sa transmission à la cible. Une panne du Policy Engine, du Recorder obligatoire ou de l'Auditor obligatoire bloque l'opération (fail-closed).
6. **Enregistrer le flux d'affichage** : les framebuffer updates sont horodatées et transformées vers un format de replay documenté et versionné. Les segments vidéo sont chiffrés et acquittés par le Video Recorder avant d'être servis, conformément à ADR-0070. Le proxy ne doit ni considérer un octet reçu comme durable avant acquittement, ni continuer à transmettre des mises à jour d'écran si la chaîne d'enregistrement obligatoire est indisponible.
7. **Définir explicitement les limites de capture** :
   - événements clavier/pointeur : capturer les événements reçus et ceux réellement transmis, avec horodatage ;
   - clipboard : capturer direction, taille et métadonnées bornées ; le contenu n'est conservé que si une politique explicite l'autorise et si le mécanisme de chiffrement/rétention le permet ;
   - transfert de fichiers : ne le déclarer disponible que pour une extension identifiée, implémentée et testée des deux côtés ; RFB standard ne garantit pas un protocole de transfert de fichiers universel ;
   - capture écran : conserver les mises à jour ou images nécessaires au replay, selon le format versionné ;
   - ne pas affirmer qu'une frappe correspond à une commande exécutée sur la cible.
8. **Gérer les secrets dans le seul chemin de données** : les identifiants de la cible sont obtenus par l'adaptateur autorisé et ne sont jamais renvoyés au navigateur, à l'UI, au control plane ou à l'audit. Les erreurs d'authentification sont génériques côté client.
9. **Préserver les invariants** : secrets hors control plane (ADR-0003), enregistrement obligatoire ou refus (ADR-0008), mTLS interne (ADR-0010), terminaison effective (ADR-0018), segments chiffrés acquittés (ADR-0070), proxy RDP/VNC Go pur et flux écran acquitté (ADR-0071). Aucune connexion directe à la cible ne doit être ajoutée au client.
10. **Migrer progressivement** le code VNC existant vers le module, en conservant les parcours déjà validés. Le proxy existant reste le point d'intégration ; aucune extraction ne doit dégrader les scénarios TigerVNC qui passent actuellement.
11. **Valider avant publication** : tests unitaires de chaque message RFB, fuzzing des parsers, tests de dimensions et tailles hostiles, pixel formats et encodings, backpressure, recorder indisponible, révocation, expiration, TLS et pinning, clipboard dans les deux directions, tests race et interopérabilité avec plusieurs implémentations VNC supportées.

## Contrat fonctionnel initial

| Domaine | Contrat |
|---|---|
| Protocole | RFB ; versions et extensions annoncées selon les capacités réelles |
| Authentification | profils nommés et explicitement autorisés ; aucune sécurité faible implicite |
| Identité cible | validation TLS/pinning obligatoire selon le profil |
| Affichage | framebuffer updates horodatées, acquittées et rejouables |
| Entrées | clavier/pointeur soumis à politique et enregistrés avant transmission |
| Clipboard | direction et métadonnées auditées ; contenu selon politique explicite |
| Transfert de fichiers | uniquement via extension identifiée et testée ; jamais supposé natif |
| Commandes | aucune sémantique de commande déduite du clavier |
| Runtime | maintien du parcours VNC existant ; aucune capacité nouvelle annoncée avant E2E |

## Conséquences

### (+) Résultats attendus, non encore mesurés

- Le moteur RFB pourra être réutilisé et testé sans dépendre du proxy ou du Video Recorder.
- La capture des interactions et de l'affichage sera découplée des transports et stockages de la plateforme.
- Les capacités RFB et extensions seront documentées et négociées explicitement.

Aucune extraction ni nouvelle capacité n'est mesurée par cet ADR. La validation TigerVNC existante reste celle du proxy actuel, et ne constitue pas une preuve de cette future bibliothèque autonome.

### (−) Limites et coûts

- Les extensions VNC sont hétérogènes ; la compatibilité devra être décrite par implémentation et version.
- RFB ne fournit pas une sémantique universelle de transfert de fichiers ni de commande distante.
- La capture vidéo/framebuffer peut être coûteuse ; les limites, la compression et la backpressure devront être mesurées.
- Le contenu clipboard peut être sensible ; sa capture doit être explicitement gouvernée, chiffrée et soumise à rétention.
- Une API publique stable et la migration progressive augmentent la charge de maintenance.
- Le format de replay devra être versionné et rétrocompatible ; le changement de format exigera une stratégie de migration.
- Cette décision ne prouve pas que toutes les extensions, authentifications ou encodings sont déjà pris en charge.

## Alternatives envisagées

- **Garder RFB exclusivement dans le proxy** : rejeté comme cible à long terme ; cela limite la réutilisation et mêle moteur et infrastructure.
- **Fusionner RDP et VNC dans une seule bibliothèque protocolaire** : rejeté ; leurs machines d'état et formats d'événements sont différents, même si le proxy peut les héberger ensemble.
- **Considérer toutes les extensions VNC comme standard** : rejeté ; leur présence varie selon les implémentations.
- **Capturer systématiquement le contenu clipboard** : rejeté ; le contenu peut être sensible et doit dépendre d'une politique explicite.
- **Déduire les commandes exécutées à partir des frappes clavier** : rejeté ; une saisie n'est pas une preuve d'exécution.

## Références

- [ADR-0003 — Les secrets ne traversent jamais le control plane](0003-les-secrets-ne-traversent-jamais-le-control-plane.md)
- [ADR-0008 — Enregistrer ou refuser](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md)
- [ADR-0010 — mTLS interne](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md)
- [ADR-0018 — Terminaison effective d'une session](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md)
- [ADR-0070 — Le Video Recorder acquitte les segments](0070-le-video-recorder-acquitte-des-segments-chiffres-avant-de-les-servir.md)
- [ADR-0071 — Proxy RDP/VNC Go pur](0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md)
- [Limites connues](../security/known-limitations.md)
