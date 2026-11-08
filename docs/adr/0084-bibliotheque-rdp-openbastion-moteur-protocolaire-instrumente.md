# ADR-0084 — La bibliothèque RDP OpenBastion sépare le moteur protocolaire des contrôles PAM

- **Statut** : Proposé
- **Date** : 2026-11-08
- **Décideurs** : Mainteneurs OpenBastion
- **Périmètre** : future bibliothèque Go publique `github.com/openbastion/rdp`, RDP Proxy, Session Broker et Video Recorder

## Contexte

OpenBastion développe un moteur RDP original en Go pur. Le socle couvre déjà une partie de la négociation X.224/HYBRID, TLS épinglé, CredSSP/NTLMv2, MCS/GCC, licensing partiel, capacités et décodage graphique partiel. Toutefois, l'état du dépôt au 2026-11-08 indique que le runtime RDP demeure désactivé et que l'interopérabilité réelle avec Windows Server/RDS n'est pas démontrée. La présence de code ou de décodeurs ne vaut pas activation opérationnelle.

Le moteur doit pouvoir être réutilisé indépendamment du RDP Proxy, sans perdre les contrôles PAM : identité de cible, politique, enregistrement obligatoire, audit, révocation et absence d'exposition des credentials. RDP possède des concepts qui lui sont propres (NLA/CredSSP, licensing, canaux virtuels, redirections, ordres graphiques et codecs) ; il serait dangereux de les masquer derrière une abstraction générique qui prétendrait avoir la même sémantique que SSH ou VNC.

## Décision

1. **Créer une bibliothèque Go autonome** sous le module public `github.com/openbastion/rdp`, sous AGPL-3.0, avec une implémentation originale, sa documentation, ses exemples et sa politique de compatibilité. Aucun code propriétaire ni code tiers ne sera copié. Les références étudiées dans ADR-0081 servent à comparer des concepts et des résultats de tests uniquement.
2. **Séparer le moteur RDP des adaptateurs PAM** :
   - moteur protocolaire : transport, X.224, négociation de sécurité, TLS, NLA/CredSSP, MCS/GCC, licensing, capabilities, slow/fast path, canaux virtuels et décodage graphique ;
   - session : cycle de vie, clavier, souris, redirections autorisées et événements protocole ;
   - instrumentation : capture des entrées, événements de canaux, données graphiques décodées et métadonnées ;
   - ports de sécurité : politique, Recorder, Auditor, vérificateur TLS/identité de cible et terminaison ;
   - adaptateur : RDP Proxy et intégration aux services OpenBastion.
3. **Exposer des contrats injectables**, sans dépendance directe à PostgreSQL, Redis, NATS, Kafka, OpenSearch, MinIO, Envoy ou aux microservices. Les contrats structurants seront équivalents dans leur intention à ceux de l'ADR-0083 : évaluation de politique, préparation/acquittement d'enregistrement, clôture de résultat, émission d'événement d'audit, vérification de la cible et cycle de vie annulable. Les types définitifs seront validés sur les parcours réels avant stabilisation de l'API publique.
4. **Rendre la sécurité de la négociation non contournable** :
   - validation TLS et identité de cible obligatoires, avec pinning conforme à ADR-0069/ADR-0071 ;
   - NLA/CredSSP et méthodes de sécurité explicitement configurées ; aucun downgrade silencieux ;
   - aucune désactivation de vérification de certificat, aucun `InsecureSkipVerify` dans le chemin de production ;
   - algorithmes obsolètes et mécanismes de compatibilité désactivés par défaut, avec décision explicite et traçable si un profil de compatibilité est ultérieurement nécessaire ;
   - authentification et transmission des credentials uniquement après vérification de la cible.
5. **Appliquer les contrôles avant chaque action significative** : politique de session avant connexion ; acquittement du début de session avant établissement du canal utilisateur ; pour chaque événement d'entrée (clavier, souris, presse-papiers ou redirection), évaluation des règles pertinentes et enregistrement préalable avant transfert vers la cible ; les événements de sortie et segments graphiques sont horodatés, associés à la session et acquittés par le mécanisme d'enregistrement avant d'être servis/rejoués selon ADR-0070. Une panne obligatoire bloque l'action et termine proprement la session.
6. **Définir une capture RDP fidèle à ses capacités** :
   - événements d'entrée clavier/souris avec horodatage et distinction entre entrée reçue et entrée transmise ;
   - données d'affichage capturées à un niveau décodé et versionné, ou image/segment vidéo produit par le Video Recorder ; le format exact doit être déterministe et documenté ;
   - événements de canaux virtuels (clipboard, drive, printer, audio, smart card, port/serial) uniquement lorsqu'ils sont implémentés, activés et autorisés ;
   - événements de redirection et transferts avec direction, compteurs, résultat et métadonnées bornées ;
   - aucune capture d'un canal non pris en charge ou non autorisé ; aucune affirmation de visibilité fichier par fichier si le protocole ou l'implémentation ne la fournit pas.
7. **Ne pas inventer de notion de commande** : RDP n'expose pas au proxy une liste fiable de commandes exécutées dans la session Windows. La bibliothèque capture des événements d'interaction, des canaux et des flux graphiques ; l'analyse de commandes Windows nécessite un agent ou une source d'audit sur la cible, hors du périmètre de cette bibliothèque.
8. **Gérer les credentials sans fuite** : les secrets ne sont jamais renvoyés au client, à l'UI, au control plane ou aux événements ; leur obtention se fait par l'adaptateur de données autorisé, puis leur utilisation est confinée au handshake avec la cible reconnue. Les erreurs externes sont génériques et ne révèlent ni secret ni détail d'authentification.
9. **Préserver les invariants** : ADR-0003, ADR-0008, ADR-0010, ADR-0018, ADR-0069, ADR-0070 et ADR-0071. Le runtime reste désactivé tant que les tests d'interopérabilité RDP réels, les scénarios négatifs et les contrôles d'enregistrement ne sont pas verts.
10. **Migrer progressivement** le code RDP existant vers le module, sans réécriture globale. Aucun composant ne sera déclaré disponible avant activation dans le runtime et preuve par tests avec des cibles Windows Server/RDS réelles ou des environnements de test représentatifs explicitement documentés.
11. **Valider avant publication** : corpus de négociation et de paquets malformés, fuzzing des parsers, limites de taille/temps/profondeur, tests race, tests TLS/pinning/downgrade, CredSSP/NLA, canaux virtuels, codecs, backpressure, coupure de session, recorder indisponible, replay et interopérabilité avec plusieurs versions supportées de Windows Server/RDS.

## Contrat fonctionnel initial

| Domaine | Contrat |
|---|---|
| Protocole | RDP Go pur ; capacités annoncées limitées aux fonctions réellement implémentées |
| Sécurité | TLS et identité cible vérifiés ; NLA/CredSSP selon profils explicitement admis |
| Entrées | clavier/souris capturés et contrôlés avant transmission |
| Sorties | affichage décodé/segmenté, horodaté et enregistré avant service |
| Canaux virtuels | allow-list par canal et direction ; aucun canal implicite |
| Redirections | refus par défaut, limites et consentement de politique |
| Commandes Windows | aucune capture sémantique garantie par le protocole RDP |
| Credentials | chemin de données uniquement, jamais exposés au control plane |
| Runtime | désactivé tant que l'interopérabilité et l'enregistrement ne sont pas démontrés |

## Conséquences

### (+) Résultats attendus, non encore mesurés

- Le moteur RDP pourra évoluer et être testé indépendamment du proxy et du Video Recorder.
- Les événements de protocole seront instrumentables sans coupler le code aux services de stockage ou d'audit.
- La couverture RDP pourra être décrite par capacités effectivement testées, plutôt que par présence de décodeurs.

Aucune extraction, activation ni interopérabilité nouvelle n'est mesurée par cet ADR.

### (−) Limites et coûts

- RDP est un protocole complexe ; la couverture des codecs, licensing, NLA, redirections et canaux virtuels demandera une matrice de compatibilité explicite.
- L'API devra exposer des capacités hétérogènes sans promettre une parité avec SSH ou VNC.
- La capture vidéo/graphique peut consommer CPU, mémoire et stockage ; backpressure et limites de ressources sont obligatoires.
- L'inspection de commandes Windows n'est pas fournie par RDP seul.
- Le runtime demeure désactivé jusqu'à preuve d'interopérabilité et de sécurité ; cette bibliothèque ne change pas ce statut.
- Le découplage et le versionnement d'un module public augmentent le coût de maintenance.
- Les formats d'enregistrement décodés devront être versionnés pour préserver la compatibilité de replay.

## Alternatives envisagées

- **Importer directement gopher-rdp ou gordp** : rejeté comme décision par défaut ; la couverture protocolaire n'établit pas la conformité aux invariants PAM. Toute dépendance future exigera audit de licence, provenance, sécurité et ADR.
- **Faire dépendre le moteur des microservices** : rejeté ; la bibliothèque ne serait plus autonome.
- **Réutiliser une abstraction générique SSH/RDP/VNC pour les messages protocole** : rejeté ; les événements et capacités doivent conserver leur sémantique propre.
- **Activer le runtime sur la seule présence du code** : rejeté ; seule une interopérabilité réelle et une chaîne d'enregistrement validée l'autorisent.
- **Promettre la capture des commandes Windows** : rejeté ; cette information n'est pas exposée de manière fiable par RDP.

## Références

- [ADR-0003 — Les secrets ne traversent jamais le control plane](0003-les-secrets-ne-traversent-jamais-le-control-plane.md)
- [ADR-0008 — Enregistrer ou refuser](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md)
- [ADR-0010 — mTLS interne](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md)
- [ADR-0018 — Terminaison effective d'une session](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md)
- [ADR-0069 — Le proxy RDP vérifie la cible](0069-le-proxy-rdp-verifie-la-cible-et-refuse-les-sessions-non-enregistrees.md)
- [ADR-0070 — Le Video Recorder acquitte des segments](0070-le-video-recorder-acquitte-des-segments-chiffres-avant-de-les-servir.md)
- [ADR-0071 — Proxy RDP/VNC Go pur](0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md)
- [ADR-0081 — Veille RDP externe](0081-veille-rdp-externe-et-integration-selective.md)
- [Limites connues](../security/known-limitations.md)
