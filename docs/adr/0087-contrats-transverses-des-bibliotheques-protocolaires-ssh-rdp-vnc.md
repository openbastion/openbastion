# ADR-0087 — Les bibliothèques SSH, RDP et VNC partagent des contrats PAM sans partager leurs moteurs protocolaires

- **Statut** : Proposé
- **Date** : 2026-11-08
- **Décideurs** : Mainteneurs OpenBastion
- **Périmètre** : futures bibliothèques Go `github.com/openbastion/ssh`, `github.com/openbastion/rdp`, `github.com/openbastion/vnc` et leurs adaptateurs dans OpenBastion

## Contexte

Les ADR-0083, ADR-0084 et ADR-0085 définissent trois bibliothèques protocolaires autonomes. Elles ont des besoins transverses identiques du point de vue PAM : décider si une opération est permise, faire acquitter son enregistrement avant un effet externe, produire des événements d'audit, vérifier l'identité de la cible et arrêter une session lorsqu'elle est annulée, expirée ou révoquée.

Ces besoins communs ne rendent pas les protocoles interchangeables. SSH expose des channels, des requêtes exec, des PTY et des subsystems ; RDP expose notamment des entrées, des canaux virtuels et des mises à jour graphiques ; VNC expose des messages RFB, des événements clavier/pointeur et des mises à jour framebuffer. Une abstraction qui prétendrait uniformiser ces opérations ferait perdre de l'information et pourrait annoncer des contrôles qui ne sont pas applicables à un protocole donné.

Les ADR précédents demandent des ports injectables, mais laissent encore à préciser leur sémantique commune, leur ordre d'appel, leurs erreurs et les garanties attendues des adaptateurs. Sans contrat normatif, les trois bibliothèques risquent de diverger sur le fail-closed, les acquittements, la révocation et la forme des événements.

## Décision

### 1. Définir un contrat commun de comportement, pas un moteur commun

Les trois bibliothèques respecteront le même **contrat PAM normatif** décrit dans cet ADR. Chaque module exposera des interfaces Go adaptées à son protocole et pourra employer ses propres types. Les adaptateurs OpenBastion traduiront les contrats vers les services de la plateforme.

Il n'est **pas** créé de module Go partagé tel que `github.com/openbastion/contracts` à ce stade. Les bibliothèques ne s'importent pas mutuellement et ne dépendent pas d'un package transversal pour leurs types publics. Cette décision évite de coupler leurs cycles de version et de figer prématurément une abstraction générique. Une éventuelle extraction ultérieure d'un package commun exigera une ADR fondée sur des usages réels et une analyse de compatibilité.

### 2. Contrat Policy — décider avant l'opération

Chaque bibliothèque expose un port de politique injectable dont la sémantique est :

- recevoir un contexte annulable et une requête typée contenant au minimum l'identité de session, le principal, la cible, le protocole, l'action demandée et les attributs propres au protocole ;
- retourner une décision explicite `Allow` ou `Deny`, accompagnée d'un code de motif stable et, si nécessaire, de contraintes bornées ;
- ne jamais interpréter l'absence de réponse, une réponse inconnue, un timeout ou une erreur comme une autorisation ;
- évaluer de nouveau la politique pour chaque opération significative lorsque le protocole permet de l'intercepter (commande exec, ouverture de subsystem, transfert, entrée clavier/pointeur, clipboard, canal virtuel ou redirection).

Une décision positive ne dispense jamais de l'acquittement du Recorder et de l'Auditor lorsque ceux-ci sont obligatoires. Les attributs spécifiques restent typés par bibliothèque ; aucun contrat ne suppose que RDP ou VNC possède une sémantique de commande SSH.

### 3. Contrat Recorder — acquittement avant effet externe

Chaque bibliothèque fournit un port d'enregistrement avec deux phases conceptuelles :

1. **Prepare** : soumettre l'événement préalable et obtenir un reçu opaque attestant que l'enregistreur a accepté durablement l'événement ou réservé la capacité requise selon son contrat ;
2. **Complete** : clôturer le reçu avec le résultat de l'opération, son statut et des compteurs/métadonnées bornés.

Règles obligatoires :

- aucune opération contrôlée ne produit d'effet externe avant le succès de `Prepare` ;
- le reçu est lié à la session, à l'événement et à l'opération ; il ne contient aucun secret d'authentification ;
- `Complete` est appelé pour les succès, refus après préparation, échecs et annulations, dans la mesure où le contexte de clôture et le Recorder le permettent ;
- les implémentations définissent un contexte de clôture borné indépendant de l'annulation de la session, afin de tenter la finalisation sans bloquer indéfiniment ;
- une erreur ou un timeout de préparation refuse l'opération (fail-closed) ; une erreur de clôture est remontée comme défaut d'intégrité d'enregistrement et déclenche le traitement de dégradation prévu par la plateforme ;
- les données volumineuses sont transmises en segments bornés avec backpressure ; un octet reçu ou mis en mémoire n'est pas réputé durable avant l'acquittement correspondant.

Le contrat ne prétend pas qu'un simple appel réseau garantit à lui seul une écriture physique sur disque : le Recorder doit documenter précisément le niveau de durabilité représenté par son reçu.

### 4. Contrat Auditor — événements structurés, signature centralisée

Chaque bibliothèque expose un port d'audit qui accepte des événements structurés, versionnés, bornés et associés à une session. Il couvre au minimum les tentatives, décisions, opérations commencées, résultats, transferts, changements de canal et terminaisons que le protocole permet réellement d'observer.

- Les événements distinguent l'action demandée, l'action autorisée, l'action transmise et son résultat.
- Les événements portent un identifiant de session, un identifiant d'événement, un horodatage UTC, un numéro de séquence local à la session, le protocole, le type d'événement et une version de schéma.
- Les métadonnées sont limitées en taille, profondeur et cardinalité ; les champs inconnus ne sont pas recopiés sans validation.
- Les secrets, mots de passe, clés privées, jetons, cookies d'authentification et credentials ne sont jamais émis.
- Les payloads de terminal, d'écran, de clipboard ou de transfert ne sont pas placés dans l'audit : ils relèvent du Recorder et de ses règles de chiffrement/rétention.
- Les bibliothèques ne détiennent pas les clés de signature de la chaîne d'audit et ne fabriquent pas de preuve cryptographique de plateforme. L'Audit Service valide, signe/chaîne, ancre et conserve les événements selon ses ADR.
- Si l'audit synchrone est déclaré obligatoire pour une opération, son indisponibilité empêche cette opération. Le profil de criticité et le point d'acquittement doivent être explicites ; aucun mode dégradé silencieux n'est admis.

### 5. Contrat TargetVerifier — identité de cible vérifiée avant credential

Chaque bibliothèque fournit un vérificateur d'identité de cible adapté au protocole. Le contrat commun impose le résultat, pas une représentation cryptographique universelle :

- l'identité attendue provient de la configuration de confiance de la cible (pinning, autorité ou profil déclaré) ;
- les éléments présentés par la cible sont vérifiés avant toute transmission de credential ou tout établissement de session authentifiée ;
- un résultat négatif, inconnu, expiré, révoqué, ambigu ou impossible à vérifier interrompt le handshake ;
- le motif interne est structuré pour l'audit, tandis que le message externe reste générique ;
- aucune option permissive par défaut ne permet d'ignorer la vérification.

Les preuves et algorithmes restent spécifiques : clé d'hôte/certificat SSH, chaîne TLS et identité RDP, ou profil de sécurité/certificat RFB lorsque le mode VNC correspondant le permet. Un protocole qui ne fournit pas une preuve équivalente doit documenter sa limite et ne peut pas être présenté comme offrant une vérification TLS qu'il n'implémente pas.

### 6. Contrat SessionLifecycle — annulation et terminaison réelles

Le cycle de vie est porté par le contexte de session et par la propriété explicite des connexions :

- toute opération bloquante reçoit un contexte annulable ;
- l'expiration, la révocation, la fermeture demandée ou la perte d'autorité annule ce contexte ;
- chaque bibliothèque observe l'annulation et ferme effectivement les transports, channels et flux qu'elle possède ; arrêter uniquement une goroutine ou marquer la session comme terminée ne suffit pas ;
- aucune nouvelle opération ne commence après observation de l'annulation ;
- les opérations en cours sont interrompues dans des délais bornés, puis leur résultat de clôture est tenté ;
- la terminaison est idempotente et sûre en présence d'appels concurrents ;
- les erreurs de terminaison sont observables par l'adaptateur et ne sont pas masquées.

L'adaptateur reste responsable de relayer les décisions du Session Broker et de propager la révocation à toutes les instances concernées, conformément à ADR-0018.

### 7. Enveloppe d'événement commune, payloads spécifiques

Les événements produits par les trois bibliothèques suivent les mêmes concepts d'enveloppe, sans imposer un type Go partagé :

| Champ | Sémantique |
|---|---|
| `schema_version` | version explicite du schéma d'événement |
| `event_id` | identifiant unique de l'événement |
| `session_id` | identifiant de session OpenBastion, opaque pour la bibliothèque |
| `sequence` | séquence monotone dans le flux d'événements de la session |
| `occurred_at` | instant UTC de l'observation |
| `protocol` | `ssh`, `rdp` ou `vnc` |
| `kind` | type d'événement défini par le protocole |
| `direction` | direction applicable : client→cible, cible→client ou interne |
| `operation_id` | corrélation des phases prepare/complete et du résultat |
| `metadata` | attributs typés, validés et bornés, sans secret |

Chaque bibliothèque définit ses propres valeurs de `kind` et ses extensions de métadonnées. Les champs communs ne doivent pas effacer la sémantique du protocole. L'ordre d'arrivée réseau n'est pas une preuve d'ordre durable ; les reçus du Recorder établissent les points d'acquittement.

### 8. Ordre normatif d'une opération contrôlée

Le parcours d'une opération significative suit cet ordre :

1. vérifier que la session est active et que son contexte n'est pas annulé ;
2. valider la forme et les limites de la requête protocolaire ;
3. vérifier l'identité de la cible avant l'authentification, lorsque l'opération établit une connexion cible ;
4. demander la décision Policy ;
5. émettre/acquitter l'événement d'audit préalable si le profil l'exige ;
6. appeler Recorder.Prepare et attendre son reçu ;
7. effectuer l'effet externe (transmission, exécution, entrée utilisateur ou service de données) ;
8. appeler Recorder.Complete avec le résultat ;
9. émettre l'événement d'audit de résultat ;
10. propager toute erreur de clôture à l'adaptateur et appliquer le traitement de sécurité défini.

Les étapes qui ne s'appliquent pas à une opération donnée sont explicitement documentées ; elles ne sont pas simplement omises par commodité. Pour les flux continus, ces étapes s'appliquent à chaque unité d'acquittement définie (segment, message ou lot borné), et non à chaque octet isolé.

### 9. Erreurs, délais et concurrence

Les trois bibliothèques exposent des erreurs Go inspectables par catégorie stable, sans exposer les secrets ni les détails sensibles à l'utilisateur final. Les catégories minimales sont : refus de politique, identité cible invalide, enregistrement indisponible, audit indisponible, session annulée/expirée/révoquée, limite dépassée, erreur protocolaire et erreur de transport.

Les ports reçoivent un `context.Context`. Chaque implémentation définit des délais maximums et des limites de taille ; aucune attente de Policy, Recorder, Auditor ou transport ne peut être infinie. Les appels concurrents sur une même session ne doivent pas contourner l'ordre de séquence ni provoquer une double transmission. Les garanties de sérialisation sont documentées par type d'opération.

### 10. Adaptateurs OpenBastion et responsabilités

Les bibliothèques restent indépendantes de PostgreSQL, Redis, NATS, Kafka, OpenSearch, MinIO, Envoy, Keycloak et des endpoints internes. Les adaptateurs OpenBastion :

- construisent le contexte et la requête de politique à partir d'une identité authentifiée ;
- relient Policy aux décisions de l'Authorization Service ;
- relient Recorder aux services d'enregistrement appropriés (terminal, commandes, vidéo ou transferts) ;
- relient Auditor à l'Audit Service, qui demeure propriétaire de la signature et de la chaîne ;
- relient le vérificateur aux éléments de confiance fournis par le Vault ou la configuration de cible ;
- propagent expiration et révocation depuis le Session Broker ;
- traduisent les erreurs internes en codes externes stables et génériques.

Aucun adaptateur ne doit renvoyer un secret au control plane ou à l'interface utilisateur.

### 11. Matrice de sémantique par protocole

| Contrat | SSH | RDP | VNC |
|---|---|---|---|
| Policy | exec, shell/PTY, subsystem, transfert | entrées, canaux virtuels, redirections | clavier, pointeur, clipboard, extensions |
| Recorder | requêtes, flux terminal, opérations de transfert | événements d'entrée/canaux et affichage | messages RFB, framebuffer et interactions |
| Auditor | channels, exec, subsystem, transfert, résultat | négociation, entrées, canaux et résultat | négociation, entrées, extensions et résultat |
| TargetVerifier | clé/certificat d'hôte | TLS et identité de cible | selon le profil RFB effectivement négocié |
| Lifecycle | transport, channels, commandes et subsystems | transport, canaux et session graphique | transport et flux RFB |
| Commandes | exec opaque ; PTY non sémantique | non fournies par RDP seul | non fournies par RFB |

La matrice décrit les points d'observation possibles, pas une promesse que chaque capacité est déjà implémentée. Chaque bibliothèque publiera une matrice de capacités testées par version et par implémentation distante.

### 12. Compatibilité, tests et publication

- Les interfaces publiques sont documentées et soumises à Semantic Versioning ; toute rupture d'API publique exige une version majeure.
- Les événements ont leur propre version de schéma, indépendante de la version du module Go.
- Les tests de conformité communs vérifient les propriétés comportementales : refus par défaut sur erreur, ordre Policy/Recorder/effet, absence de secret dans les événements, clôture et terminaison sur annulation.
- Les tests spécifiques vérifient les états, messages et capacités propres à SSH, RDP et RFB ; aucun test générique ne remplace l'interopérabilité protocolaire.
- Des tests négatifs couvrent timeout, Recorder/Auditor indisponible, reçu invalide, vérification cible échouée, annulation pendant un flux, concurrence, backpressure, limites et tentative de réutilisation d'un reçu.
- Fuzzing, race detector, tests de charge et interopérabilité réelle sont requis avant publication stable.
- Les bibliothèques et leurs exemples restent sous AGPL-3.0 ; la provenance des dépendances et licences est vérifiée. Aucun code propriétaire ou code tiers n'est copié.

## Conséquences

### (+) Résultats attendus, non encore mesurés

- Les trois moteurs appliqueront des garanties PAM cohérentes tout en conservant leurs modèles protocolaire et leurs événements propres.
- Les adaptateurs OpenBastion pourront être testés séparément des parseurs et transports.
- Les propriétés critiques (fail-closed, acquittement préalable, révocation, absence de secret) pourront être vérifiées dans un corpus de conformité commun.
- Les modules resteront autonomes et éviteront une dépendance de version entre bibliothèques.

Aucune interface ni bibliothèque n'est encore implémentée par cet ADR. Ces bénéfices ne sont donc pas mesurés à ce stade.

### (−) Limites et coûts

- Les interfaces Go exactes restent à concevoir et à valider sur les parcours existants ; cet ADR fixe leur sémantique, pas leurs signatures définitives.
- La duplication volontaire de petites interfaces entre modules peut exister ; elle est préférée à un package partagé prématuré.
- Les capacités d'observation diffèrent fortement entre SSH, RDP et VNC ; aucune parité de capture ou de contrôle n'est promise.
- L'acquittement synchrone ajoute de la latence et impose une conception rigoureuse de la backpressure.
- Une panne après l'effet externe mais avant `Complete` peut laisser une opération dont le résultat est connu du proxy mais pas durablement clôturé ; les adaptateurs doivent signaler cet état et permettre la réconciliation.
- Un audit émis par une bibliothèque n'est pas, à lui seul, une preuve signée ; cette responsabilité reste centralisée.
- La révocation dépend de la propagation par le Session Broker et de la fermeture effective des ressources possédées par chaque bibliothèque.
- Les garanties d'identité de cible dépendent des capacités cryptographiques réellement disponibles dans chaque protocole et profil.

## Alternatives envisagées

- **Créer immédiatement un module Go commun de contrats** : rejeté à ce stade ; les signatures ne sont pas encore validées par des usages réels et le package deviendrait un point de couplage/versionnage entre bibliothèques.
- **Faire importer SSH, RDP et VNC les uns par les autres** : rejeté ; cela détruirait leur autonomie et mélangerait des sémantiques distinctes.
- **Créer une interface universelle `ExecuteCommand` ou `CaptureCommand`** : rejeté ; RDP et VNC ne fournissent pas une sémantique de commande distante, et SSH PTY ne garantit pas l'interprétation réelle.
- **Traiter l'audit et l'enregistrement comme une seule interface** : rejeté ; l'audit est une trace structurée signée centralement, tandis que le Recorder gère des flux/payloads chiffrés, leur durabilité et leur replay.
- **Autoriser un mode dégradé permissif si Recorder ou Policy est indisponible** : rejeté ; contraire aux invariants fail-closed d'OpenBastion.
- **Uniformiser les preuves de cible dans un type cryptographique unique** : rejeté ; les preuves SSH, RDP/TLS et RFB dépendent des mécanismes effectivement négociés.

## Références

- [ADR-0003 — Les secrets ne traversent jamais le control plane](0003-les-secrets-ne-traversent-jamais-le-control-plane.md)
- [ADR-0008 — Enregistrer ou refuser](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md)
- [ADR-0010 — mTLS interne](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md)
- [ADR-0018 — Terminaison effective d'une session](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md)
- [ADR-0025 — Événements d'audit bornés](0025-l-audit-service-ne-prend-dans-la-trace-que-ce-qu-un-emetteur.md)
- [ADR-0026 — Hash d'événement versionné](0026-le-hash-d-un-evenement-d-audit-couvre-chaque-champ-comme-un.md)
- [ADR-0027 — Chaîne d'audit à clé](0027-la-chaine-d-audit-est-a-cle-hmac-et-chaque-evenement-dit.md)
- [ADR-0038 — SFTP et SCP à travers le proxy](0038-sftp-et-scp-a-travers-le-proxy-chaque-transfert-est.md)
- [ADR-0068 — Détails d'audit bornés et protégés](0068-les-details-d-un-evenement-d-audit-sont-bornes-et-proteges-par-le-hash.md)
- [ADR-0070 — Segments vidéo chiffrés et acquittés](0070-le-video-recorder-acquitte-des-segments-chiffres-avant-de-les-servir.md)
- [ADR-0071 — Proxy RDP/VNC Go pur](0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md)
- [ADR-0082 — rsync distant via le proxy SSH](0082-rsync-distant-passe-par-le-proxy-ssh-sans-shell-arbitraire.md)
- [ADR-0083 — Bibliothèque SSH OpenBastion](0083-bibliotheque-ssh-openbastion-avec-politiques-capture-et-audit.md)
- [ADR-0084 — Bibliothèque RDP OpenBastion](0084-bibliotheque-rdp-openbastion-moteur-protocolaire-instrumente.md)
- [ADR-0085 — Bibliothèque VNC OpenBastion](0085-bibliotheque-vnc-openbastion-moteur-rfb-instrumente.md)
