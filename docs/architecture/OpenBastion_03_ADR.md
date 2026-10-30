# OpenBastion — Architecture Decision Records

**Version** 0.1 · **Statut** Draft de travail
**Document précédent** `OpenBastion_02_Arborescence_Depot.md`
**Portée** Formalisation des décisions déjà signalées « 🔖 Sujet ADR » dans les documents précédents, plus les décisions structurantes de langage et de service partagé.

---

## 1. Format retenu

Chaque ADR suit un gabarit léger (inspiré de Michael Nygard / MADR) : **Contexte, Décision, Conséquences, Alternatives envisagées**. Statuts possibles : `Proposé`, `Accepté`, `Déprécié`, `Remplacé par ADR-NNNN`. Dans le dépôt, chaque ADR vivra en fichier individuel sous `docs/adr/NNNN-titre-kebab-case.md` (convention posée au document précédent, §8) ; ils sont consolidés ici pour la revue initiale.

## 2. Index

| ID | Titre | Statut |
|---|---|---|
| ADR-0001 | Double bus NATS (temps réel) + Kafka (streaming durable) | Accepté |
| ADR-0002 | Organisation en monorepo multi-module Go | Accepté |
| ADR-0003 | Les secrets ne traversent jamais le control plane | Accepté |
| ADR-0004 | Go comme langage unique des microservices backend | Accepté |
| ADR-0005 | Séparation Password Vault / Secrets Manager | Accepté |
| ADR-0006 | Pipeline proxy partagé factorisé en bibliothèque interne | Accepté |
| ADR-0007 | Keycloak comme IdP de plateforme, fédération externe en complément | Accepté |
| ADR-0008 | Enregistrer ou refuser : une session qui ne peut pas être enregistrée n'a pas lieu | Accepté |
| ADR-0009 | Break-glass : une dérogation d'urgence, bornée et auditée, à « enregistrer ou refuser » | Accepté |
| ADR-0010 | mTLS interne : l'identité de l'appelant vient du certificat, et chaque route a sa liste d'appelants | Accepté |
| ADR-0011 | Break-glass : double validation — une demande en attente, approuvée par une autre personne | Accepté |
| ADR-0012 | Break-glass : l'approbateur découvre les demandes en attente (liste filtrée par son droit) et en est prévenu (webhook, au mieux) | Accepté |
| ADR-0013 | Break-glass : un plafond de demandes en attente par demandeur (atomique) et un message de notification signé (HMAC) | Accepté |
| ADR-0014 | Une limitation de débit par identité sur les demandes de session, au Gateway — et un limiteur dont les unités et la mémoire sont justes | Accepté |
| ADR-0015 | Qui est « le client » derrière l'arête : une confiance à `X-Forwarded-For` limitée aux proxys déclarés, et des limites par adresse réglables | Accepté |
| ADR-0016 | Un budget par identité sur les actions de session qui écrivent à chaque appel (`approve`, `reject`, `connect`) — et pas sur ce qui n'écrit qu'une fois ou rien | Accepté |
| ADR-0017 | Mettre fin à une session : son demandeur ou une autorité déclarée, et au nom de celui qui le demande | Accepté |
| ADR-0018 | Rendre la terminaison réelle côté proxy : le Broker fait couper les connexions et jeter les tickets avant de marquer la session terminée | Accepté |
| ADR-0019 | Qui peut lire une session : son demandeur, celui qui l'a décidée, ou le titulaire d'une politique `session-read` — et une lecture n'écrit rien | Accepté (règle 6 amendée par ADR-0020) |
| ADR-0020 | Auditer les refus de lecture d'une session, au nom de celui qui lit, dans la limite d'un budget par identité | Accepté (règle 2 amendée par ADR-0021) |
| ADR-0021 | Une lecture servie à un titulaire de politique s'enregistre avant d'être servie — et sans enregistrement, elle n'est pas servie | Accepté |
| ADR-0022 | Chaque page d'un enregistrement du Command Recorder servie s'enregistre avant d'être servie, au nom de celui que le Gateway a vérifié — et sans enregistrement, elle n'est pas servie | Accepté (règle 6 amendée par ADR-0024) |
| ADR-0023 | Chaque demande servie par la liste des demandes en attente s'enregistre avant d'être servie — et sans enregistrement, la liste n'est pas servie | Accepté |
| ADR-0024 | Auditer les refus de lecture d'un enregistrement, dans un budget par identité — et un seul seau à jetons, partagé (`pkg/refusalbudget`) | Accepté |
| ADR-0025 | L'Audit Service ne prend dans la trace que ce qu'un émetteur peut vouloir dire (forme et taille de chaque champ, corps borné) | Accepté |
| ADR-0026 | Le hash d'un événement d'audit couvre chaque champ comme un champ : un format versionné, et l'ancien seulement pour vérifier | Accepté |

---

## ADR-0001 — Double bus NATS (temps réel) + Kafka (streaming durable)

**Contexte**
Deux besoins de communication asynchrone coexistent : la coordination inter-services à faible latence (établissement de session, notifications d'approbation, score de risque) et la constitution d'un flux d'audit durable, rejouable, à garanties d'ordre fortes pour des besoins de conformité.

**Décision**
Adopter deux bus distincts : **NATS** pour la coordination temps réel, **Kafka** pour le streaming durable des événements d'audit et de session.

**Conséquences**
- (+) Chaque bus est utilisé pour ce qu'il fait le mieux ; pas de compromis sur la latence de coordination ni sur la durabilité de l'audit.
- (+) Isolation des pannes : un incident sur le bus de coordination n'affecte pas la rétention d'audit, et inversement.
- (−) Deux systèmes de messagerie à exploiter, superviser et sécuriser (mTLS, quotas, capacité) — coût opérationnel réel, accepté sciemment.
- (−) Complexité accrue pour un nouveau contributeur découvrant l'architecture.

**Alternatives envisagées**
- *Kafka seul* : rejeté — latence et modèle pub/sub moins adaptés à la coordination synchrone courte (ex. attente de décision du Session Broker).
- *NATS JetStream seul* (durabilité incluse) : envisageable à terme, mais l'écosystème d'outillage de conformité/rejeu autour de Kafka est jugé plus mature aujourd'hui pour un usage d'audit réglementaire.

---

## ADR-0002 — Organisation en monorepo multi-module Go

**Contexte**
L'architecture comporte ~35 microservices dont les contrats gRPC bougeront fréquemment pendant la phase pré-v1.0. Un multi-repo imposerait une coordination de versions de contrats dès le premier jour.

**Décision**
Un seul dépôt Git, avec un `go.mod` par service (`go.work` en racine) — monorepo au niveau du dépôt, modules isolés au niveau Go.

**Conséquences**
- (+) Refactoring cross-service atomique (un commit peut modifier un contrat `proto/` et tous ses consommateurs).
- (+) CI et revue de code centralisées.
- (+) Extraction future d'un service vers un dépôt indépendant possible sans réécriture, grâce à l'isolation des modules Go.
- (−) Nécessite un outillage CI sélectif par chemins modifiés pour éviter de reconstruire les 35 services à chaque commit.

**Alternatives envisagées**
- *Multi-repo dès le départ* : rejeté pour la phase actuelle — coût de coordination des contrats jugé trop élevé tant que l'architecture n'est pas stabilisée en v1.0.

---

## ADR-0003 — Les secrets ne traversent jamais le control plane

**Contexte**
Un PAM doit garantir qu'aucun opérateur, ni aucun composant d'orchestration compromis, ne puisse exfiltrer un secret cible. Le Session Broker, l'API Gateway et le Workflow Service constituent le control plane.

**Décision**
Seuls les proxies protocolaires récupèrent un credential éphémère, directement auprès du Vault via mTLS, au moment de l'établissement de connexion. Le control plane autorise (scope, TTL) mais ne manipule ni ne transmet jamais le secret lui-même.

**Conséquences**
- (+) Compromission du control plane ≠ fuite de secrets.
- (+) Surface d'audit claire : seul le proxy peut avoir détenu un secret donné, à un instant donné.
- (−) Chaque proxy doit implémenter sa propre logique de récupération et de purge mémoire (mutualisée via `pkg/proxycore`, ADR-0006).
- (−) Le scoping des droits Vault par proxy doit être strict et testé (un proxy DB ne doit jamais pouvoir demander un secret SSH).

**Alternatives envisagées**
- *Le Broker récupère le secret et le transmet au proxy* : rejeté — réintroduit un point unique de compromission critique sur un composant à plus large surface d'exposition réseau que les proxies.

---

## ADR-0004 — Go comme langage unique des microservices backend

**Contexte**
La plateforme comporte de nombreux microservices aux profils variés (proxies à fort débit, services de décision, connecteurs d'identité). Un langage unique simplifie l'outillage, le recrutement de contributeurs open source, et la cohérence du monorepo.

**Décision**
Tous les microservices backend sont écrits en Go.

**Conséquences**
- (+) Concurrence native (goroutines) bien adaptée aux proxies à connexions multiples.
- (+) Compilation statique → images conteneur minimales, démarrage rapide.
- (+) Un seul outillage de build/lint/test à maintenir dans la CI.
- (−) Écarte des langages parfois plus riches pour certains domaines spécifiques (ex. ML pour le Risk Engine) — traité en composant optionnel isolable plutôt qu'en exception de langage (§ ADR future si besoin).

**Alternatives envisagées**
- *Polyglotte par domaine* (ex. Python pour le Risk Engine) : rejeté à ce stade — la brique ML du Risk Engine reste optionnelle et peut être exposée comme service séparé appelé via gRPC sans remettre en cause l'uniformité du reste.

---

## ADR-0005 — Séparation Password Vault / Secrets Manager

**Contexte**
Le brief distingue des comptes privilégiés à cycle de vie géré (mots de passe, clés SSH, certificats de compte, avec rotation/découverte automatique) de secrets applicatifs plus génériques et souvent dynamiques (API keys, tokens, secrets à courte durée de vie).

**Décision**
Deux microservices distincts : **Password Vault** (comptes privilégiés, découverte, rotation) et **Secrets Manager** (secrets applicatifs génériques, émission dynamique).

**Conséquences**
- (+) Modèles de données et cycles de vie différents ne sont pas forcés dans un schéma unique.
- (+) Politiques de rotation spécifiques à chaque nature de secret.
- (−) Les proxies doivent parfois consulter les deux services selon le type de ressource cible (ex. Database Proxy peut consommer un secret dynamique du Secrets Manager plutôt qu'un compte du Password Vault).

**Alternatives envisagées**
- *Vault unique généraliste* : rejeté — aurait mélangé la logique de découverte/rotation de comptes systèmes avec l'émission de secrets applicatifs dynamiques, deux logiques métier différentes.

---

## ADR-0006 — Pipeline proxy partagé factorisé en bibliothèque interne

**Contexte**
Les 9 proxies protocolaires (SSH, RDP/VNC, Telnet/Serial-IPMI, WinRM, Database, Kubernetes, Docker, Hyperviseur, HTTP/HTTPS) partagent la même séquence : écoute, récupération de credential, relais protocolaire, capture d'enregistrement, purge mémoire.

**Décision**
Factoriser ce pipeline dans `pkg/proxycore`, importé par chaque proxy, qui n'implémente que son `Protocol Codec` spécifique.

**Conséquences**
- (+) L'invariant ADR-0003 (purge mémoire, scoping Vault) est implémenté une seule fois, testé une seule fois, plutôt que dupliqué neuf fois avec risque de divergence.
- (+) Un nouveau protocole cible s'ajoute en implémentant uniquement un nouveau Codec.
- (−) `pkg/proxycore` devient un composant critique partagé — tout bug s'y trouvant affecte les 9 proxies simultanément ; couverture de tests renforcée requise.

**Alternatives envisagées**
- *Duplication par proxy* : rejeté — risque de divergence silencieuse sur la logique de purge mémoire, précisément le point le plus sensible du système.

---

## ADR-0007 — Keycloak comme IdP de plateforme, fédération externe en complément

**Contexte**
OpenBastion doit s'authentifier lui-même (comptes locaux, sessions internes) tout en fédérant des annuaires externes hétérogènes (LDAP, AD, Entra ID, OIDC, SAML).

**Décision**
Keycloak sert d'IdP de plateforme embarqué (source de vérité des sessions OpenBastion), les connecteurs de fédération (§4.7 doc 00) synchronisant ou déléguant vers les IdP externes plutôt que de dupliquer une logique OIDC/SAML complète par connecteur.

**Conséquences**
- (+) Un seul point d'émission de JWT pour l'ensemble de la plateforme, quelle que soit la source d'identité d'origine.
- (+) Réutilise un projet OSS mature plutôt que de réimplémenter un serveur OIDC/SAML.
- (−) Keycloak devient une dépendance de disponibilité critique — traité dans le futur guide HA.

**Alternatives envisagées**
- *Chaque connecteur émet ses propres jetons* : rejeté — aurait fragmenté le modèle de session et compliqué l'Authorization Service, qui doit raisonner sur une identité canonique unique.

---

## ADR-0008 — Enregistrer ou refuser : une session qui ne peut pas être enregistrée n'a pas lieu

**Contexte**
L'enregistrement des sessions est la raison d'être d'un bastion : sans lui, un accès privilégié n'est plus auditable. Or le Command Recorder (doc 06) est un service comme un autre — il peut être arrêté, injoignable, ou sa base peut passer en lecture seule (basculement de réplica, disque plein). Il faut décider ce que fait le proxy dans ce cas. La première implémentation du tap d'enregistrement était *au mieux* : les commandes partaient dans une file asynchrone, et une panne du recorder faisait perdre des entrées **sans que la session s'arrête ni que l'opérateur le sache**. Un administrateur pouvait donc exécuter des commandes non journalisées pendant une panne — ou la provoquer.

**Décision**
La politique par défaut est `required` (variable `RECORDING_POLICY`, valeur par défaut `required`) et applique deux garde-fous distincts :

1. **Admission** — le proxy interroge `GET /readyz` du recorder à deux moments : à `EstablishSession` (avant d'émettre le ticket de connexion — refus précoce et lisible) puis de nouveau quand le client se connecte, **avant** de récupérer le credential (le recorder a pu tomber entre-temps). Un recorder non prêt (injoignable, ou base non inscriptible) **refuse la session** : `EstablishSession` renvoie `503 recording unavailable`, le Session Broker le relaie tel quel (pas un `409`), et l'événement `session.recording_unavailable` est audité. Le scope Vault à usage unique n'est pas consommé (ADR-0003) ; il est simplement réémis à la tentative suivante.
2. **Acquittement par commande** — une ligne de commande n'est transmise à la cible qu'**après** que le recorder l'a acquittée (`RecordBatch`, tout ou rien). Si l'enregistrement échoue, la commande n'est **pas** exécutée, l'opérateur reçoit un message explicite (« session ended because recording is unavailable… »), la session est terminée et `session.recording_lost` est audité.

Le mode `best-effort` subsiste mais doit être choisi **explicitement** ; le proxy l'annonce au démarrage par un avertissement. La valeur zéro de `RecordingConfig` est `required` : une configuration oubliée refuse les sessions au lieu de les laisser passer. Un proxy en `required` **refuse de démarrer** s'il n'a pas de `RECORDER_URL`, et une valeur de politique inconnue est une erreur fatale, pas un repli silencieux.

Le prégate `/readyz` n'est qu'une courtoisie (refus tôt et lisible) : c'est l'acquittement qui garantit l'enregistrement. Un recorder qui tombe une milliseconde après un `/readyz` favorable arrête la session à la commande suivante.

**Conséquences**
- (+) Aucune commande exécutée sur une cible n'échappe à l'enregistrement : il n'existe plus de fenêtre de panne pendant laquelle un privilège est utilisable sans trace. Prouvé au niveau unitaire, sur un vrai canal SSH en processus, et sur 8 processus réels (une commande tapée pendant une panne n'arrive jamais à la cible).
- (+) La panne du recorder est visible : l'opérateur est informé, l'audit porte deux événements distincts (refus à l'admission / perte en cours de session).
- (−) **Le Command Recorder devient une dépendance de disponibilité de tous les accès privilégiés.** Il doit être déployé en haute disponibilité (guide HA) et supervisé comme un composant de rang 1.
- (−) Latence : chaque ligne de commande attend un aller-retour acquitté vers le recorder avant d'être transmise (retry limité : 2 tentatives, uniquement sur erreur de connexion ou `500`/`503`, car le recorder est en ajout seul sans déduplication — un échec ambigu n'est jamais rejoué).
- (−) Un échec ambigu (réponse perdue après écriture) peut **sur-enregistrer** une commande jamais exécutée ; on préfère ce sens d'erreur au sens inverse.
- (−) Pas de dérogation d'urgence (« break-glass ») : si le recorder est indisponible, personne n'accède aux cibles via le bastion. Une procédure d'urgence avec approbation, auditée et temporaire est une décision ouverte (v1.0), distincte de ce choix.
- Ne change pas les limites déjà connues du tap : l'historique, la complétion et les déplacements de curseur ne sont pas reconstitués, et un secret saisi dans les arguments d'une commande est enregistré tel que saisi. L'ADR garantit l'enregistrement de ce que le proxy capte, pas l'exhaustivité de la capture.

**Alternatives envisagées**
- *Au mieux, avec alerte* : rejeté — une alerte n'empêche pas une commande non journalisée, et un attaquant qui sait déclencher la panne obtient une fenêtre sans trace.
- *Tamponner localement puis rejouer* : rejeté pour le MVP — un tampon sur le proxy redevient un second lieu où vivent des données de session (chiffrement, purge, taille à borner) et ne supprime pas la décision « que faire quand il est plein ? ».
- *Laisser l'opérateur choisir* : rejeté — la décision d'enregistrer ne doit pas appartenir à celui qui est enregistré.

---

## ADR-0009 — Break-glass : une dérogation d'urgence, bornée et auditée, à « enregistrer ou refuser »

**Contexte**
ADR-0008 fait du Command Recorder une dépendance de disponibilité de tous les accès privilégiés : s'il est en panne, personne n'atteint les cibles via le bastion. C'est le bon défaut — mais c'est aussi exactement la situation où un incident de production exige un accès. Un PAM répond classiquement par un accès « break-glass ». Mal conçu, c'est une porte dérobée : un drapeau que n'importe quel administrateur peut lever pour échapper à l'enregistrement. La question n'est donc pas d'en avoir un, mais de savoir ce que la dérogation coûte et ce qui la borne.

**Décision**
Le break-glass est **une dérogation à l'enregistrement, pour une session, et rien d'autre**. Il ne contourne ni l'authentification, ni le RBAC `session:create`, ni le Vault (le secret n'est toujours jamais exposé), ni l'audit (toujours fail-closed). Il s'appuie sur six verrous :

1. **Demandé explicitement** : `breakGlass: true` à `POST /sessions`, avec une justification d'au moins 10 caractères (un plancher contre le vide, pas une garantie de qualité).
2. **Autorisé à part** : une politique RBAC sur la ressource `breakglass:account:{accountId}` — refusé par défaut. Être administrateur de la plateforme ne suffit pas ; il faut une politique `breakglass:*` explicite. (La ressource, et non l'action, porte la distinction : `CheckAccess` n'évalue aujourd'hui que le rôle et la ressource.)
3. **Borné dans le temps** : durée maximale `BREAKGLASS_MAX_MINUTES` côté Broker, **désactivé tant qu'elle vaut 0 (défaut)**. La durée est imposée par le **proxy**, qui coupe désormais toute session à son échéance (`session.expire`) — jusqu'ici l'expiration n'était qu'une lecture paresseuse du Broker et rien ne coupait une session déjà connectée.
4. **Désactivé par défaut dans le proxy aussi** : `BREAKGLASS_ENABLED` (défaut faux) — un proxy qui ne l'a pas activé refuse la dérogation même si le Broker l'a autorisée. Deux interrupteurs, deux endroits : le Broker décide, le proxy applique.
5. **Exercée seulement en cas de besoin** : si le recorder est prêt à l'admission, la session est enregistrée normalement, avec acquittement par commande (ADR-0008). La dérogation n'a d'effet que lorsque le recorder n'est **pas** prêt ; une session break-glass ne dégrade jamais une session qui pouvait être enregistrée.
6. **Jamais silencieuse** : `session.breakglass_requested` (Broker : qui, succès ou refus), puis `session.breakglass` (proxy : la dérogation a réellement servi, émis **avant** la récupération du credential — si cet événement ne peut pas être audité, la session est refusée), puis `session.expire` à l'échéance. La justification reste lisible sur la session.

Pendant une session dérogée, l'enregistrement continue **au mieux** : les commandes sont envoyées au recorder sans l'attendre, sans jamais bloquer l'opérateur ; celles qui échouent sont comptées et journalisées, pas masquées.

**Conséquences**
- (+) Un accès d'urgence existe, sans trou silencieux : une dérogation laisse trois événements d'audit chaînés et signés, une justification, un titulaire de politique identifiable et une durée butoir.
- (+) La coupure à l'échéance corrige un défaut général : toute session, pas seulement break-glass, a maintenant une fin imposée par le proxy.
- (−) **Pendant une session dérogée, des commandes peuvent ne pas être enregistrées** — c'est le coût assumé de l'exception. La traçabilité repose alors sur l'audit, la justification et les journaux de la cible ; le replay peut être incomplet, et dupliqué (le mode au mieux rejoue sur échec ambigu).
- (−) **Une seule personne suffit** : pas de double validation (le Workflow Service et l'Approval Engine sont v1.0). Atténué par une politique étroite et la désactivation par défaut ; à compléter en v1.0 par une approbation à deux et une revue post-incident obligatoire. **Approbation à deux : ADR-0011** (requise par défaut) ; la revue post-incident reste ouverte.
- (−) Le drapeau voyage du Broker au proxy sur le canal interne, qui attendait le mTLS (comme le jeton de scope). Sans lui, un appelant atteignant le proxy pouvait l'ajouter lui-même ; il lui fallait toujours un scope Vault valide, et le proxy doit avoir été activé (verrou 4). **Résolu par ADR-0010** : `establish-session` n'accepte que l'identité du Session Broker.
- (−) La ressource `breakglass:account:*` est une convention de nommage, pas un type : une politique mal écrite (`*`) l'accorderait. Les guides le disent.

**Alternatives envisagées**
- *Basculer `RECORDING_POLICY=best-effort` le temps de l'incident* : rejeté — cela dérègle toutes les sessions, exige de redémarrer les proxies, n'identifie personne, et ne se ferme pas tout seul.
- *Tampon local sur le proxy, rejoué au retour du recorder* : écarté pour l'instant (voir ADR-0008) — c'est un second lieu de stockage des données de session (chiffrement, purge, borne, déduplication au rejeu) ; à reconsidérer si les dérogations deviennent fréquentes.
- *Dérogation automatique pour les administrateurs* : rejeté — le privilège de gérer les politiques n'est pas celui d'échapper à l'enregistrement.
- *Sans limite de durée* : rejeté — une dérogation sans butoir devient un mode de fonctionnement.

---

## ADR-0010 — mTLS interne : l'identité de l'appelant vient du certificat, et chaque route a sa liste d'appelants

**Contexte**
Trois décisions précédentes reposent sur une chose qui n'existait pas encore. ADR-0003 : seul le proxy peut échanger un scope contre un secret — mais « le proxy » n'était qu'un champ (`calling_proxy_id`) du corps de la requête. ADR-0009 : le Broker transmet au proxy le drapeau `break_glass` — sur un canal où n'importe quel appelant pouvait l'ajouter lui-même. Et le Command Recorder acceptait des écritures de quiconque atteignait son port. Le doc 07 dit pourtant depuis le début que l'identité de l'appelant est « jamais un champ de message : dérivée du certificat mTLS ». Tant que le transport est du HTTP en clair, cette phrase est une intention : chaque service croit ce que dit le corps, et un seul service compromis (ou un seul pod hostile sur le réseau) peut se faire passer pour n'importe quel autre. L'architecture (doc 00) prévoit du mTLS via un mesh Envoy ; le sandbox n'a ni mesh ni gRPC, et la question de fond est ailleurs : *qui décide qu'un appelant a le droit d'appeler cette route ?*

**Décision**
Le service lui-même authentifie et autorise chaque appel interne, à partir du certificat — pas du réseau, pas du corps. Huit règles :

1. **Une identité, un nom de service.** L'identité est l'unique SAN URI du certificat, `spiffe://<domaine>/<service>` (domaine par défaut `openbastion.local`, `TLS_TRUST_DOMAIN`). Les noms sont ceux des huit services plus `admin-cli` (outillage opérateur). Zéro ou plusieurs SAN URI, un autre schéma, un autre domaine, un chemin à plusieurs segments : refusé.
2. **TLS 1.3, certificat client obligatoire, identité du serveur épinglée.** Le serveur exige et vérifie un certificat client de la chaîne attendue. Le client vérifie chaîne et adresse (jamais `InsecureSkipVerify`) **et** que le pair répond sous le nom de service attendu : un client n'est construit que pour des pairs déclarés (`Peer{URL, Service}`), refuse toute autre adresse, tout `http://`, et ignore les variables proxy. Une adresse détournée vers un service qui a un certificat valide mais n'est pas le Vault ne reçoit rien.
3. **Une table d'appelants par service, refus par défaut.** Chaque service déclare des règles `{méthode, chemin ou préfixe, appelants}` ; la première règle qui correspond décide, **aucune règle ne correspond = 403**, une table mal formée empêche le démarrage, un chemin non canonique est refusé (400). Les refus de cette garde ont un corps reconnaissable (`forbidden`) : un appel stoppé à la porte se distingue d'un appel entré puis refusé par l'autorisation du service.
4. **L'identité du certificat remplace les champs déclaratifs.** Le Vault déduit le proxy du certificat ; `calling_proxy_id` devient facultatif et une discordance est un 403 **sans consommer le jeton**. Les rôles (`actorRoles`) ne sont acceptés que d'un appelant autorisé à les affirmer — le Gateway, qui les tire du jeton de l'utilisateur ; le drapeau break-glass n'est accepté que du Broker ; les entrées du recorder que du proxy ; les événements d'audit que du Broker et du proxy ; la création d'utilisateurs et la vérification de la chaîne d'audit que de `admin-cli`.
5. **Requis par défaut.** `INTERNAL_TLS` vaut `required` quand il est absent ; `disabled` doit être demandé par son nom et chaque service l'annonce en avertissement ; toute autre valeur est fatale (une faute de frappe ne choisit aucun des deux côtés). Un service refuse de démarrer sans certificat, clé et CA, avec un certificat expiré, d'un autre domaine, ou **appartenant à un autre service** ; le proxy SSH refuse `PROXY_SERVICE_ID` différent de son identité. (Même principe qu'ADR-0008 : un réglage oublié ne doit jamais sélectionner le comportement faible.)
6. **Rotation sans redémarrage, sans fenêtre ouverte.** Les fichiers sont relus quand leur contenu change (au plus tous les `TLS_RELOAD_INTERVAL`, 5 s par défaut) et échangés atomiquement. Un remplacement invalide — autre autorité, autre identité, clé qui ne correspond pas, autorité retirée avant que le service ait un certificat de la nouvelle — est **refusé, l'ancien est conservé** et le refus est journalisé une fois. L'expiration est annoncée quand il reste 20 % de la durée de vie, puis à l'échéance.
7. **Pas de liste de révocation : des certificats courts, et le remplacement de l'autorité.** Une compromission se traite en ajoutant la nouvelle autorité au bundle (recouvrement : les deux sont acceptées), en réémettant les certificats, puis en retirant l'ancienne. Aucun CRL/OCSP à distribuer, aucune fenêtre pendant laquelle un service légitime est refusé.
8. **Le listener public du Gateway reste en HTTP.** Ses appelants sont des personnes avec un jeton, pas des services avec un certificat ; le TLS se termine à l'arête (Traefik). Le Gateway a une identité pour ses **appels sortants** — c'est lui qui affirme les rôles.

Outillage : `pkg/mtls` (bibliothèque, stdlib seulement) et `openbastion-pki` (`init`, `issue`, `all`) pour une autorité de développement ou de petit déploiement. En production, l'émission est celle de l'organisation (cert-manager, Vault PKI, SPIRE…) du moment que l'identité a la forme de la règle 1.

*Rapport avec le mesh Envoy du doc 00.* Les deux ne s'excluent pas, mais le mesh ne peut pas porter à lui seul cette décision. Un sidecar qui termine le mTLS livre au service une connexion locale : le service ne sait plus qui appelle, sauf à croire un en-tête (`X-Forwarded-Client-Cert`) — c'est-à-dire à refaire de l'identité un champ de message, cette fois posé par le sidecar. Le mesh reste utile pour le routage, les reprises et l'observabilité (en passthrough TCP, il laisse le TLS de bout en bout) ; si l'organisation émet les certificats avec SPIRE, il suffit d'enregistrer les identités au format `spiffe://<domaine>/<service>` (un seul segment) et de monter les fichiers là où le service les attend.

**Conséquences**
- (+) Un service compromis ne peut faire que ce que sa table lui permet. Prouvé sur 8 processus réels sous `INTERNAL_TLS=required` : le parcours complet (connexion, session, SSH, enregistrement, lecture par un auditeur) fonctionne ; 20 appels forgés (24 depuis ADR-0011) par une identité valide mais *mauvaise* (un Gateway qui crée des utilisateurs ou génère des scopes, un Broker qui forge des rôles ou des entrées de recording, le Vault qui écrit dans l'audit, une demande break-glass d'un non-Broker…) sont arrêtés à la porte, et rien n'a eu lieu ; un jeton de scope volé est inutilisable par toute autre identité que le proxy (et ne brûle pas à chaque tentative) ; sans certificat, avec un certificat d'une autre autorité, d'un autre domaine ou expiré, aucun échange n'a lieu ; un Broker dont l'adresse du Vault mène à un imposteur ne lui envoie rien.
- (+) Ferme deux limites ouvertes : les écritures non authentifiées du Command Recorder, et le canal du drapeau break-glass (ADR-0009, conséquence 4).
- (+) La rotation d'un certificat, et le remplacement de l'autorité, se font sur des processus vivants (testé).
- (−) **Le certificat devient une dépendance de disponibilité de rang 1** : un certificat expiré est une panne, pour ce service et pour ceux qui l'appellent. Il faut surveiller l'échéance (le service journalise l'approche et l'échéance) et renouveler bien avant ; guide HA.
- (−) Les sondes HTTP du kubelet ne présentent pas de certificat client : sondes `tcpSocket`, ou port de santé distinct (à faire — décision ouverte).
- (−) **Les listes d'appelants sont dans le code, pas dans la configuration.** Un changement de topologie est une livraison ; en contrepartie, personne ne peut élargir une règle par une erreur de configuration. À reconsidérer si des déploiements divergent.
- (−) Un service compromis fait tout ce que sa table autorise : le Gateway affirme les rôles des utilisateurs, donc un Gateway compromis agit en leur nom. Le mTLS borne ce que *les autres* peuvent faire, pas ce que fait celui-là ; le RBAC en aval (Authorization) reste la limite.
- (−) **Les événements d'audit ne sont pas encore attribués par l'identité du certificat** : `actor_id` reste déclaratif sur `emit-event`. Les deux appelants autorisés sont connus, mais l'attribution signée par appelant est un travail distinct (reporté).
- (−) Le transport interne reste du HTTP/JSON (gRPC non disponible dans le sandbox) ; la même garde se transpose en intercepteur gRPC. Pas de CRL/OCSP (règle 7). Le mode `disabled` garde toutes les faiblesses antérieures et ne doit pas atteindre la production.
- (−) Le Gateway recopie le corps des erreurs de ses amonts : un échec de connexion interne peut afficher une adresse interne à l'utilisateur (déjà vrai avant le mTLS ; le message d'identité s'y ajoute). À traiter à part.

**Alternatives envisagées**
- *Mesh seul (Envoy/Istio en mTLS automatique)* : rejeté comme **seul** mécanisme — voir plus haut ; compatible en complément.
- *Jeton signé par appel (JWT de service) au lieu d'un certificat client* : rejeté — il faut quand même un canal chiffré, un secret à distribuer, et la protection contre le rejeu ; le certificat réunit les trois.
- *Listes d'appelants en configuration* : rejeté pour le MVP (voir ci-dessus).
- *Liste de révocation / OCSP* : rejeté — une infrastructure de plus, qui devient elle-même une dépendance critique ; les certificats courts et le remplacement de l'autorité couvrent le besoin.
- *Identité = nom DNS dans le CN/SAN* : rejeté — un nom DNS désigne une adresse, pas un rôle ; plusieurs services peuvent partager une adresse, un même service en changer.

---

## ADR-0011 — Break-glass : double validation — une demande en attente, approuvée par une autre personne

**Contexte**
ADR-0009 a borné la dérogation (six verrous) mais a laissé une limite écrite : **une seule personne suffit**. Quiconque détient la politique `breakglass:account:*` obtient, seul, une session qui peut s'exécuter sans enregistrement — exactement la session que l'on voudrait qu'une seconde paire d'yeux ait validée, et la plus tentante à demander sous un faux prétexte d'urgence. Le Workflow Service et l'Approval Engine (doc 00) sont des composants v1.0 qui n'existent pas ; attendre eux, c'est laisser la dérogation la plus sensible du produit sans contrôle à deux. La question n'est donc pas d'écrire un moteur de workflow, mais de savoir **quel est le plus petit mécanisme qui rende « personne ne s'accorde seul une dérogation » vrai et prouvable**, sans bloquer l'urgence qu'il doit servir.

Chemin d'attaque à fermer en même temps : une validation fait connaître l'identifiant de la session à une seconde personne (l'approbateur). Or le Broker ne vérifiait pas que celui qui appelle `connect` est celui qui a demandé la session (limite connue depuis le MVP, inoffensive tant que seul le demandeur connaissait l'identifiant). Sans correctif, l'approbateur pourrait obtenir le ticket de connexion de la session qu'il vient d'approuver — et utiliser un break-glass qu'il n'a jamais demandé, sans détenir la politique de demande.

**Décision**
Une demande break-glass qui passe les verrous 1 à 3 d'ADR-0009 n'est plus accordée : elle est **mise en attente** jusqu'à ce qu'une *autre* personne l'approuve. Sept règles :

1. **Requise par défaut.** `BREAKGLASS_APPROVAL` vaut `required` quand il est absent ; `disabled` doit être demandé par son nom et le Broker l'annonce en avertissement ; toute autre valeur est fatale. La valeur zéro du service est « approbation requise » : un câblage oublié refuse plutôt que d'accorder seul (même principe qu'ADR-0008 et ADR-0010).
2. **Une demande en attente n'est pas une session.** Elle est enregistrée au statut `pending_approval` (statut prévu dès le doc 06 et resté inutilisé), avec une **échéance de décision** (`BREAKGLASS_APPROVAL_WINDOW_MINUTES`, 15 par défaut, entre 1 et 1440 ; hors bornes = fatal). `connect` refuse tout statut autre qu'`active` : une demande en attente, rejetée ou périmée ne s'ouvre pas. Passée l'échéance elle est `expired` (lecture paresseuse, comme les sessions). Événement d'audit `session.breakglass_requested` (succès) ; pas de `session.create` : rien n'a été accordé.
3. **Une autorité distincte pour approuver.** Politique RBAC sur la ressource `breakglass-approve:account:{accountId}` — refusé par défaut. Le préfixe diffère exprès de `breakglass:` : une politique `breakglass:*` (celle des demandeurs) ne couvre pas l'approbation. Détenir la politique de demande n'autorise pas à approuver, et réciproquement.
4. **Jamais soi-même.** L'approbateur et le demandeur sont comparés par **identifiant d'utilisateur** tiré du jeton vérifié, pas par rôle : quelqu'un qui détient les deux politiques ne s'approuve pas pour autant. Le rejet n'est soumis qu'à l'autorité d'approbation (renoncer à sa propre demande n'est pas une élévation).
5. **L'identité de l'approbateur vient du Gateway, jamais du corps.** `POST /sessions/{id}/approve` et `/reject` : le Gateway construit lui-même le corps (`decidedBy`, `actorRoles`) à partir du jeton vérifié et **écarte** celui du client ; les routes de session du Gateway deviennent une liste blanche (`GET|DELETE /sessions/{id}`, `POST …/connect|approve|reject`, `GET …/recording`) — toute autre est 404, de sorte qu'une route ajoutée au Broker n'est jamais relayée brute par défaut. Côté Broker, ces routes n'acceptent que l'identité du Gateway (ADR-0010).
6. **L'approbation est une décision, auditée avant d'agir, prise une seule fois.** À l'approbation : (a) la demande doit être en attente, non périmée, break-glass ; (b) la dérogation doit **encore** être permise (`BREAKGLASS_MAX_MINUTES` > 0 et durée demandée dans la limite d'aujourd'hui — couper la fonction ou la resserrer prend effet sur les demandes déjà en attente) ; (c) l'autorité d'approbation est vérifiée auprès de l'Authorization Service, **fail-closed** ; (d) `session.breakglass_approved` est écrit **avant** l'effet — si l'audit ne peut pas l'écrire, la demande reste en attente ; (e) le passage `pending_approval → active` est une **comparaison-échange atomique** (`SaveIfStatus`, un `UPDATE … WHERE status = 'pending_approval'`) : deux décisions simultanées (deux approbations, ou approbation et rejet) n'ont qu'un gagnant, l'autre reçoit 409. La **durée court à partir de l'approbation**, pas de la demande : l'attente ne la ronge pas. `decided_by` et `decided_at` gardent qui a décidé et quand. Un refus (soi-même, sans politique, dérogation coupée, durée hors limite) est audité (`session.breakglass_approved`, échec) ; le rejet laisse `session.breakglass_rejected` et la demande passe à `denied`.
7. **Seul le demandeur ouvre sa session.** `connect` exige que l'appelant (injecté par le Gateway, `callerId`) soit `requested_by` : un autre utilisateur, y compris l'approbateur, reçoit 403. Vaut pour **toutes** les sessions, pas seulement break-glass. Et la dérogation d'enregistrement n'est transmise au proxy que si la session a été approuvée (`decided_by` non vide) quand l'approbation est requise : activer l'approbation prend effet sur une session break-glass accordée avant, qui s'exécute alors sous « enregistrer ou refuser » (comme couper la fonction, ADR-0009).

Réponses : `200` décision prise ; `403` refus (soi-même, politique absente, dérogation coupée ou hors limite) ; `404` session inconnue ; `409` pas en attente / déjà décidée / périmée / pas une demande break-glass ; `503` une dépendance (Authorization, audit, base) ne répond pas — la décision n'a pas été prise, et la cause reste dans le journal du Broker, pas dans la réponse.

Mise en œuvre dans le Session Broker, pas dans un service nouveau : l'état d'une session est déjà là, le besoin est une transition gardée, pas un flux configurable. Schéma additif et idempotent : `duration_minutes`, `decided_by`, `decided_at`.

**Conséquences**
- (+) Ferme la limite « une seule personne suffit » d'ADR-0009 **par défaut** : sous `required`, aucun break-glass ne devient `active` sans l'approbation d'un second utilisateur distinct, porteur d'une politique d'approbation distincte, et sans que l'audit l'ait écrite.
- (+) Ferme au passage une limite générale : un utilisateur authentifié qui connaissait l'identifiant d'une session pouvait demander son ticket de connexion ; seul le demandeur le peut maintenant, pour toutes les sessions.
- (+) Sans rien changer à ADR-0009 : la dérogation reste une dérogation à l'enregistrement, sous ses six verrous ; l'approbation s'y ajoute, elle n'en remplace aucun.
- (+) Prouvé à quatre niveaux, mesuré : 19 tests du Broker (verrous, auto-approbation, audit avant d'agir, horloge, règles du jour, propriété du `connect`), 6 du magasin (dont six décisions concurrentes dont une seule gagne à chaque tour, 50 tours en mémoire et 10 en PostgreSQL), 9 HTTP (Broker et Gateway : identité du jeton et non du corps, liste blanche des routes), et 3 tests sur huit processus réels (`breakglass_approval_test.go`) ; 25 mutations sur 25 tuées.
- (−) **Aucune découverte des demandes en attente.** Il n'existe ni liste (`GET /sessions` est documenté mais pas implémenté) ni notification (le Notification Service n'existe pas) : l'approbateur doit recevoir l'identifiant de la session du demandeur ou de l'astreinte, puis peut relire la demande (`GET /sessions/{id}`) avant de décider. C'est une friction réelle pendant un incident. Priorité suivante. **Refermé par ADR-0012.**
- (−) **Deux comptes tenus par la même personne ne sont pas détectés** : la règle 4 compare des identifiants, pas des humains. L'hygiène des identités (un compte par personne, rôles disjoints, SCIM) est la défense ; le contrôle est de revue des politiques `breakglass-approve:*`. Deux personnes complices, ou un approbateur trop complaisant, restent possibles : une approbation à deux ne remplace pas la revue après l'incident, toujours **non implémentée** (v1.0, Workflow).
- (−) Un seul approbateur (pas de quorum à N) ; pas de commentaire sur la décision (l'audit ne porte pas de champ de détail) ; l'expiration d'une demande non décidée n'est **pas** auditée comme événement (pas de Scheduler pour le déclencher) — la demande, elle, l'est, et son statut se lit `expired`.
- (−) Une décision perdante dans une course (cross-réplica) laisse son événement d'audit (écrit avant la comparaison-échange, pour qu'aucun octroi ne soit jamais sans trace) : l'audit peut porter deux `session.breakglass_approved` pour une session dont `decided_by` nomme le gagnant. On préfère un événement en trop à un octroi sans événement.
- (−) La convention `breakglass-approve:account:*` est, comme celle d'ADR-0009, un nom et pas un type : un motif `*`, ou `breakglass*` (qui couvre `breakglass-approve:` **et** `breakglass:`), accorde les deux autorités. Les guides le disent.
- (−) `terminate` n'a toujours ni contrôle d'appartenance ni politique RBAC propre (un utilisateur authentifié qui connaît l'identifiant peut couper la session d'un autre) ; c'est un déni de service, pas une élévation, et il est consigné. **Levé par ADR-0017** : le demandeur, ou une politique `session-terminate:account:{id}` ; reste que terminer ne coupe pas la connexion déjà ouverte. **Levé par ADR-0018** : le proxy coupe les connexions et jette les tickets.
- (−) Changement de comportement pour qui avait activé le break-glass sous ADR-0009 : les demandes restent désormais en attente. `BREAKGLASS_APPROVAL=disabled` rétablit l'ancien comportement, et l'annonce.

**Alternatives envisagées**
- *Attendre le Workflow Service / l'Approval Engine (v1.0)* : rejeté — la dérogation la plus sensible resterait à une personne ; le mécanisme minimal tient dans une transition d'état, et le Workflow pourra le reprendre (quorum, étapes N+1, ticket obligatoire, fenêtre horaire).
- *Un service d'approbation séparé dès maintenant* : rejeté — une identité mTLS, un port, une base, un contrat de plus, pour une transition ; à réévaluer si les workflows se généralisent.
- *Exprimer « demandeur ≠ approbateur » dans le RBAC (ABAC)* : impossible aujourd'hui — l'Authorization Service ne juge que le rôle et la ressource, pas le sujet. Le contrôle vit dans le Broker, qui connaît les deux identités.
- *Lien ou jeton d'approbation envoyé au demandeur pour qu'il le transmette* : rejeté — un jeton porteur se transfère, et ne prouve pas *qui* approuve ; l'approbation est liée à une identité authentifiée.
- *Faire courir la durée dès la demande* : rejeté — une approbation tardive rognerait, voire annulerait, la durée accordée.
- *Approbation désactivable par service ou par compte* : rejeté — un seul interrupteur global, annoncé, plutôt qu'une exception par compte que l'on oublie.

## ADR-0012 — Break-glass : l'approbateur découvre les demandes en attente, et en est prévenu

**Contexte**
ADR-0011 a fermé « une seule personne suffit », mais l'a laissé inutilisable à l'heure où il compte : l'approbateur ne peut approuver que ce qu'il connaît, et il ne connaît l'identifiant d'une demande que si le demandeur le lui transmet — pendant un incident, par un canal que le bastion ne voit pas. La fenêtre de décision est de 15 minutes. Le contrat `GET /sessions` existe dans l'OpenAPI depuis le début (« liste les demandes/sessions de l'opérateur, ou toutes si administrateur ») sans avoir jamais été implémenté, et le Notification Service du doc 00 n'existe pas.

Deux questions de fond, plus délicates que la plomberie : (1) **qui a le droit de savoir** qu'une demande d'accès d'urgence existe — la liste ne doit pas devenir un moyen d'apprendre quels comptes sont sensibles, qui les demande et pourquoi ; (2) **que doit faire le bastion quand il ne peut pas prévenir** — une urgence ne doit pas dépendre de la disponibilité d'un service de messagerie.

**Décision**
Neuf règles.

1. **Une liste de ce que l'appelant peut décider, pas de ce qui existe.** `GET /sessions?status=pending_approval` renvoie les demandes que l'appelant pourrait approuver *maintenant*, selon le même prédicat que `approve` : demande en attente et non périmée ; l'appelant n'en est pas l'auteur ; sa politique `breakglass-approve:account:{id}` couvre le compte (Authorization Service) ; le break-glass est encore activé et la durée demandée tient dans la limite d'aujourd'hui. Qui n'a aucune autorité reçoit une liste **vide** (200), jamais 403 : la réponse ne dit pas s'il existe des demandes. Ses propres demandes n'y figurent pas (il les connaît ; `GET /sessions/{id}`).
2. **Un seul statut est servi pour l'instant.** Sans `status`, ou avec un autre statut : 400. Servir `active`, `denied`… exige un modèle de visibilité (« les siennes, et toutes pour un administrateur ») que le RBAC actuel — rôle et ressource, pas de sujet — ne sait pas exprimer ; on ne l'invente pas ici.
3. **L'identité vient du Gateway, la requête est reconstruite.** Le Gateway ne copie du client que `status`, `page` et `pageSize` ; `callerId` et `actorRoles` sont ceux du jeton vérifié. Un `callerId` ou un `actorRoles` écrit par le client n'arrive jamais au Broker.
4. **Fail-closed, jamais de liste partielle.** Le Broker interroge l'Authorization Service **une fois par compte distinct** (pas une fois par demande). Si une de ces questions échoue, la réponse est 503 générique : une liste dont manque une demande, sans le dire, est pire qu'une erreur — l'approbateur croirait qu'il n'y a rien à décider.
5. **Une borne, et elle est dite.** Le Broker lit au plus 100 demandes en attente (les plus proches de leur échéance d'abord) ; s'il y en avait davantage, la réponse porte `"truncated": true`. La pagination (`page`, `pageSize`, comme `GET /vault/accounts`) porte sur la liste **déjà filtrée**.
6. **Prévenir est un port, au mieux, jamais un contrôle.** Le Broker déclare un port `ApprovalNotifier` sans valeur de retour ; son adaptateur d'aujourd'hui est un webhook (`BREAKGLASS_NOTIFY_URL`). Trois événements — `breakglass.requested`, `breakglass.approved`, `breakglass.rejected` — émis **seulement quand la chose a eu lieu** (après l'enregistrement de la demande ; après la comparaison-échange gagnée) : jamais pour une demande refusée, ni pour une décision perdue ou refusée. L'envoi est asynchrone, sans nouvelle tentative, borné (5 s, 16 envois simultanés, le surplus est abandonné et journalisé) ; **un échec ne change rien** : ni la demande, ni la décision, ni le code de retour. L'urgence ne dépend pas de la messagerie ; la liste est le filet.
7. **Le message désigne, il ne raconte pas.** Il porte l'événement, l'identifiant de la session, du compte et du demandeur, la durée, l'échéance, et un texte lisible par un webhook de type Slack — dont les identifiants sont assainis (voir la règle 9). **Il ne porte ni la justification ni rien d'issu de la cible** : le détail s'obtient en s'authentifiant, par la liste, et seulement si l'on a l'autorité. L'URL du webhook est un **secret** (celles de Slack ou de Teams en contiennent un) : elle n'est jamais journalisée — on n'écrit que son schéma et son hôte — et les erreurs de transport sont purgées de l'URL avant d'être écrites. https est exigé, sauf vers une adresse de boucle locale (développement) ; une URL avec identifiants, sans hôte, d'un autre schéma, ou qui ne se lit pas est **fatale au démarrage** ; les redirections ne sont pas suivies.
8. **Pas de canal, pas de notification, et le Broker le dit.** `BREAKGLASS_NOTIFY_URL` vide : aucune notification (défaut) ; au démarrage, si le break-glass est actif avec approbation requise, le Broker annonce que les approbateurs devront consulter la liste.
9. **Ce que le demandeur écrit n'arrive jamais tel quel dans un message lu par des tiers.** `targetAccountId` est de la saisie du demandeur, et il se retrouve dans la liste et dans le canal. Une demande de break-glass dont l'identifiant de compte n'est pas un identifiant (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`) est refusée avant tout autre contrôle, donc avant d'avoir interrogé qui que ce soit ; et le texte du webhook ne reproduit que `[A-Za-z0-9._:-]` (64 caractères au plus, le reste devient « ? ») : ni lien, ni mention, ni saut de ligne ne peut passer. Deux défenses, parce que la seconde protège aussi contre un identifiant déjà en base.

Réponses de `GET /sessions` : `200` `{items, page, pageSize, totalItems}` (+ `truncated` seulement s'il est vrai) ; `400` statut absent ou non servi ; `403` appelant non identifié ; `503` une dépendance ne répond pas (corps générique, cause dans le journal du Broker).

Mise en œuvre dans le Session Broker, qui détient déjà la demande et la décision ; schéma additif (un index partiel sur les demandes en attente, idempotent) ; aucune nouvelle identité mTLS — la règle `/sessions` ← `api-gateway` couvre la route, et le webhook sort du maillage.

**Conséquences**
- (+) La friction que consignait ADR-0011 est levée : l'approbateur voit ce qu'il peut décider, avec la justification, sans qu'on lui transmette un identifiant ; et un canal peut le prévenir sans qu'il ait à scruter.
- (+) La liste n'est pas un oracle : un appelant sans autorité, un demandeur et un tiers voient la même chose — rien — et la liste ne montre jamais ce que `approve` refuserait pour une raison qui tient à l'appelant ou à la règle du jour.
- (+) Une messagerie en panne, lente, ou hostile ne bloque et ne retarde aucune demande, aucune décision : c'est prouvé en la rendant indisponible, puis lente, sur processus réels.
- (+) Le secret de l'URL du webhook ne fuit ni dans le journal de démarrage ni dans celui d'une erreur de transport.
- (+) Un demandeur ne peut pas faire écrire sa prose dans le canal des approbateurs : un identifiant de compte qui contient une mention, un lien ou un saut de ligne est refusé à la demande, et assaini dans le message s'il était déjà là.
- (+) Mesuré : 69 mutations — le contrôle d'autorité de la liste, l'exclusion de ses propres demandes, la limite de durée du jour, le « une question par compte », le refus d'une dépendance muette, la borne et son drapeau, la pagination, l'ordre et le bord d'échéance dans les deux magasins, chaque événement de notification et son absence sur une décision perdue, chaque garde de l'URL (https, identifiants, redirections, journal), l'asynchronisme et la borne des envois, la reconstruction de la requête au Gateway, l'arrêt du Broker sur une URL inutilisable — **toutes tuées par un test qui échoue pour la bonne raison** (quatre mutants mal formés — dont un qui « survivait » en plantant le processus — et un test qui se bloquait au lieu d'échouer ont été corrigés en route ; voir NOTES_SANDBOX).
- (−) **Aucune nouvelle tentative.** Une notification perdue est perdue ; la liste reste le filet. Pas de journal de livraison dans l'audit : un échec s'écrit dans le journal du Broker, la demande, elle, est toujours auditée.
- (−) **Un seul canal, sans routage par personne.** Qui est prévenu, c'est qui lit ce canal — le Broker ne connaît pas les approbateurs, et l'appartenance au canal est hors d'OpenBastion. Les membres du canal apprennent qu'une demande existe, pour quel compte et de qui, sans avoir forcément le droit de l'approuver ; ces identifiants sont ceux du message, pas la justification.
- (−) **Le message n'est pas signé** : le destinataire n'a, pour croire qu'il vient du Broker, que le secret de l'URL. Une signature HMAC est possible sans changer le contrat ; elle n'est pas faite.
- (−) **Un demandeur qui détient les deux politiques (`breakglass:` sur le compte et `session:create`) peut noyer la liste et le canal** de demandes : la borne à 100 est signalée par `truncated`, pas empêchée. Une limite de demandes en attente par demandeur est la défense ; elle n'est pas faite.
- (−) Seul `status=pending_approval` est servi ; le reste de `GET /sessions` du doc 05 (« les siennes », « toutes pour un administrateur ») ne l'est toujours pas.
- (−) Les rôles voyagent dans une chaîne de requête séparée par des virgules, comme pour les routes du Vault et du Recorder : un nom de rôle qui contient une virgule serait lu comme deux rôles. Les noms de rôles sont posés par l'administrateur ; ce n'est pas nouveau, c'est consigné.
- (−) Avec `INTERNAL_TLS=disabled`, un appelant interne peut écrire `callerId` et `actorRoles` à sa guise (comme pour `approve`).

**Alternatives envisagées**
- *Implémenter tout `GET /sessions`* : rejeté — il faut d'abord décider qui voit quoi (« les siennes, toutes pour un administrateur »), et le RBAC ne parle pas de sujet.
- *Un Notification Service dès maintenant* : rejeté — un service, une identité, une base pour un envoi ; le port est la couture, un service le remplacera en v1.0 sans toucher le Broker.
- *Notifier de façon synchrone et refuser la demande si la notification échoue* : rejeté — ferait dépendre l'accès d'urgence d'une messagerie ; c'est exactement la dépendance qu'ADR-0009 retire pour le recorder.
- *Nouvelles tentatives avec file persistante* : rejeté pour l'instant — une file à garantir (et à purger) pour un message dont la liste est le filet.
- *Mettre la justification dans le message* : rejeté — elle part dans un canal tiers, lu par des gens qui n'ont pas l'autorité de la lire, et conservée par lui.
- *Notifier chaque approbateur par son adresse* : rejeté — suppose un annuaire des approbateurs que ni le Broker ni l'Authorization Service ne possèdent (l'Authorization Service répond « ce rôle a-t-il ce droit ? », pas « qui a ce droit ? »).
- *Flux (SSE, WebSocket) vers la console* : rejeté — la console n'existe pas ; la liste est ce qu'elle appellera.
- *Servir la liste à tous les utilisateurs authentifiés, avec les droits en champ* : rejeté — ce serait révéler à tous les demandes d'urgence, leurs auteurs et leurs motifs.

## ADR-0013 — Break-glass : un plafond de demandes en attente par demandeur, et un message signé

**Contexte**
ADR-0012 a consigné deux limites que rien n'empêche. (1) Qui détient `session:create` et `breakglass:` sur un compte peut déposer demandes sur demandes : chacune apparaît dans la liste des approbateurs et déclenche une notification. La borne de lecture à 100 est *signalée* (`truncated`), pas *empêchée* — et une liste noyée est une liste où l'approbateur ne trouve plus la vraie demande, pendant un incident, dans une fenêtre de 15 minutes. (2) Le message du webhook n'est pas signé : le destinataire n'a, pour croire qu'il vient du Broker, que le secret de l'URL — un secret qui figure dans la configuration de l'émetteur *et* du récepteur, et qui, pour les récepteurs génériques, ne dit rien de l'intégrité du corps.

Deux questions de fond : (1) **quel plafond, et où le tenir** pour qu'il protège la liste sans jamais empêcher une urgence légitime ni donner à un tiers un moyen de bloquer quelqu'un d'autre ; (2) **ce qu'une signature prouve et ne prouve pas**.

**Décision**
Sept règles.

1. **Un plafond par demandeur, pas global.** Un demandeur ne peut avoir que `N` demandes break-glass *en attente et non périmées* à la fois (`BREAKGLASS_MAX_PENDING_PER_REQUESTER`, défaut **3**, de 1 à 100). Au-delà, la demande est refusée. Il est **par demandeur** : le quota de l'un n'est jamais consommé par un autre, donc personne ne peut empêcher *autrui* de demander un accès d'urgence en remplissant une file commune. Un plafond global est rejeté pour cette raison : il transformerait un abus en déni de service sur l'urgence.
2. **Il n'y a pas de valeur « sans plafond ».** Le défaut est le plus strict qui reste utilisable, une valeur illisible ou hors bornes est fatale au démarrage, et un Broker construit à la main sans réglage applique le défaut (le zéro-valeur est strict, comme pour la double validation). Il ne s'applique que lorsque l'approbation est requise : sans approbation (`BREAKGLASS_APPROVAL=disabled`) il n'existe pas de file à noyer.
3. **Refus net et audité.** Un refus pour plafond est `429` (`too many break-glass requests are waiting for a decision`, avec la limite, qui est celle du demandeur lui-même), audité comme les autres refus (`session.breakglass_requested`, `success=false`) — un volume de refus est ce qu'un relecteur cherche. Il ne notifie personne et n'entre pas dans la liste.
4. **Atomique.** Compter puis enregistrer laisse deux requêtes simultanées passer chacune sous le plafond. L'enregistrement d'une demande en attente est donc une opération du magasin (`SaveIfUnderPendingLimit`), atomique : en mémoire sous verrou, en PostgreSQL dans une transaction qui prend un verrou consultatif propre au demandeur. Un contrôle préalable (le même décompte, avant l'audit) garde le cas courant exact — le refus est audité *avant* d'avoir écrit « demandé » — et l'opération atomique ferme la course ; si elle perd, la demande est refusée et un second événement `success=false` suit le premier pour la même session (le dernier fait foi, comme pour une décision perdue, ADR-0011).
5. **Un message signé, si l'on donne un secret.** `BREAKGLASS_NOTIFY_SECRET` (au moins 32 octets ; `openssl rand -hex 32`) ajoute deux en-têtes à chaque envoi : `X-OpenBastion-Timestamp` (secondes Unix) et `X-OpenBastion-Signature: v1=<hex>`, où `<hex>` est HMAC-SHA256, avec ce secret, de `<horodatage>.<corps exact>`. Le récepteur recalcule sur les octets reçus, compare en temps constant et refuse un horodatage trop éloigné (5 minutes est une valeur raisonnable). Sans secret, aucun en-tête, et le Broker l'annonce au démarrage (« signed » ou « not signed »).
6. **Un secret mal posé est fatal, et n'est jamais écrit.** Secret trop court, ou secret sans URL (il ne signerait rien : l'opérateur croirait protéger un canal qui n'existe pas) : le Broker refuse de démarrer, sans répéter la valeur. Le secret n'est jamais journalisé, ni dans un message, ni dans une erreur ; comme l'URL, il se pose dans un Secret Kubernetes, pas une ConfigMap.
7. **Ce que la signature prouve, et ne prouve pas.** Elle prouve que le corps vient de qui détient le secret (le Broker) et n'a pas été modifié ; avec l'horodatage, qu'il est récent. Elle ne rend pas le message confidentiel (le canal l'est, ou ne l'est pas), n'empêche pas un rejeu *dans la fenêtre de tolérance* (un doublon de notification, pas un accès), et **n'est vérifiée que par un récepteur qui le fait** : un webhook entrant de Slack ou de Teams ignore ces en-têtes — pour eux, le secret de l'URL reste la seule protection.

Réponses : `POST /sessions` avec `breakGlass: true` ajoute `429`. Schéma inchangé (le décompte lit la table des sessions ; il existe déjà un index sur `requested_by` et l'index partiel des demandes en attente d'ADR-0012).

**Conséquences**
- (+) La liste et le canal ne sont plus noyables par un demandeur seul : il tient au plus `N` places, et le décompte est exact sous 40 demandes simultanées, y compris sur deux réplicas du Broker (deux pools de connexions sur la même base).
- (+) Personne ne peut empêcher *un autre* de demander : le quota est celui du demandeur.
- (+) Un récepteur qui vérifie la signature sait que le message vient du Broker et qu'il est intact ; un secret trop faible ou orphelin n'arrive pas en production.
- (+) Mesuré : 63 mutations, toutes tuées — plafond ignoré ou d'une place de trop (service, mémoire, PostgreSQL), plafond infini, quota appliqué sans approbation ou demandé avant l'autorité, décompte en panne accepté ou présenté comme un plafond atteint, verrou retiré ou posé par demande, demande perdante non auditée / acceptée / annoncée, `429` devenu `403` (Broker et Gateway), cause d'un `503` montrée, limite ou secret invalide non fatal, signature dont l'horodatage, le séparateur, le corps, la clé ou la version change, secret répété dans une erreur ou un journal. La première passe en avait laissé survivre une — « le quota s'applique sans approbation » — que ni le décompte (toujours 0) ni les tests d'alors ne distinguaient : deux tests de plus l'ont tuée. L'extrait de vérification du guide administrateur a été exécuté contre une vraie livraison.
- (−) **Il faut plusieurs identités pour noyer encore** : un attaquant qui détient les accès de `K` demandeurs peut tenir `K × N` places. Le plafond borne l'abus d'une identité, pas une compromission de dizaines d'identités ; la borne de 100 et `truncated` restent le signal.
- (−) **Un demandeur peut s'enfermer lui-même** pendant la fenêtre de décision (15 minutes) : s'il remplit son quota avec des demandes inutiles, il ne peut plus en déposer de vraie avant qu'elles expirent ou soient décidées. C'est le prix d'un quota par identité ; un demandeur n'a pas de moyen de retirer sa demande, sauf à détenir aussi l'autorité d'approuver (ADR-0011).
- (−) **Une personne avec deux comptes a deux quotas** (même limite que la double validation : la règle compare des identifiants, pas des humains).
- (−) **Les tentatives refusées ne sont pas limitées en débit** : chacune écrit une ligne `denied` et un événement d'audit (Full Auditability). Cela ne touche ni la liste ni le canal, mais ce n'est pas borné. **Traité pour `POST /sessions` par l'ADR-0014** : un budget par identité, au Gateway, avant que la demande n'atteigne le Broker.
- (−) **Un seul secret, sans recouvrement** : changer `BREAKGLASS_NOTIFY_SECRET` exige un redémarrage du Broker, et le récepteur doit accepter les deux secrets le temps du changement (il peut essayer les deux ; le Broker n'en signe qu'un).
- (−) **Pas de protection contre le rejeu au-delà de la tolérance du récepteur**, et aucun identifiant de livraison : un récepteur qui veut dédupliquer le fait sur `sessionId` + `event`.
- (−) Rien n'a été vérifié contre un vrai récepteur tiers : les tests vérifient la signature avec un code de récepteur écrit à part, à partir de la description ci-dessus.

**Alternatives envisagées**
- *Un plafond global de demandes en attente* : rejeté — un demandeur malveillant le remplirait pour que les demandes légitimes soient refusées : l'abus deviendrait un déni de service sur l'urgence.
- *Plafond par compte privilégié* : rejeté — il laisserait un seul demandeur noyer la liste en visant plusieurs comptes ; et un incident sur un compte ne doit pas être gêné par le bruit d'un autre demandeur sur ce même compte.
- *Plafond « mou » (compter puis enregistrer, sans verrou)* : rejeté — une course le contourne, et la course est exactement ce qu'un script d'abus produit.
- *Un plafond désactivable (`0` = illimité)* : rejeté — un interrupteur de plus pour retrouver l'abus, et il aurait fallu un mode faible de plus à annoncer.
- *Limitation de débit générique sur `POST /sessions`* : pas ici — c'est le bon outil contre les refus en rafale, mais un autre sujet (et un autre composant : le Gateway) ; consigné.
- *Signer avec une clé asymétrique* : rejeté pour l'instant — un secret partagé suffit entre un émetteur et un récepteur que le même administrateur configure, et le HMAC est ce que savent vérifier tous les récepteurs ; une clé publique serait pertinente le jour où le Notification Service servira plusieurs récepteurs.
- *Un identifiant de livraison et des nouvelles tentatives* : rejeté — ADR-0012 a fait de la notification un message au mieux sans nouvelle tentative ; un identifiant de livraison n'a de sens que s'il y en a.

## ADR-0014 — Une limitation de débit par identité sur les demandes de session, au Gateway

**Contexte**
ADR-0013 a consigné une limite que rien n'empêche : les refus ne sont pas limités en débit. Une requête `POST /sessions` refusée — plafond atteint, politique absente, justification trop courte — n'est pas gratuite : le Broker écrit une ligne `denied` dans `sessions` et un événement d'audit (Full Auditability, doc 00 §2), et interroge l'Authorization Service. Un détenteur de jeton, même sans aucun droit, peut donc faire écrire au Broker autant de lignes et d'événements que le réseau lui laisse envoyer.

Le Gateway limite déjà, par adresse IP. En lisant ce limiteur pour y adosser le nouveau, j'ai **mesuré** trois défauts (ils n'ont pas été supposés) :
1. **Les unités mentent.** `NewRateLimiter(60, time.Minute)` est une rafale de 60 puis **un** jeton par minute (le second paramètre est le temps pour accumuler *un* jeton) : 10 requêtes acceptées sur 10 minutes de requêtes régulières, et non « 60 par minute » comme l'écrit `main.go`. Le login, `(5, time.Minute)`, est une rafale de 5 puis une par minute, et non « 5 par minute ».
2. **Rien n'est jamais évincé.** Un seau par clé, gardé pour toujours : 100 000 clés distinctes laissent près de 98 000 seaux en mémoire, toujours là 48 heures plus tard. Sur `/auth/login`, public et dont la clé est l'IP, c'est une fuite de mémoire à la portée d'un attaquant.
3. **La clé est l'adresse du pair TCP.** Le listener public est en HTTP derrière Traefik, où le TLS se termine : `RemoteAddr` est alors celle du reverse proxy **pour tout le monde**. Tous les utilisateurs partagent un seau, et l'un d'eux peut en épuiser la rafale de login pour tous les autres.

Deux questions : (1) **quoi limiter, avec quelle clé**, pour borner les écritures du Broker sans donner à quiconque un moyen de bloquer les autres ; (2) **que faire du limiteur existant**, dont le nouveau dépend.

**Décision**
Sept règles.

1. **La clé est l'identité vérifiée, pas l'adresse.** Le budget de `POST /sessions` est celui de l'utilisateur — le `UserID` que rend la vérification du jeton —, appliqué **après** l'authentification. Ni l'IP (la même pour tous derrière l'arête), ni le corps (le demandeur l'écrit), ni le nom d'utilisateur. Un utilisateur ne peut pas épuiser le budget d'un autre.
2. **On compte les tentatives, pas les succès, et avant tout travail.** Chaque `POST /sessions` d'un jeton valide coûte un jeton du seau, acceptée ou non, corps lisible ou non : le contrôle précède la lecture du corps. Une requête refusée ici n'atteint jamais le Broker : **elle n'écrit ni ligne ni événement d'audit**.
3. **Un seau à jetons, des défauts stricts, pas d'« illimité ».** Rafale `SESSION_REQUEST_BURST` (défaut **10**, de 1 à 1000), débit soutenu `SESSION_REQUEST_RATE_PER_MINUTE` (défaut **6**, de 1 à 600). Une valeur invalide empêche le Gateway de démarrer, en nommant la variable. Un Gateway construit à la main applique les défauts (le zéro-valeur est strict). Au démarrage, le Gateway annonce ce qu'il applique.
4. **`429`, avec un `Retry-After` vrai.** Le délai est ce qui manque pour accumuler le prochain jeton, arrondi à la seconde supérieure, au moins 1. Le message est distinct de celui du plafond du Broker (ADR-0013) : un client sait si c'est le *débit* (réessayer dans quelques secondes) ou le *nombre en attente* (attendre une décision).
5. **Visible, mais borné : le journal, pas l'audit.** Un refus laisse une ligne dans le journal du Gateway — **une par épisode de refus et par utilisateur**, jamais une par requête refusée : identifiant et limite. Il ne laisse rien dans l'audit : le Gateway n'est pas un émetteur d'audit autorisé (ADR-0010), et un événement par tentative refusée recréerait ce qu'on cherche à borner.
6. **On répare le limiteur dont on dépend, sans jamais l'affaiblir.** (a) Les seaux inactifs depuis assez longtemps pour être pleins sont évincés : un seau plein équivaut à un seau neuf, donc aucune décision ne change, et la mémoire cesse de croître avec le temps. (b) Le limiteur des requêtes authentifiées reçoit les unités que son commentaire promettait (60 par minute, soutenu). (c) Le limiteur du login **garde** son comportement réel — rafale de 5, puis une par minute, plus strict que ce qui était écrit — et ce sont le commentaire et la documentation que l'on corrige : on ne relâche pas une protection contre la force brute pour qu'elle ressemble à son commentaire. (d) Les trois limiteurs disent leur vrai `Retry-After`.
7. **Par processus.** Le seau vit dans la mémoire du Gateway : N réplicas accordent N fois le budget. Un état partagé (Redis, doc 00 §10) est un autre sujet.

Réponses : `POST /sessions` ajoute le `429` du Gateway, avec `Retry-After`. Aucun changement du Broker ni du schéma.

**Conséquences**
- (+) Un détenteur de jeton, même sans droit, ne fait plus écrire au Broker que le débit de son seau : 10 lignes en rafale, puis 6 par minute (8 640 par jour au plus), au lieu de « ce que le réseau laisse passer ».
- (+) Le budget est celui de l'identité : le bruit d'un utilisateur ne retire rien aux autres, même derrière un reverse proxy qui masque toutes les adresses.
- (+) La mémoire du limiteur cesse de croître avec le temps, sans qu'aucune décision change.
- (+) **Mesuré** : 50 mutations du limiteur, du Gateway et de sa configuration, 50 détectées (clé sur l'adresse ou le corps, contrôle après la lecture du corps, refusé qui atteint le Broker, unités à l'envers, `Retry-After` faux, éviction trop précoce ou sans marge, login relâché…) ; 16 tests unitaires et 4 d'intégration sur processus réels ajoutés (450 unitaires avec base, 52 PostgreSQL, 33 d'intégration au total). Une de ces mutations est détectée par un dépassement de délai plutôt que par une assertion.
- (−) **Le titulaire légitime d'un jeton volé peut être privé de son budget** : si l'attaquant envoie sans arrêt, chaque jeton qui se reforme (un toutes les 10 secondes) va à qui arrive le premier. Le remède est de révoquer le jeton, pas de toucher au limiteur ; la ligne de journal par épisode est là pour le voir. Même nature que l'auto-verrouillage d'ADR-0013, en beaucoup plus court (10 secondes, pas 15 minutes).
- (−) **Seul `POST /sessions` est couvert.** `approve`, `reject`, `connect`, `terminate` et la liste des demandes en attente ne sont limités que par le limiteur par IP, qui n'est pas fait pour cela et n'est pas juste derrière une arête. À traiter. *(Traité par ADR-0016 pour `approve`, `reject` et `connect`, après mesure ; `terminate` et les lectures ne sont pas couverts, et ce choix est motivé là.)*
- (−) **Les refus de débit ne sont pas dans l'audit**, seulement dans le journal du Gateway.
- (−) **Plusieurs identités, plusieurs budgets** : K jetons compromis donnent K fois le budget. Et **par processus** : N réplicas, N fois.
- (−) **Le limiteur par IP reste faux derrière l'arête** : tous les utilisateurs partagent le seau de l'adresse de Traefik — et, avec les unités corrigées, ce sont 60 requêtes authentifiées par minute pour **toute la plateforme**. Le seau du login, une rafale de 5, peut être épuisé par un seul pour tous. Corriger demande de décider à qui faire confiance pour `X-Forwarded-For` (une confiance mal placée permet de forger sa clé) : décision à part, **non prise ici**, consignée — **prise par l'ADR-0015**.
- (−) Le correctif des unités des requêtes authentifiées **relâche en pratique** une limite qui, telle qu'elle était codée, se vidait en 60 requêtes pour ne plus laisser passer qu'une par minute. C'est ce que la documentation disait ; ce n'est pas ce que le code faisait.

**Alternatives envisagées**
- *Garder la clé par IP* : rejeté — derrière l'arête elle est la même pour tous : un seul utilisateur épuiserait le budget de tous, et la limite ne dirait rien de qui abuse.
- *Ne limiter que les refus* : rejeté — le Gateway ne sait pas ce que le Broker refusera ; et une limite qui ne compte que les refus laisse écrire autant de succès qu'on veut.
- *Un budget global pour `POST /sessions`* : rejeté — une arme : un utilisateur le viderait pour que les autres soient refusés, y compris en urgence.
- *Auditer chaque refus de débit* : rejeté — recrée le flux d'écritures qu'on veut borner, et le Gateway n'est pas un émetteur d'audit autorisé (ADR-0010).
- *Une fenêtre glissante exacte (journal des instants)* : rejeté — plus de mémoire par identité pour une précision sans objet ici ; le seau à jetons est déjà celui du Gateway.
- *Relâcher le limiteur du login pour qu'il fasse « 5 par minute »* : rejeté — cela affaiblirait une protection contre la force brute pour que le code ressemble à son commentaire.
- *Un état partagé (Redis) dès maintenant* : rejeté pour l'instant — un composant à déployer et à rendre disponible, pour un risque que le budget par processus borne déjà ; consigné.

## ADR-0015 — Qui est « le client » derrière l'arête : une confiance à `X-Forwarded-For` limitée aux proxys déclarés, et des limites par adresse réglables

**Contexte**
ADR-0014 a laissé deux limites écrites : la limite **par adresse** du Gateway est fausse derrière Traefik, et ses valeurs ne se règlent pas. Le Gateway clé deux limiteurs sur `clientIP(r)`, l'hôte de `r.RemoteAddr` : le **login** (rafale de 5, puis une par minute) et les **requêtes authentifiées** (rafale de 60, puis 60 par minute), ce dernier avant même que le jeton soit regardé. Le listener public est en HTTP derrière Traefik, où le TLS se termine : l'adresse du pair est celle de Traefik **pour tout le monde**. Conséquences déjà consignées : un seul seau pour toute la plateforme (60 requêtes authentifiées par minute en tout), et une rafale de login qu'un seul utilisateur peut épuiser pour tous.

L'évidence est de lire `X-Forwarded-For`. Mais cet en-tête est écrit par **qui veut** : un client peut l'envoyer lui-même, et un limiteur qui prend la première valeur offre à l'attaquant une clé neuve à chaque requête — c'est-à-dire qu'il **supprime** la protection contre la force brute qu'il devait fournir. La question n'est donc pas « lire l'en-tête ou non » mais **la parole de qui on prend**. Et aucun fichier de déploiement Traefik n'existe encore dans le dépôt (`deploy/*` est vide) : la règle ne peut vivre que dans le Gateway et dans les guides.

Deux questions : (1) **comment trouver l'adresse du vrai client sans la laisser choisir par lui** ; (2) **que faire des valeurs figées des deux limiteurs**, qui devenaient par client réel et non plus par plateforme.

**Décision**
Sept règles.

1. **La confiance se déclare, par adresse de pair.** `TRUSTED_PROXY_CIDRS` liste (séparés par des virgules) les adresses ou réseaux CIDR des proxys inverses devant le Gateway. **Par défaut, personne n'est de confiance** : la clé est l'adresse du pair, comme aujourd'hui, et le Gateway annonce au démarrage ce qu'il fait. Un en-tête n'est lu que si le **pair TCP immédiat** est dans cette liste ; venant de tout autre pair, il est ignoré.
2. **On remonte la chaîne par la droite et on s'arrête au premier inconnu.** Seul `X-Forwarded-For` est lu (plusieurs lignes de l'en-tête sont lues comme une seule, dans l'ordre). Du dernier élément vers le premier : une adresse de confiance est un saut de plus à franchir ; la **première adresse qui n'est pas de confiance est le client**. La partie gauche — celle qu'un client écrit — n'est jamais lue tant qu'un élément non fiable plus à droite l'arrête.
3. **Au moindre doute, la clé est celle du pair — jamais une valeur choisie par le client.** Pair de confiance sans en-tête, élément illisible rencontré, chaîne de plus de 32 sauts, tous les éléments de confiance : la clé est l'adresse du pair, c'est-à-dire exactement le comportement d'aujourd'hui, pas un comportement plus faible.
4. **Les clés sont normalisées.** Une adresse IPv4 écrite en IPv6 (`::ffff:a.b.c.d`) devient l'IPv4 ; une adresse IPv6 est ramenée à son **/64**, car un seul abonné en possède 2⁶⁴ et un seau par adresse lui donnerait une clé neuve à volonté ; la zone (`%eth0`) et le port (`ip:port`, `[ipv6]:port`) sont retirés. La même normalisation vaut pour le pair et pour le client.
5. **Une configuration douteuse empêche de démarrer.** Entrée vide (`a,,b`), texte qui n'est ni adresse ni CIDR, préfixe hors bornes, **bits d'hôte non nuls** (`192.168.1.5/24` : le préfixe visé est ambigu et une confiance élargie sans le dire est le mauvais sens d'erreur), et **tout réseau de longueur 0** (`0.0.0.0/0`, `::/0` : faire confiance à tout pair revient à laisser chacun choisir sa clé) arrêtent le Gateway, en nommant la variable et l'entrée. Il n'existe pas de valeur « tout le monde ». Les entrées répétées sont acceptées.
6. **Les quatre valeurs figées deviennent réglables, avec des défauts qui sont ce que le code fait vraiment, et des bornes.** `CLIENT_LOGIN_BURST` (défaut **5**, de 1 à 100) et `CLIENT_LOGIN_RATE_PER_MINUTE` (défaut **1**, de 1 à 60) ; `CLIENT_REQUEST_BURST` (défaut **60**, de 1 à 10000) et `CLIENT_REQUEST_RATE_PER_MINUTE` (défaut **60**, de 1 à 6000). Pas d'« illimité » ; valeur invalide fatale en nommant la variable ; annonce au démarrage. Les défauts reproduisent à l'identique les limiteurs de l'ADR-0014 : rien n'est relâché, ni le login, ni le reste, tant qu'on ne le demande pas **par son nom**.
7. **Les refus par adresse ne sont pas journalisés ligne à ligne.** Contrairement au budget par utilisateur (ADR-0014), dont la clé est une identité authentifiée donc bornée, la clé d'adresse peut tourner librement pour qui possède beaucoup d'adresses : une ligne par épisode deviendrait une ligne par requête. Le refus est visible dans le journal d'accès de l'arête, qui connaît la vraie adresse.

Ni les réponses, ni le schéma, ni les autres services ne changent. Ce que le Gateway transmet en amont n'est pas touché : il ne forge ni ne propage d'adresse cliente.

**Conséquences**
- (+) Avec `TRUSTED_PROXY_CIDRS` réglé sur l'arête, **chaque client réel a son seau** : l'un ne peut plus épuiser la rafale de login des autres, et les 60 requêtes authentifiées par minute sont par client, non par plateforme.
- (+) **Forger l'en-tête ne rapporte rien** : d'un pair non fiable, il est ignoré ; derrière un pair fiable, les éléments de gauche ne sont jamais lus tant que l'adresse que le proxy a ajoutée à droite est inconnue de la liste.
- (+) Les limites se règlent sans toucher au code, avec des bornes, sans « illimité ».
- (+) **Mesuré** : 66 mutations de la résolution d'adresse, de la lecture de la configuration, des limiteurs, du Gateway et de son câblage — 65 détectées, 1 équivalente (une confiance `nil` qui répond « oui » saute tous les éléments et laisse la clé au pair) ; 13 tests unitaires et 4 d'intégration sur processus réels ajoutés (463 unitaires avec base, 52 PostgreSQL, 37 d'intégration au total), dont un attaquant qui se connecte depuis `127.0.0.2` en écrivant l'adresse d'un autre et n'épuise que sa propre rafale. Cinq mutations ont survécu à la première passe : quatre étaient de vraies lacunes de tests, comblées.
- (−) **Tant que l'opérateur n'a pas réglé `TRUSTED_PROXY_CIDRS`, rien ne change** : toute la plateforme partage encore un seau, et l'annonce du démarrage est la seule trace. Choisi plutôt que de deviner : un défaut qui ferait confiance aux réseaux privés ferait confiance à tout pod du cluster.
- (−) **La confiance est celle de l'opérateur.** Un réseau trop large (tout un VPC) laisse n'importe quel hôte qu'il contient choisir sa clé ; seule la longueur 0 est refusée. Et le proxy doit **ajouter l'adresse dont il a reçu la connexion** à `X-Forwarded-For`, comme le font les proxys usuels : un proxy qui transmet l'en-tête du client sans rien ajouter rend la valeur forgeable par le client à travers lui.
- (−) **Traefik n'a pas été essayé.** Les tests tiennent le rôle du proxy ; la configuration de `forwardedHeaders` de l'arête (ne pas croire les `X-Forwarded-*` d'un client non fiable) est un prérequis documenté, non vérifié ici. L'algorithme est choisi pour ne pas dépendre de ce détail — que Traefik écrase l'en-tête ou y ajoute son pair, la clé est la même — mais cela reste à voir sur un vrai déploiement.
- (−) **Une adresse n'est pas une personne** : derrière un NAT d'entreprise ou d'opérateur, de nombreux utilisateurs partagent une adresse et un seau, même bien résolue. À l'inverse, un attaquant qui possède beaucoup d'adresses obtient beaucoup de seaux : la limite par adresse ne borne pas une force brute **distribuée** (aucune limite par compte n'est ajoutée ici).
- (−) **Le /64 IPv6 est un choix, non réglable** : des utilisateurs d'un même /64 (un réseau local) partagent un seau ; un attaquant qui possède plusieurs /64 en a plusieurs.
- (−) **Par processus**, comme ADR-0014 : N réplicas, N fois le budget.
- (−) **Les refus par adresse ne sont ni dans l'audit ni dans le journal du Gateway.**
- (−) Les défauts n'ont pas été éprouvés sur un usage réel ; ils reproduisent ceux de l'ADR-0014.

**Alternatives envisagées**
- *Prendre la première adresse de `X-Forwarded-For`* : rejeté — c'est celle que le client écrit : une clé neuve par requête supprime la limite de login.
- *Lire l'en-tête dès qu'il est présent* : rejeté — même défaut, avec l'accès direct au Gateway en plus.
- *Faire confiance par défaut aux réseaux privés* : rejeté — tout pod compromis du cluster choisirait sa clé, et un défaut qui devine un réseau est un défaut faux dans certains déploiements.
- *Un nombre fixe de proxys à sauter (compter à partir de la droite)* : rejeté — il fait confiance à une **position**, pas à un qui ; il se casse en silence quand la chaîne change de longueur.
- *`X-Real-IP` ou `Forwarded` (RFC 7239)* : rejeté pour l'instant — un seul en-tête à analyser, une seule règle à auditer.
- *Le protocole PROXY entre Traefik et le Gateway* : écarté — il évite les en-têtes mais change le listener et demande un arrêt côté arête ; décision à part, non essayée.
- *Une clé IPv6 par adresse complète* : rejeté — rotation gratuite à l'intérieur d'un /64.
- *Remplacer la limite par adresse par une limite par compte de login* : rejeté ici — protection d'une autre nature (verrouillage d'un compte par un tiers) ; à traiter à part.

## ADR-0016 — Un budget par identité sur les actions de session qui écrivent à chaque appel (`approve`, `reject`, `connect`)

**Contexte**
ADR-0014 a mis un budget par identité sur `POST /sessions` et consigné que les autres routes de session « ne dépendent que de la limite par adresse ». J'avais proposé d'étendre ce budget à `approve`, `reject`, `connect`, `terminate` et à la liste des demandes en attente. Avant de le faire, j'ai lu ce que chacune **écrit ou appelle** quand elle est refusée ou répétée, parce qu'un budget n'a de sens que là où un appel répété coûte quelque chose :

| Route | À chaque appel |
|---|---|
| `POST /sessions/{id}/approve`, `…/reject` | Un refus « qui dit quelque chose de l'appelant » (auto-approbation, aucune politique d'approbation, break-glass désactivé ou hors limite) écrit un **événement d'audit** (`session.breakglass_approved` / `_rejected`, `success=false`), après un appel à l'Authorization Service. Un appelant qui connaît l'identifiant d'une session — la sienne, par exemple — peut donc faire écrire autant d'événements qu'il peut envoyer de requêtes. |
| `POST /sessions/{id}/connect` | Pour son demandeur, sur une session active : un **scope du Vault**, un **ticket du proxy** et un **événement d'audit** (`session.connect`) à chaque appel, sans limite de nombre pendant la durée de la session. Pour un autre appelant, ou sur une session non active : un refus, sans écriture. |
| `DELETE /sessions/{id}` (terminate) | Une écriture, **une fois** par session : l'appel suivant est un conflit, sans écriture. |
| `GET /sessions/{id}`, `GET …/recording`, `GET /sessions?status=pending_approval` | **Aucune écriture.** La liste interroge l'Authorization Service une fois par compte distinct en attente ; l'enregistrement, le Command Recorder. |

L'attaquant réaliste n'est donc pas « n'importe qui » : un refus de création ne révèle pas l'identifiant de la session, il faut en détenir une (une demande acceptée ou en attente). C'est un titulaire de jeton qui a **un** droit, par exemple celui de demander un accès — un compte compromis, pas un inconnu.

Deux questions : (1) **sur quelles routes** mettre un budget, et avec quelle clé ; (2) **comment** l'ajouter sans que changer de route donne un budget neuf, et sans gêner l'enchaînement normal « demander puis se connecter ».

**Décision**
Six règles.

1. **Le budget suit le coût, pas la symétrie.** Il couvre les trois routes qui écrivent à **chaque** appel : `approve`, `reject` et `connect`. Il ne couvre **pas** `terminate` (une écriture par session, bornée par le nombre de sessions — *amendé par ADR-0017 : dès que `terminate` refuse et audite chaque appelant sans autorité, il écrit à chaque appel et rejoint ce seau*) ni les lectures (aucune écriture — *confirmé par ADR-0019 : un refus de lecture n'écrit rien non plus — puis amendé par ADR-0020 : il écrit, mais sous un budget propre, dans le Broker, et les lectures restent hors de ce seau-ci*) : y mettre un budget limiterait des interfaces qui interrogent l'état à intervalles réguliers, pour borner quelque chose qui ne coûte rien à écrire.
2. **Un seau par utilisateur pour les trois, pas un par route**, et **distinct** de celui de `POST /sessions` (ADR-0014). Pas un par route : changer de route ne doit pas donner un budget neuf. Distinct : « demander puis se connecter » est un enchaînement normal, et un utilisateur qui vient d'épuiser ses demandes ne doit pas perdre le droit de se connecter à une session déjà accordée — en urgence surtout.
3. **La clé est l'identité vérifiée, et le compte se fait avant tout travail.** Comme en ADR-0014 : le `UserID` issu du jeton, jamais l'adresse ni le corps (ces routes ne lisent pas le corps du client). Chaque `POST` sur une de ces actions coûte un jeton, accepté ou non, **avant** que le Broker ne soit appelé : une action refusée par le budget n'atteint ni le Broker, ni le Vault, ni le proxy, et n'écrit **aucun événement d'audit**. Une méthode non permise (`405`) ou un chemin inconnu (`404`) ne coûte rien.
4. **Défauts stricts, bornes, pas d'« illimité » :** `SESSION_ACTION_BURST` (défaut **10**, de 1 à 1000) et `SESSION_ACTION_RATE_PER_MINUTE` (défaut **6**, de 1 à 600) ; valeur invalide fatale en nommant la variable ; un Gateway construit à la main applique les défauts ; annonce au démarrage.
5. **`429` avec un `Retry-After` vrai** (secondes, arrondies au-dessus, au moins 1), message **distinct** de celui de `POST /sessions` et de ceux du Broker (« too many session actions from this user … ») : un client sait quel budget il a épuisé. **Une ligne de journal par utilisateur et par épisode de refus**, jamais une par requête, jamais le jeton ; rien dans l'audit (ADR-0014, règle 5).
6. **Par processus**, comme les autres budgets du Gateway.

Réponses : les trois routes ajoutent le `429` du Gateway, avec `Retry-After`. Aucun changement du Broker ni du schéma.

**Conséquences**
- (+) Un titulaire de jeton ne fait plus écrire que le débit de son seau — 10 en rafale, puis 6 par minute (8 640 par jour au plus) — en événements d'audit (`approve`/`reject` refusés) et en scopes Vault, tickets proxy et événements d'audit (`connect`), au lieu de « ce que le réseau laisse passer ». Les refus du budget n'écrivent rien.
- (+) Le budget est celui de l'identité : le bruit d'un utilisateur ne retire rien aux autres.
- (+) **Mesuré** (processus réels : Authorization, Authentication, Audit, Session Broker, trois Gateways) : **sans budget**, 6 approbations refusées et 6 rejets refusés écrivent **12 événements d'audit** ; avec une rafale de 3, huit approbations d'affilée n'en écrivent que **3**, les cinq autres sont des `429` qui n'atteignent pas le Broker ; `reject` et `connect` sont ensuite refusés par le même seau ; un autre utilisateur a le sien. 44 mutations : 43 détectées, 1 équivalente (le budget d'actions emprunte les défauts de `POST /sessions` : valeurs identiques, aucun test ne peut les distinguer).
- (−) **Un jeton volé peut priver son titulaire de ses actions** : un jeton se reforme toutes les 10 secondes, il va à qui arrive le premier. C'est le cas d'**urgence** qui pèse le plus ici : un attaquant qui détient le jeton d'un approbateur ou d'un demandeur peut épuiser son budget pendant l'incident. Le remède est de révoquer le jeton. Même nature qu'ADR-0013 et ADR-0014.
- (−) **Un utilisateur légitime très actif est ralenti** : plus de 10 décisions ou connexions d'un coup, ou plus de 6 par minute en continu, reçoivent des `429`. C'est le prix du budget ; les valeurs sont choisies, non mesurées sur un usage réel, et se règlent. Le seau est partagé entre toutes ses sessions : un script qui en ouvre vingt d'un coup est ralenti.
- (−) **`terminate` et les lectures ne sont pas couverts** (`terminate` l'est depuis ADR-0017) : ils ne dépendent que de la limite par adresse. La liste des demandes en attente peut coûter à l'Authorization Service un appel par compte distinct ; elle n'écrit rien. `terminate` n'a toujours ni contrôle d'appartenance ni politique propre (limite connue) : le budget n'y change rien.
- (−) **Les refus du budget ne sont pas dans l'audit**, seulement dans le journal du Gateway.
- (−) **Le jeton est pris avant de savoir ce que le Broker dira** : un `connect` d'un autre utilisateur, qui ne ferait aucune écriture, coûte un jeton quand même. C'est le prix d'un compte fait avant tout travail.
- (−) **Plusieurs identités, plusieurs budgets** ; **par processus** : N réplicas, N fois le budget.

**Alternatives envisagées**
- *Un budget par route* : rejeté — passer de `approve` à `reject` à `connect` donnerait un budget neuf à chaque fois.
- *Un seul seau avec `POST /sessions`* : rejeté — il ferait perdre à un utilisateur le droit de se connecter parce qu'il a trop demandé, y compris en urgence.
- *Un budget par session* : rejeté — le coût est celui de l'utilisateur sur l'ensemble de ses sessions ; borner chacune laisse la somme libre.
- *Budget sur `terminate` et sur les lectures aussi* : rejeté ici — ils n'écrivent pas à chaque appel ; ce serait limiter des interfaces qui interrogent l'état pour borner un coût nul. À reconsidérer si une mesure montre une charge de lecture sur l'Authorization Service.
- *Un seul `connect` par session* : rejeté — se reconnecter après une coupure est légitime, et cela changerait la sémantique de l'API.
- *Auditer chaque refus du budget* : rejeté — recrée le flux d'écritures qu'on veut borner (ADR-0014).

---

## ADR-0017 — Mettre fin à une session : son demandeur ou une autorité déclarée, et au nom de celui qui le demande

**Contexte**
ADR-0016 avait laissé `terminate` hors du budget en consignant une limite : « `terminate` n'a ni contrôle d'appartenance ni politique propre ». En préparant cette étape j'ai lu `DELETE /sessions/{id}` de bout en bout, puis écrit le test d'attaque **avant** le correctif et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Le Gateway ne dit pas au Broker qui demande.** `DELETE /sessions/{id}` est relayé tel quel (« rien à injecter », disait le commentaire) ; `TerminateSession(ctx, id)` du Broker ne reçoit aucun appelant. **Bob — rôle `sre`, aucune politique de terminaison — obtient `200` et la session d'Alice passe à `terminated`.** Tout porteur de jeton valide qui connaît un identifiant met fin à la session de n'importe qui.
- **L'audit en attribue la fin au demandeur.** L'événement est émis avec `sess.RequestedBy` comme auteur, quel que soit celui qui a appelé : la terminaison faite par Bob est écrite au nom d'Alice. C'est une fausse attribution dans la trace, pas seulement un trou de contrôle.
- **En urgence, c'est un déni d'accès.** Une session break-glass approuvée est `active` : n'importe qui peut la terminer avant que son demandeur ait pu s'y connecter (`connect` exige `active`).
- **Un identifiant inconnu répond `409 session not found`** : le statut ment (c'est un `404`).
- **Ce que `terminate` fait vraiment.** Il change l'enregistrement du Broker, donc empêche un **futur** `connect`. Le proxy SSH n'expose qu'une route interne, `establish-session` (appelable par le seul Broker) : **aucune route de révocation**. Ni la connexion SSH en cours ni un ticket déjà émis mais pas encore consommé ne sont coupés avant l'échéance de la session (lecture du code des routes du proxy, non rejouée par un test : un test qui l'assertait figerait une limite). La coupure réelle est l'étape suivante ; cet ADR protège **qui** peut changer l'enregistrement.
- **Le contrat prévoyait déjà l'identité.** `TerminateSessionRequest` du proto (doc 07 §3) porte un `RequestContext` : l'implémentation HTTP ne s'en servait pas.
- **Constat voisin, non traité ici — traité par ADR-0019** : `GET /sessions/{id}` n'a pas d'appelant non plus. Un utilisateur **sans rôle ni politique** (`nobody`) reçoit `200` avec le demandeur, le compte, la justification et l'échéance de la session d'un autre (sonde jetée, mesurée sur processus réels). C'est une divulgation, d'une autre nature : qui a le droit de **voir** une session est une décision à part (le demandeur, le décideur, un approbateur, un auditeur ?).
- **Un refus qui s'écrit à chaque tentative recrée le problème d'ADR-0014 et d'ADR-0016.** Dès que `terminate` refuse un appelant sans autorité et l'inscrit dans l'audit, chaque tentative écrit un événement : ADR-0016, règle 1 (« terminate écrit une fois par session ») n'est plus vraie.

**Décision**
Sept règles.

1. **L'identité est celle du jeton vérifié, jamais celle du corps.** Le Gateway construit `{callerId, actorRoles}` à partir du jeton ; ce que le client écrit est écarté ; `DELETE` n'est plus « relayé tel quel ». Sans `callerId`, le Broker refuse (`403`) : une terminaison a besoin d'un utilisateur authentifié.
2. **Qui peut mettre fin à une session** : (a) **son demandeur**, toujours, sans politique — mettre fin à son propre accès n'est pas une élévation (même raisonnement que rejeter sa propre demande, ADR-0011), et cela ne dépend d'aucun service distant ; (b) **un titulaire d'une politique RBAC** sur `session-terminate:account:{privilegedAccountId}` (action `session:terminate`), **refusée par défaut**. Le préfixe est distinct de `vault:`, `breakglass:` et `breakglass-approve:` : le droit d'approuver une urgence n'est pas celui de couper une session.
3. **L'ordre est : la session (`404`), puis l'appelant (`403`, quel que soit l'état), puis l'état (`409`).** Un appelant sans autorité reçoit « refusé » quel que soit l'état de la session, comme pour `approve` : la réponse ne décrit pas une session à qui n'a pas le droit d'en décider. L'Authorization Service muet n'est consulté que pour qui n'est pas le demandeur ; dans ce cas, **`503` et rien n'est terminé** (échec fermé).
4. **L'audit dit qui a demandé.** L'événement de succès (`session.terminate`) a pour auteur l'**appelant**, pas le demandeur de la session. Un refus qui dit quelque chose de l'appelant (aucune politique) est un événement `session.terminate`, `success=false`, au nom de l'appelant. Un `409` ou un `404` n'est pas un événement. **L'événement de succès reste émis après l'action, au mieux** (comme avant) : `terminate` réduit un accès, et refuser de le réduire parce que l'audit est en panne ferait plus de mal qu'un événement manquant — l'inverse de l'octroi, où l'audit vient avant (ADR-0011). C'est un choix, pas un oubli.
5. **`terminate` rejoint le budget d'actions d'ADR-0016** — le même seau, pris avant le Broker, après la vérification de la méthode — puisque ses refus écrivent maintenant un événement à chaque tentative. Le budget suit le coût (ADR-0016, règle 1) : le coût de `terminate` a changé, donc sa place aussi. **Les lectures restent hors budget.**
6. **Réponses de `DELETE /sessions/{id}`** : `200`, `403`, `404`, `409`, `429` (budget), `503` (une dépendance ne répond pas : rien n'est terminé). Les causes d'une dépendance restent dans le journal du Broker, pas dans la réponse.
7. **Aucun changement de schéma ni de proto** : le contrat portait déjà l'identité.

**Conséquences**
- (+) Un porteur de jeton sans droit ne peut plus couper la session de quelqu'un, et le demandeur d'une session d'urgence ne peut plus se la voir retirer par un tiers.
- (+) La trace est vraie : celui qui met fin à une session est celui qui est nommé ; une tentative refusée est inscrite sous le nom de son auteur.
- (+) Mettre fin à **sa propre** session ne dépend d'aucun service distant.
- (+) **Mesuré** (processus réels, puis mutations). *Avant* : le test d'attaque donnait `200` à Bob (rôle `sre`, aucune politique) qui terminait la session d'Alice, et `409` pour une session inconnue ; l'audit nommait le demandeur. *Après* : Bob reçoit `403` (refus audité sous son nom, session toujours `active`, y compris avec un corps forgé qui porte l'identifiant d'Alice et les rôles `responder` et `platform-admin`), l'approbateur d'urgence sans politique de terminaison reçoit `403`, Carol (politique sur ce compte) reçoit `200` et l'audit la nomme, Carol sur un autre compte `403`, Alice termine sa session sans politique, une session inconnue est `404`, une seconde terminaison `409` sans événement, sans jeton `401`, et six refus avec un budget de 2 donnent `[403 403 429 429 429 429]` avec **2** événements d'audit seulement. **53 mutations** sur `TerminateSession`, son HTTP côté Broker et le cas `DELETE` du Gateway, toutes détectées : 46 d'emblée, 3 survivants réels (l'action demandée à Authorization, les rôles perdus entre le HTTP du Broker et le service, la cause du `503` non journalisée) comblés par deux tests, 4 mutations qui ne compilaient pas réécrites puis détectées ; le rejeu des 43 mutations d'ADR-0016 donne 42 détectées et 1 équivalente (déjà consignée). Le service d'autorisation **ignore** aujourd'hui le champ `action` : le test qui fige `session:terminate` épingle ce que dit le Broker, pas un comportement qui changerait la décision. Tests : 449 unitaires sans base (46 ignorés), 495 avec ; 52 PostgreSQL ; 34 d'intégration sans base (6 ignorés), 40 avec ; `go test -race` propre.
- (−) ~~**`terminate` ne coupe toujours pas une connexion en cours ni un ticket déjà émis**~~ : il bloquait le prochain `connect`, pas la connexion ouverte — un changement d'enregistrement, pas une coupure. **Levé par ADR-0018.**
- (−) ~~**`GET /sessions/{id}` reste ouvert à tout porteur de jeton**~~ (mesuré). **Levé par ADR-0019** : le demandeur, celui qui a décidé, ou le titulaire d'une politique `session-read:account:{id}`.
- (−) **Changement de comportement visible** : avant, tout le monde pouvait terminer ; maintenant, seul le demandeur le peut tant que l'opérateur n'a pas écrit une politique `session-terminate:account:*`. Aucune politique n'est créée par défaut.
- (−) **La terminaison en masse par un responsable est ralentie par le budget** (10 d'un coup, puis 6 par minute, comme les trois autres actions) : un incident où il faut couper trente sessions prend des minutes. `SESSION_ACTION_BURST` se règle ; l'alternative (ne compter que les refus) est décrite plus bas.
- (−) **Une autorité de terminaison compromise coupe ce qu'elle veut sur ses comptes** : c'est son droit ; le remède est de réduire ses politiques et de révoquer le jeton.
- (−) Une politique `session-terminate:account:*` est large par construction (un motif) : à écrire par compte, comme les autres.

**Alternatives envisagées**
- *Seul le demandeur peut terminer* : rejeté — une équipe de sécurité n'aurait aucun moyen de couper l'accès de quelqu'un d'autre.
- *Réutiliser `breakglass-approve:account:*`* : rejeté — cela confond deux pouvoirs : qui valide une urgence n'est pas forcément qui doit couper une session ordinaire, et inversement.
- *Un rôle « admin » écrit en dur* : rejeté — tout le reste du Broker passe par des politiques déclarées ; un rôle en dur serait un droit que l'opérateur ne voit pas.
- *Répondre `404` aux appelants sans droit pour cacher l'existence* : rejeté ici — comme pour `approve` et `connect`, l'identifiant est aléatoire sur 64 bits et le `403` ne décrit pas l'état ; ce serait un second schéma de réponses pour le même cas.
- *Auditer l'action avant d'agir, et refuser d'agir si l'audit est en panne* : rejeté pour `terminate` — l'inverse d'un octroi (ADR-0011).
- *Ne compter au budget que les refus (`403`)* : rejeté pour l'instant — il laisserait une terminaison en masse légitime à plein débit, mais demande de reprendre un jeton après coup ou de « prêter » un jeton avant, donc une seconde logique de budget à côté des trois autres ; à reconsidérer si un besoin de terminaison en masse apparaît.
- *Ne pas mettre `terminate` au budget et ne pas auditer les refus* : rejeté — on perd la trace des tentatives de couper la session d'un autre.

---

## ADR-0018 — Rendre la terminaison réelle côté proxy : le Broker fait couper les connexions et jeter les tickets avant de marquer la session terminée

**Contexte**
ADR-0017 avait protégé **qui** peut mettre fin à une session, et consigné une limite : `terminate` change l'enregistrement du Broker, donc empêche un **futur** `connect`, mais ne touche ni la connexion déjà ouverte ni un ticket émis et pas encore consommé. Un opérateur qui lit « terminé » croit que l'accès est coupé ; il ne l'est pas, jusqu'à l'échéance de la session. Pour un outil dont la promesse est de pouvoir **retirer** un accès privilégié, c'est la limite qui compte le plus. Ce qui a été **mesuré** avant de toucher au code :

- Le proxy SSH n'exposait qu'une route interne, `establish-session`. **Aucune route de révocation** : rien, côté proxy, ne savait qu'une session était finie.
- **Test d'intégration écrit avant le correctif, sur processus réels** (Gateway, Broker, Vault, Authorization, Audit, proxy SSH, cible SSH) : l'opérateur ouvre un shell, le demandeur appelle `DELETE /sessions/{id}`, la réponse est `200` et la session passe à `terminated` — et **le shell reste ouvert** ; le test échoue à sa première assertion (« la session n'a pas été coupée »). Les assertions suivantes (ticket jeté, mémoire de la révocation) n'étaient pas atteintes avant le correctif ; elles sont vertes après.
- Un ticket qui sortait du Broker juste avant la terminaison, et qui est consommé juste après, ouvre une connexion à une session que le Broker croit finie : il faut que **le proxy** refuse, pas seulement le Broker.
- Le Broker n'a pas besoin du proxy pour **marquer** une session terminée, mais s'il le fait sans le proxy, il écrit un mensonge : « terminé » pendant qu'une connexion tourne.

**Décision**
Neuf règles.

1. **L'ordre est : le proxy d'abord, l'enregistrement ensuite.** `TerminateSession` garde ses contrôles d'ADR-0017 (session `404`, appelant `403`, état `409`), puis appelle `RevokeSession` sur le proxy ; **seulement si le proxy répond 200**, il change l'enregistrement (compare-and-swap `SaveIfStatus`, inchangé). Si le proxy a coupé et que l'enregistrement échoue, la session est coupée mais encore marquée `active` : c'est le bon sens de l'erreur, et le même appel, qui est idempotent, termine le travail.
2. **Une route interne de révocation** : `POST /internal/v1/revoke-session` `{session_id, ttl_seconds}`, **appelable par le seul Session Broker** (ADR-0010, règle par route). `200` seulement si plus rien de la session ne reste ouvert ; `503` sinon ; `400` pour un corps invalide (identifiant vide, durée nulle ou négative) ; `405` hors `POST`. Idempotente : une session que le proxy ne connaît pas est un `200` qui ne coupe rien.
3. **Un registre des connexions vivantes dans le proxy, partagé avec le pipeline** (`proxycore.LiveSessions`, utilisé par `Listener.Serve` : un proxy RDP ou HTTP bâti sur `proxycore` est révocable de la même façon). Il tient, sous **un seul verrou**, les connexions ouvertes par session **et** la mémoire des révocations : une connexion qui s'enregistre pendant qu'on révoque est soit coupée, soit refusée, jamais entre les deux.
4. **Révoquer, c'est dans cet ordre** : se souvenir de la révocation, signaler l'annulation à chaque connexion ouverte (cause `ErrSessionRevoked`), jeter les tickets non utilisés (leur jeton de portée Vault est abandonné avec eux), puis **attendre au plus 5 s** que les relais se terminent. `200` si aucun ne se ferme encore, `503` sinon — le Broker ne dit alors pas « terminé ».
5. **Une session révoquée ne démarre pas.** `establish-session` répond `409` (aucun ticket) et `Serve` refuse l'enregistrement de la connexion (`ErrSessionRevoked`) **avant** l'admission, l'audit ou la récupération du credential. Le contrôle se fait deux fois dans `establish-session` (avant la recherche de l'enregistreur, puis après l'enregistrement du ticket, qu'il reprend si une révocation est passée entre les deux). Un `Listener` ou un serveur HTTP **sans registre** refuse toute session (`ErrNotRevocable`, `503`) : une session qu'on ne saurait pas couper ne commence pas (même posture qu'ADR-0008).
6. **Si le proxy ne répond pas** : le Broker répond `503`, **rien n'est terminé**, et la tentative est inscrite à l'audit (`session.terminate`, `success=false`) **au nom de l'appelant**. Le même appel, rejoué quand le proxy est revenu, aboutit. La révocation n'est **jamais** émise pour une terminaison refusée, d'une session inconnue, non active, expirée, ou quand l'Authorization Service ne répond pas.
7. **La mémoire de la révocation dure jusqu'à ce que la session se serait terminée d'elle-même** : le Broker envoie le temps restant plus une marge d'une minute (`RevocationMargin`) ; le proxy la plafonne à 7 jours (comparaison faite en secondes avant conversion, pour qu'une durée énorme ne déborde pas vers le passé) et balaye ce qui n'a plus rien à refuser. Elle est **en mémoire** : un proxy qui redémarre perd ses connexions, ses tickets et cette mémoire — sans danger, puisque le Broker n'émet plus de ticket pour une session terminée.
8. **L'audit dit ce qui s'est passé, chacun de son côté.** Le Broker émet `session.terminate` au nom de l'appelant (ADR-0017). Le proxy émet `session.revoked` (succès) pour chaque connexion coupée, puis `session.terminate` (succès : c'est une fin voulue, et le credential est purgé) ; la cause d'un arrêt du proxy n'est **pas** une révocation. **L'opérateur lit « session ended because it was terminated. »** — pas par qui.
9. **La connexion vers la cible est fermée dès l'annulation**, y compris au milieu de la poignée de main SSH, qui n'a pas de contexte propre (`context.AfterFunc` dans le codec) : on ne termine pas un login que personne n'a plus le droit d'utiliser.

**Conséquences**
- (+) « Terminé » veut dire coupé : la connexion ouverte est fermée, les tickets non utilisés sont morts, et rien ne peut être établi de nouveau pour cette session, jusqu'à ce qu'elle ait expiré de toute façon.
- (+) Le Broker ne ment pas : tant que le proxy n'a pas confirmé, la session reste `active`, l'appelant est informé (`503`) et la tentative est consignée.
- (+) La révocation ne dépend pas de l'audit : ce qu'elle attend, c'est la fin du **relais**, pas la fin de la comptabilité qui suit (testé avec un audit retenu).
- (+) **Mesuré** (processus réels, puis mutations). *Avant* : `DELETE` → `200`, session `terminated`, shell toujours ouvert. *Après* : un demandeur ou une autorité qui met fin à la session voit **toutes** ses connexions fermées (deux shells ouverts, les deux coupés, avec le message de l'opérateur), un ticket non consommé ne sert plus, une frappe après la coupure n'atteint jamais la cible, une autre session reste intacte, une session terminée ne se reconnecte pas, le proxy arrêté donne `503` avec la session toujours `active` et la tentative échouée dans l'audit — puis le même appel, une fois le proxy relancé, aboutit. Une terminaison refusée ne coupe rien. Les appels forgés vers la route de révocation (Vault, Gateway compromis, outil d'exploitation) sont refusés à la porte et la session de l'opérateur reste ouverte, comme les `DELETE` forgés vers le Broker. **96 mutations** sur le Broker (ordre, audit, marge, échec), son client HTTP, la route du proxy, ses règles d'appelants, le registre des connexions, `Serve`, le codec, le message de l'opérateur et le câblage : 73 détectées d'emblée, **18 survivantes réelles** et **5 qui ne compilaient pas** (réécrites) — toutes closes par des tests, dont les lacunes qu'elles ont révélées (marge exacte de la révocation, audit d'un échec sous le nom d'une autorité, durée et plafond de la mémoire, refus avant d'interroger l'enregistreur, comptes tickets/connexions confondus, fin du relais avant l'audit, succès de `session.terminate` à la coupure, échéance sous la révocation, arrêt du proxy pris pour une révocation, poignée de main SSH non coupée, message de l'opérateur, verrou des tickets) ; la série finale donne 96 sur 96, et le rejeu des 53 mutations d'ADR-0017 donne 53 sur 53. Une condition redondante de `Serve` (`ctx.Err() == nil` autour de `context.Cause`) a été retirée plutôt que testée : sa mutation était équivalente. **Une régression a été trouvée par la vérification complète, pas par les mutations** : `TestPostgresFlow_SessionSurvivesSessionBrokerProcessRestart` terminait une session sur un Broker dont le proxy n'existait pas ; il reçoit désormais `503` (comportement voulu) et le test dispose d'un proxy de substitution qui confirme la révocation. Tests : 501 unitaires sans base (46 ignorés), 547 avec ; 52 PostgreSQL ; 35 d'intégration sans base (6 ignorés), 41 avec ; `go test -race` propre (unitaires et intégration).
- (−) **Le proxy est en instance unique dans le MVP.** Les tickets, les connexions et la mémoire des révocations sont dans le processus : avec plusieurs réplicas, la révocation atteindrait **un** réplica. Il faudra un registre des proxys (le Broker sait déjà lequel il a choisi) ou une diffusion. Tant que ce n'est pas fait, **on ne doit pas déployer plusieurs réplicas du proxy SSH** (consigné dans le guide HA).
- (−) **Mode strict seulement** : si le proxy ne répond pas, on ne peut pas terminer. Un mode `PROXY_REVOCATION=best_effort` (marquer terminé même si le proxy ne répond pas) est une décision à prendre ; je ne l'ai pas ajouté, car il rouvre exactement le mensonge que cet ADR ferme.
- (−) **Les octrois de portée du Vault ne sont pas révoqués.** Le proxy jette le jeton avec le ticket ; seule l'identité du proxy peut le consommer, et il est à usage unique avec une durée de vie courte. Un jeton déjà consommé a produit un credential que le proxy purge à la fin de la connexion. Rien de plus n'est fait côté Vault.
- (−) **La mémoire est en mémoire** : un redémarrage du proxy l'efface (sans danger, voir règle 7) ; le nombre de révocations mémorisées n'est borné que par leur expiration.
- (−) **Une fenêtre au démarrage de la poignée de main SSH** : une révocation qui arrive pendant la connexion vers la cible ferme cette connexion (règle 9) ; le proxy ne peut pas faire mieux sans contexte dans la bibliothèque SSH.
- (−) ~~**`GET /sessions/{id}` reste ouvert à tout porteur de jeton**~~ (limite d'ADR-0017, inchangée) : décider qui peut **voir** une session était une décision à part. **Levé par ADR-0019.**
- (−) **La coupure peut prendre jusqu'à 5 s** à confirmer, et un `503` est possible si un relais ne se ferme pas à temps : l'appel peut être rejoué.

**Alternatives envisagées**
- *Marquer terminé d'abord, couper ensuite* : rejeté — si la coupure échoue, la session est « terminée » et ouverte, et personne ne le sait. L'ordre inverse échoue dans le bon sens.
- *Un mode « au mieux » (marquer terminé même si le proxy est injoignable)* : rejeté pour l'instant (voir plus haut) ; à reconsidérer si l'exploitation demande de pouvoir terminer un proxy en panne.
- *Que le proxy interroge le Broker à intervalles réguliers pour savoir si sa session est finie* : rejeté — un délai de coupure égal à l'intervalle, un coût en charge permanent, et une dépendance du proxy au Broker pendant la session.
- *Diffuser la révocation sur le bus (NATS)* : rejeté pour le MVP — l'appel direct donne une réponse (a-t-on coupé ?) ; une diffusion n'en donne pas. À reconsidérer avec plusieurs réplicas du proxy.
- *Se contenter de tickets à courte durée de vie* : rejeté — cela ne coupe pas la connexion déjà ouverte, qui est le cas qui compte.
- *Fermer seulement la connexion vers la cible* : rejeté — la connexion de l'opérateur reste ouverte sans rien derrière, sans dire pourquoi ; il faut aussi le lui dire, et purger le credential.

---

## ADR-0019 — Qui peut lire une session : son demandeur, celui qui l'a décidée, ou le titulaire d'une politique `session-read` — et une lecture n'écrit rien

**Contexte**
ADR-0017 avait consigné un constat voisin sans le traiter : `GET /sessions/{id}` n'a pas d'appelant. ADR-0018 l'avait reporté tel quel. J'ai écrit le test d'attaque **avant** le correctif, sur processus réels (Gateway, Broker, Authorization, Audit, Vault, proxy SSH), et constaté qu'il échouait. Ce qui a été **mesuré** (six affirmations, **quatre** en échec avant) :

- **Le Gateway ne dit pas au Broker qui lit.** `GET /sessions/{id}` était relayé tel quel (`forwardPassthrough`) ; `GetSession(ctx, id)` ne recevait aucun appelant. **`nobody` — aucun rôle, aucune politique — obtient `200` avec le demandeur, le compte privilégié, la justification, l'échéance et l'état de la session d'un autre.**
- **La liste d'ADR-0012 est contournée.** Elle ne montre à un approbateur que les demandes en attente qu'il a le droit de décider ; mais la **justification d'une urgence** (« enregistreur en panne pendant l'incident P1 ») se lit par `GET` sur l'identifiant, par n'importe quel porteur de jeton. Filtrer la liste n'a de sens que si la lecture directe l'est aussi.
- **Toute erreur du store se lisait « session introuvable ».** L'ancien gestionnaire répondait `404` à n'importe quelle erreur : une base en panne disait « cette session n'existe pas », ce qui est faux et empêche un client de réessayer.
- **Un piège à poser avec le correctif.** Dès que le Broker lit `callerId` et `actorRoles` dans la requête, un client qui les écrirait lui-même (`?callerId=<le demandeur>&actorRoles=platform-admin`) lirait comme n'importe qui : il faut, **ensemble**, que le Gateway les construise lui-même et écarte ceux du client. Le test les forge.
- **Le contrat portait déjà l'identité.** `GetSessionRequest` du proto (doc 07 §3) a un `RequestContext` : l'implémentation HTTP ne s'en servait pas. Aucun schéma ni proto à changer.

**Décision**
Huit règles.

1. **L'identité est celle du jeton vérifié, jamais celle du client.** Le Gateway construit `?callerId=<id>&actorRoles=<rôles séparés par des virgules>` (le mécanisme de la liste, ADR-0012, règle 3) ; la requête du client est **écartée** — paramètres et corps — et les rôles sont **encodés** (un nom de rôle est une donnée, jamais de la syntaxe de requête). Sans `callerId`, le Broker refuse (`403`) : lire une session demande un utilisateur authentifié. La route du Broker reste réservée au Gateway (ADR-0010).
2. **Qui peut lire une session** : (a) **son demandeur**, toujours, sans politique et sans interroger personne — lire sa propre session n'élargit rien, et cela ne dépend d'aucun service distant ; (b) **la personne qui l'a décidée** (`DecidedBy` non vide et égal à l'appelant), pour **cette** session seulement — elle l'a déjà vue pour décider ; (c) **le titulaire d'une politique RBAC** sur `session-read:account:{privilegedAccountId}` (action `session:read`), **refusée par défaut**. Le préfixe est distinct de `vault:`, `breakglass:`, `breakglass-approve:` et `session-terminate:` : aucun de ces pouvoirs ne donne le droit de lire. Un approbateur qui n'est ni le demandeur, ni le décideur, ni titulaire d'une politique de lecture est **refusé** : la liste d'ADR-0012 lui donne ce qu'il a le droit de décider, pas un accès en lecture à toutes les sessions.
3. **L'ordre est : l'appelant vide (`403`), la session (`404`), puis l'appelant (`403`), puis l'Authorization Service (`503`).** Un appelant sans nom reçoit `403` même pour un identifiant inconnu ; un appelant sans droit reçoit le même `403` quel que soit l'état de la session ; l'Authorization Service n'est interrogé que pour qui n'est ni le demandeur ni le décideur.
4. **Le refus ne dit rien de la session.** Le message est le même pour tous : il ne contient ni le compte, ni le demandeur, ni la justification, ni l'état, **ni la raison de l'Authorization Service** — celle-ci nomme la ressource, donc le compte d'une session dont cet appelant n'a pas le droit de savoir qu'elle existe.
5. **Échec fermé, et une panne n'est pas une absence.** L'Authorization Service muet → `503` pour un tiers (rien n'est servi) ; le demandeur et le décideur ne dépendent pas de lui. Une erreur du store qui n'est pas « introuvable » → `503` (la cause reste dans le journal du Broker), jamais `404`.
6. **Une lecture n'écrit rien** : aucun événement d'audit — **pas même pour un refus** — et aucune ligne (mesuré avec un store qui compte ses écritures : zéro). *Amendé par ADR-0020 : un **refus de politique** est audité, dans la limite d'un budget par identité ; amendé par ADR-0021 : une lecture **servie à un titulaire de politique** est elle aussi enregistrée, avant d'être servie. Seules les lectures du demandeur et du décideur n'écrivent rien.* Raison : si chaque `GET` refusé écrivait un événement, tout porteur de jeton aurait une écriture à volonté dans la trace signée — le problème d'ADR-0014 et d'ADR-0016 —, et les interfaces qui interrogent l'état à intervalles réguliers ne sont pas ce qu'un budget doit limiter. C'est un choix, avec un coût déclaré plus bas.
7. **Les lectures restent hors du budget d'actions** : ADR-0016, règle 1, reste vraie — et plus vraie qu'avant, puisqu'un refus de lecture n'écrit rien non plus. *(ADR-0020 : un refus écrit désormais, mais sous son propre budget, dans le Broker ; le budget d'actions du Gateway ne compte toujours pas les lectures.)* Seule la limite par adresse s'applique (ADR-0015).
8. **Réponses de `GET /sessions/{id}`** : `200`, `401` (sans jeton), `403`, `404`, `503` (une dépendance ne répond pas : rien n'est servi). Un identifiant inconnu est `404` : il révèle qu'il n'existe pas, comme pour `terminate` (identifiants aléatoires sur 64 bits, ADR-0017).

**Conséquences**
- (+) Un porteur de jeton sans droit ne lit plus le demandeur, le compte ni la justification d'une session, et la justification d'une urgence en attente n'est plus lisible par qui ne peut pas la décider.
- (+) Un client ne peut ni lire « en tant que » le demandeur, ni se donner les rôles d'un lecteur : ce qu'il écrit dans la requête est écarté.
- (+) Lire **sa propre** session, ou celle qu'on a décidée, ne dépend d'aucun service distant ; une panne de l'Authorization Service ne prive pas un opérateur de l'état de sa session.
- (+) Une base qui ne répond pas ne se lit plus « session inconnue » : `503`, que le client peut réessayer.
- (+) **Mesuré** (processus réels, puis mutations). *Avant* : le test d'attaque échouait sur **4 affirmations sur 6** — `nobody` et un tiers recevaient `200` avec la justification, le compte et le demandeur, et une requête forgée `?callerId=<le demandeur>&actorRoles=platform-admin,auditor,responder` n'était arrêtée par rien parce que rien ne la lisait. *Après* : le demandeur lit sa session sans aucune politique ; Bob (rôle `sre`) et `nobody` reçoivent `403` sans rien apprendre de la session (ni justification, ni compte, ni demandeur, ni état, ni échéance) ; la requête forgée reçoit toujours `403` ; Carol (politique `session-read` sur ce compte) reçoit `200` pour ce compte et `403` pour un autre ; Dave (politiques de terminaison et d'approbation, aucune de lecture) reçoit `403` ; l'identifiant inconnu est `404`, sans jeton `401`. Les appels forgés vers `GET /sessions/{id}` depuis le Vault, le proxy SSH, l'outil d'exploitation et l'enregistreur sont refusés à la porte (table d'attaque mTLS), et la session de l'opérateur reste active. **65 mutations** sur `GetSession` (garde de l'appelant, ordre, correspondance exacte du demandeur et du décideur, préfixe, compte, action et rôles de la question posée à l'Authorization Service, panne de ce service, fuites du message de refus, erreur du store, écritures et audit d'une lecture), le gestionnaire HTTP du Broker (codes, rôles lus dans la requête, cause dans le journal seulement), la lecture du Gateway (source de l'identité, requête du client, encodage, méthode, budget) et la règle mTLS : 58 détectées d'emblée, **4 survivantes réelles** (un demandeur reconnu par préfixe de nom ; la raison de l'Authorization Service recopiée dans le refus ; une lecture qui réécrit l'enregistrement tel quel ; et le retrait de la garde « décideur vide ») dont **3 closes par des tests** et **1 équivalente** (la garde « décideur vide » est redondante tant que l'appelant vide est refusé en premier : elle est gardée en défense en profondeur, pas testée), **2 qui ne compilaient pas** (réécrites) ; la série finale donne 64 sur 64 hors l'équivalente, et le rejeu des 96 mutations d'ADR-0018 et des 53 d'ADR-0017 donne 96 sur 96 et 53 sur 53 (l'ancre de la mutation G4 d'ADR-0017, qui visait l'ancien relais brut du `GET`, a été réalignée). Tests : 527 unitaires sans base (46 ignorés), 573 avec ; 52 PostgreSQL ; 36 d'intégration sans base (6 ignorés), 42 avec ; `go test -race` propre (unitaires et intégration). **Pas de régression trouvée par la vérification complète cette fois** : les `GET` des tests existants (HTTP du Broker, `brokerGetSession`, la vérification finale de la table mTLS) ont dû être adaptés pour nommer qui lit, par construction.
- (−) ~~**`GET /sessions/{id}` reste ouvert à tout porteur de jeton**~~ : **levé par cet ADR.**
- (−) **Changement de comportement visible** : avant, tout porteur de jeton lisait toute session ; maintenant, seuls le demandeur et le décideur le peuvent tant que l'opérateur n'a pas écrit une politique `session-read:account:*` pour les rôles qui doivent lire (un auditeur, une équipe de sécurité). Aucune politique n'est créée par défaut.
- (−) ~~**Un refus de lecture ne laisse aucune trace.**~~ **Levé par ADR-0020**, dans une limite (voir cet ADR). Ce que cette limite disait : Ni dans la trace signée (règle 6), ni dans un journal : le Gateway ne journalise pas les requêtes, et le Broker n'écrit dans son journal que les pannes de dépendance. Une personne qui sonde des identifiants n'est visible nulle part. Les identifiants sont aléatoires sur 64 bits, donc une sonde ne trouve rien ; mais un refus répété n'est pas visible là où l'on cherche les tentatives. L'alternative (auditer chaque refus, avec un budget d'échecs par identité) est décrite plus bas : c'est la limite à lever en premier si l'exploitation veut voir ces sondes.
- (−) **`404` pour un identifiant inconnu révèle qu'il n'existe pas** : acceptable avec des identifiants à 64 bits aléatoires (même raisonnement qu'ADR-0017) ; ce serait un second schéma de réponses pour le même cas que de répondre `403`.
- (−) **Une politique `session-read:account:*` est large par construction** (un motif) : à écrire par compte. Son titulaire lit les justifications d'urgence de ces comptes.
- (−) **Lire une session n'est pas lire ce qui s'y est tapé** : les commandes enregistrées restent derrière le rôle auditeur du Command Recorder (`GET /sessions/{id}/recording`), dont les règles ne changent pas ici.
- (−) **Le décideur garde le droit de relire ce qu'il a décidé** même s'il perd ensuite le rôle d'approbateur : son droit est ce qu'il a fait, pas ce qu'il est.

**Alternatives envisagées**
- *Laisser `GET` ouvert* : rejeté — la divulgation est mesurée, et elle contourne le filtrage de la liste d'ADR-0012.
- *Seul le demandeur lit* : rejeté — une équipe de sécurité ou un auditeur n'aurait aucun moyen de lire la session de quelqu'un d'autre ; il faut un droit déclaré par l'opérateur.
- *Réutiliser `breakglass-approve:account:*` ou `session-terminate:account:*`* : rejeté — cela confond des pouvoirs : qui valide une urgence ou coupe une session n'est pas forcément qui doit la lire, et inversement.
- *Tout approbateur lit toute demande en attente* : rejeté — la liste d'ADR-0012 est déjà filtrée par droit sur le compte ; `GET` redeviendrait le contournement.
- *Répondre `404` aux appelants sans droit pour cacher l'existence* : rejeté — un second schéma de réponses ; l'identifiant est aléatoire sur 64 bits (ADR-0017).
- *Auditer chaque refus de lecture* : rejeté pour l'instant — chaque `GET` refusé écrirait un événement, donc une écriture à volonté dans la trace signée ; cela demande un budget d'échecs par identité à côté des autres, donc une logique de plus. À reconsidérer si l'on veut voir les sondes. **Reconsidéré et fait par ADR-0020**, avec exactement ce budget.
- *Mettre les lectures au budget d'actions* : rejeté — cela limiterait les interfaces qui interrogent l'état à intervalles réguliers pour borner ce qui ne coûte plus rien à écrire (ADR-0016, règle 1).
- *Porter l'identité dans un en-tête signé plutôt que dans la requête* : rejeté — la route du Broker n'est atteignable que par le Gateway (ADR-0010) ; un en-tête de plus ne protège pas davantage, et la liste d'ADR-0012 passe déjà par la requête.

---

## ADR-0020 — Auditer les refus de lecture d'une session, au nom de celui qui lit, dans la limite d'un budget par identité

**Contexte**
ADR-0019 avait choisi qu'une lecture n'écrit rien, pas même un refus, et avait déclaré le prix : *un refus de lecture ne laisse aucune trace — la limite à lever en premier si l'exploitation veut voir ces sondes.* Je la lève. Ce qui a été **mesuré** avant d'écrire une ligne :

- **Une sonde est invisible.** Bob (aucune politique) lit trois fois la session d'Alice : trois `403`, **zéro** événement d'audit, aucune ligne de journal (test unitaire et test sur processus réels, **rouges avant**). Une personne qui essaie des identifiants — ou qui boucle sur une session qu'elle croit pouvoir lire — n'est visible nulle part.
- **Tout auditer n'est pas une réponse.** Ce qu'ADR-0016 a mesuré pour `approve` et `reject` vaut ici : un refus qui écrit à chaque appel, c'est une écriture à volonté dans la trace signée pour tout porteur de jeton (témoin sans budget : douze refus, douze événements). Il faut **ensemble** l'événement et sa borne.
- **Le refus de politique est le seul refus qui a un appelant et une cible.** Un appelant sans nom (`403`, « authenticated user ») n'a pas d'identité à nommer ; un `404` ne désigne aucune session ; un `503` n'est le refus de personne. Seul le `403` qui suit une réponse « non » de l'Authorization Service pour un appelant nommé sur une session qui existe dit *qui a essayé de lire quoi*.

**Décision**
Neuf règles.

1. **Un refus de politique est un événement `session.read`** : `resource_type = session`, `resource_id` = l'identifiant de la session, `success = false`. L'**auteur est l'appelant que le Gateway a vérifié** — jamais le demandeur de la session (ce serait accuser la victime de la sonde), jamais une valeur de la requête du client (ADR-0019, règle 1). C'est le même choix que pour le refus de terminaison (ADR-0017).
2. **Seul ce refus écrit, de ce côté-là.** Une lecture servie (au demandeur, au décideur, à un titulaire de politique), un `404`, un `503` (Authorization ou base muette) et un appelant sans nom n'écrivent **rien** et ne dépensent aucun jeton. *Amendé par ADR-0021 : une lecture servie **à un titulaire de politique** est un événement `session.read` en succès, écrit avant d'être servie, qui ne dépense aucun jeton de ce budget et n'en dépend pas ; le demandeur et le décideur n'écrivent toujours rien.*
3. **Un budget par identité borne ce qui s'écrit** : un seau à jetons dans le Broker, rafale `SESSION_READ_AUDIT_BURST` (**10** par défaut, de 1 à 1000), puis `SESSION_READ_AUDIT_RATE_PER_MINUTE` (**6**, de 1 à 600). Une valeur invalide arrête le Broker en nommant la variable ; **il n'existe ni « illimité » ni « désactivé »** ; un Broker construit à la main sans réglage a le budget strict. Il est lu au démarrage, que quelqu'un soit refusé ou non : une faute de frappe se voit le jour où on l'écrit.
4. **Le budget est celui de l'identité**, pas de la session ni du compte : sonder dix sessions épuise un seul budget, et le budget d'une identité ne touche pas celui d'une autre.
5. **La réponse ne dépend jamais du budget.** Le refus est le même — même code, même message — que l'événement soit écrit, supprimé par le budget ou perdu par une panne de l'audit. L'écriture est **au mieux** (comme les refus d'ADR-0017) : il n'y a rien à empêcher quand l'audit est en panne, la lecture est refusée de toute façon. Ce n'est **pas** « enregistrer ou refuser » (ADR-0008) : lire n'engage à rien enregistrer, et faire d'une panne de l'audit une panne des lectures pénaliserait le demandeur.
6. **Ce qui n'est pas écrit se voit dans le journal.** Quand le budget d'une identité est épuisé, le Broker écrit **une** ligne par épisode (« refused reads by user … are no longer written to the audit one by one (budget spent) »), pas une par refus ; une panne de l'audit laisse une ligne avec sa cause, que l'appelant ne lit pas.
7. **La mémoire est bornée.** Un seau revenu plein décide comme un seau qui n'existerait pas : il est oublié (balayage périodique, marge d'un dixième pour que l'arrondi flottant ne fasse jamais différer les deux). Une horloge qui recule ne donne ni ne prend de jetons (la référence n'avance que vers l'avant).
8. **Par processus.** Avec *N* répliques du Broker, la borne d'écriture est *N* fois celle annoncée au démarrage (le Gateway choisit une réplique à chaque appel). La ligne de démarrage dit ce que le Broker applique réellement, et que c'est « per process ».
9. **Le Gateway ne change pas, ni les schémas** : il relaie déjà l'appelant vérifié (ADR-0019) ; le contrat OpenAPI de `GET /sessions/{id}` dit désormais que le `403` est audité dans la limite du budget. ADR-0019 est **amendé** sur la règle 6 (et sa limite « aucune trace »), pas sur les autres.

**Conséquences**
- (+) Une sonde est visible là où l'on cherche les tentatives : l'événement porte celui qui a essayé, la session visée et l'échec, dans la trace signée.
- (+) Cette trace n'est pas ouverte à l'écriture à volonté : au plus 10 événements d'un coup par identité, puis 6 par minute (360 par heure), par processus du Broker ; *K* jetons compromis, *K* budgets.
- (+) Le refus ne change pas : un client ne peut ni deviner le budget d'une identité depuis la réponse, ni se servir de l'audit en panne comme d'un oracle. Une lecture servie reste exempte de toute écriture.
- (+) **Mesuré** (tests rouges avant, puis processus réels et mutations). *Avant* : trois refus de Bob, zéro événement `session.read`, dans le test unitaire comme sur processus réels. *Après*, sur processus réels (Gateway, Broker, Authorization, Audit, Vault, proxy SSH) : Bob refusé laisse **un** événement `session.read` en échec **sous son nom** (jamais celui d'Alice, ni de la ressource d'un autre type) ; une requête forgée `?callerId=<le demandeur>&actorRoles=platform-admin,auditor` laisse un événement **sous le nom de la personne authentifiée**, pas sous celui que le client a écrit ; avec un budget de 3 puis 1 par minute, onze refus de Mallory répartis sur deux sessions sont **tous des `403`** et ne laissent que **trois** événements ; le budget de Bob n'est pas entamé par celui de Mallory ; la lecture d'Alice, celle de Carol (politique) et un `404` n'écrivent rien (ni échec, ni succès) ; la chaîne d'audit se vérifie encore ; une configuration invalide (`0`, négatif, au-dessus des bornes, texte, décimal, « off », « unlimited ») arrête le Broker en nommant la variable, les bornes elles-mêmes sont acceptées, et la ligne de démarrage dit le budget réellement appliqué. Le reste (une seule ligne de journal par épisode, un audit en panne, l'horloge, la mémoire) est prouvé en test unitaire. **81 mutations** (arithmétique du seau : rafale, plafond, débit et ses unités, isolation par clé, premier refus non écrit, balayage et sa marge, valeurs par défaut non positives, horloge ; câblage du service : nom, type, auteur, ressource et succès de l'événement, clé du budget, refus identique, panne de l'audit, lignes de journal, propagation de l'horloge, budget par défaut ; configuration du Broker : noms des variables, bornes, défauts, ligne de démarrage) : 73 détectées d'emblée, **4 survivantes réelles** (un seau qui n'est pas plafonné — que le balayage masque presque toujours, mais pas avant sa prochaine échéance ; son plafond relevé d'un ; un seau à moitié rempli supprimé par le balayage ; une horloge qui recule qui prend des jetons) toutes **closes par 3 tests**, **2 qui ne compilaient pas** (réécrites, détectées) et **2 équivalentes** documentées (l'arrondi de `RatePerMinute`, dont l'argument est tronqué vers le bas donc jamais trop court ; la marge du balayage, qui ne sert qu'à l'arrondi flottant) : 79 sur 79 hors équivalentes. Rejeu des séries précédentes : ADR-0019 64 sur 64 (+ l'équivalente déjà documentée), ADR-0017 53 sur 53, ADR-0018 96 sur 96. Tests : 552 unitaires sans base (46 ignorés), 598 avec ; 52 PostgreSQL ; 38 d'intégration sans base (6 ignorés), 44 avec ; `go test -race` propre.
- (−) **ADR-0019 est amendé** : « une lecture n'écrit rien, pas même un refus » n'est plus vrai pour le refus de politique. Les autres règles (qui peut lire, ordre, refus générique, échec fermé, hors du budget d'actions) sont inchangées.
- (−) **Le nombre exact de refus supprimés n'est pas enregistré.** Au-delà du budget, le refus est le même mais n'écrit plus d'événement : on sait qu'une identité a épuisé son budget (la ligne de journal) et à quel moment, pas combien de fois elle a essayé ensuite. Un événement de synthèse à la fin de l'épisode le dirait ; il demande une échéance et un état de plus, et n'est pas fait.
- (−) ~~**Une lecture servie à un titulaire de politique n'est pas auditée.**~~ **Levé par ADR-0021.** Ce que cette limite disait : on voit qui est refusé, pas qui a lu ; prouver qu'un auditeur a lu une session n'était pas possible.
- (−) **Chaque refus coûte un appel à l'Authorization Service**, budget épuisé ou non : le budget borne ce qu'on **écrit**, pas ce qu'on **interroge**. Un porteur de jeton peut faire interroger l'Authorization Service au rythme que la limite par adresse du Gateway permet (ADR-0015). Non traité ici.
- (−) **Un jeton volé épuise le budget de son titulaire** : après une rafale de refus sous son nom, les vrais refus de la victime ne s'écrivent plus un par un, pendant la durée du déficit. Même limite qu'ADR-0016 ; une identité qui sonde est de toute façon ce que la ligne de journal désigne.
- (−) **Par processus** (règle 8) et **les valeurs par défaut ne sont pas mesurées sur un usage réel** : 10 puis 6 par minute sont des défauts stricts choisis, pas des valeurs dérivées d'une charge. Elles se règlent.
- (−) **Un second limiteur** : le Gateway a le sien (ADR-0014), dans un paquet `internal` d'un autre module, et il répond autre chose (un délai de reprise). Deux petites implémentations du même modèle ; le partage dans un `pkg` est un candidat, pas un défaut mesuré.
- (−) **L'événement ne nomme pas le compte de la session** (seulement son identifiant) : il lui faudrait relire la session au moment de lire l'audit ; la session, elle, est dans le store.

**Alternatives envisagées**
- *Auditer chaque refus, sans budget* : rejeté — une écriture à volonté dans la trace signée pour tout porteur de jeton (mesuré par analogie : ADR-0016, douze refus, douze événements).
- *Ne rien changer, journaliser seulement* : rejeté — un journal n'est ni signé, ni cherchable avec le reste de l'audit, et ADR-0019 lui-même y voyait la limite à lever.
- *Compter dans le Gateway* : rejeté — le Gateway ne sait pas qu'une lecture est refusée tant que le Broker n'a pas répondu ; et ce qu'il compterait serait la réponse, pas l'événement.
- *Prendre le budget d'actions d'ADR-0016* : rejeté — il est pris **avant** que le Broker soit appelé, sans savoir si la lecture sera refusée ; y mettre les lectures limiterait les interfaces qui interrogent l'état à intervalles réguliers, pour borner ce qui ne coûte plus rien à écrire quand elle est servie.
- *« Enregistrer ou refuser » pour les lectures* (une panne de l'audit refuse la lecture) : rejeté — lire n'engage à rien enregistrer, et cela ferait d'une panne de l'audit une panne des lectures du demandeur.
- *Budget par session ou par compte* : rejeté — la sonde change de session à chaque essai ; la rareté à protéger est l'écriture dans la trace, par celui qui la provoque.
- *Un événement de synthèse à la fin d'un épisode* (« 47 refus non écrits ») : repoussé — voir les limites ; à reconsidérer avec un Scheduler.
- *Auditer aussi les lectures servies aux titulaires de politique* : repoussé — c'est une décision d'une autre nature (volume, et ce que « lire » signifie pour un auditeur) ; la limite est écrite. **Repris et fait par ADR-0021**, avec une règle différente (enregistrer avant de servir, sans budget).
- *Partager le limiteur du Gateway dans `pkg/`* : repoussé — il change d'unité (un délai de reprise contre un oui/non) ; à faire quand un troisième usage le justifie.

---

## ADR-0021 — Une lecture servie à un titulaire de politique s'enregistre avant d'être servie, et sans enregistrement elle n'est pas servie

**Contexte**
ADR-0020 avait rendu visibles les refus de lecture et déclaré ce qui restait : *on voit qui est refusé, pas qui a lu — prouver qu'un auditeur a lu une session n'est pas possible.* Or la lecture servie à un titulaire de politique est celle qui **divulgue** : le demandeur, le compte privilégié, la justification (y compris celle d'une urgence), l'échéance. J'ai écrit le test d'abord, sur processus réels (Gateway, Broker, Authorization, Audit derrière un espion qui peut tomber en panne), et constaté qu'il échouait. Ce qui a été **mesuré** (7 sous-cas, **5 en échec avant**) :

- **Une lecture divulguée ne laisse aucune trace.** Carol (rôle `auditor`, politique `session-read` sur le compte) lit la session d'Alice : `200`, avec la justification, le compte et le demandeur ; l'espion d'audit a vu **zéro** événement. Dix-sept lectures de suite : zéro. Un refus, lui, est visible depuis ADR-0020 : l'audit ne sait pas ce qui a été *lu*, seulement ce qui a été *tenté sans droit*.
- **L'audit en panne ne change rien à la divulgation.** L'Audit Service ne répond plus : Carol reçoit toujours `200` avec la justification, le compte et le demandeur. La lecture ne dépend de la trace d'aucune façon : au moment où la trace manque, la divulgation continue.
- **Le Broker sait déjà être strict quand il accorde.** `CreateSession` refuse d'accorder une session si l'événement `session.create` ne s'écrit pas (« audit emission failed (fail-closed, Guide HA §1) »), et l'approbation d'une urgence aussi (ADR-0011). Seule la lecture, qui accorde une *connaissance*, ne l'était pas.
- **Ce qui est déjà écrit et ce qui ne l'est pas.** Les refus (ADR-0020), les créations, décisions, connexions et terminaisons le sont. Ne le sont pas : la lecture de la liste des demandes en attente (ADR-0012) et la lecture de l'enregistrement par le Command Recorder (`GET /sessions/{id}/recording`, qui n'a aucun client d'audit — vérifié). Ces deux-là ne sont **pas traitées ici**.

**Décision**
Huit règles.

1. **Une lecture servie sur la force d'une politique est un événement** `session.read` : `resource_type = session`, `resource_id` = la session, `success = true`, auteur = **l'appelant que le Gateway a vérifié** — jamais le demandeur, jamais une valeur de la requête du client (mêmes règles qu'ADR-0020, règle 1). Le succès distingue cet événement du refus (`success = false`) : un seul nom d'action, deux issues.
2. **Il est écrit *avant* que la session soit servie, et s'il ne s'écrit pas, la lecture n'est pas servie** : `503` (une dépendance ne répond pas), jamais un `403` — ce n'est pas un refus de droit —, et jamais un `404`. Le message ne dit rien de la session ni de la panne ; la cause reste dans le journal du Broker (« reading session … not done »), comme pour toute dépendance muette (ADR-0019, règle 5). La même lecture, renouvelée une fois l'audit rétabli, est servie et enregistrée. C'est **enregistrer ou refuser** (ADR-0008) appliqué à ce qui divulgue.
3. **L'asymétrie est voulue.** Ce qui *réduit* un accès — terminer (ADR-0017), un refus de lecture (ADR-0020) — reste « au mieux » : il n'y a rien à empêcher quand la trace est en panne, la session se termine ou la lecture est refusée de toute façon. Ce qui *accorde* — une session, une approbation, **une connaissance** — est fermé : sans la trace, on ne l'accorde pas.
4. **Pas de budget.** Chaque lecture servie à un titulaire de politique est un événement. Un budget qui supprime un événement, c'est une lecture que personne ne peut prouver : il va à l'encontre de la raison d'être de l'événement. Ce n'est pas le problème d'ADR-0014 et d'ADR-0016 : l'auteur n'est pas un porteur de jeton *sans droit* qui écrit des refus à volonté, c'est une personne à qui un opérateur a **donné** une politique, et chaque événement est vrai (une lecture réelle). La borne est la limite par adresse du Gateway (ADR-0015, 60 puis 60 par minute par défaut) ; le coût est déclaré plus bas. Le budget des refus (ADR-0020) est **autre chose** : une lecture servie n'en dépense aucun jeton, et un budget épuisé ne fait pas taire une lecture servie.
5. **Le demandeur et le décideur n'écrivent rien, et ne dépendent pas de l'audit.** Rien ne leur est divulgué qu'ils n'avaient déjà ; la décision du second est elle-même dans la trace (ADR-0011). Un décideur qui détient aussi une politique de lecture reste le décideur : aucune politique n'est utilisée, donc aucun événement.
6. **L'ordre devient : l'appelant vide (`403`), la session (`404`), l'appelant (`403` ; un refus de politique est un événement d'ADR-0020), l'Authorization Service (`503`), l'audit (`503`), puis la lecture est servie.** L'événement n'est écrit que pour une lecture qui va être servie : ni un `404`, ni un `503` d'Authorization, ni un appelant sans nom, ni un refus n'en écrivent un de succès.
7. **Un événement peut précéder une réponse qui ne parvient pas** (le réseau coupe après l'écriture) : la trace dit une lecture qui n'a peut-être pas été vue. On se trompe du côté de la trace, jamais du côté de la divulgation.
8. **Le Gateway, les schémas et le proto ne changent pas** : il relaie déjà l'appelant vérifié (ADR-0019) et le `503` du Broker. Le contrat OpenAPI de `GET /sessions/{id}` dit désormais que la lecture d'un titulaire de politique est enregistrée avant d'être servie et que son `503` peut venir de l'audit.

**Conséquences**
- (+) On peut **prouver qui a lu quoi** parmi les titulaires de politique, et il n'existe plus de lecture divulguante sans trace : le demandeur et le décideur mis à part, chaque lecture d'une session est un événement signé, sous le nom de la personne authentifiée, ou un refus.
- (+) Une panne de l'audit ne se transforme pas en divulgation sans preuve : la lecture est un `503` qui ne dit rien de la session (mesuré : ni justification, ni compte, ni demandeur, ni identifiant), pendant que le demandeur lit toujours sa session et qu'un refus reste un refus.
- (+) L'événement est dans l'audit **au moment** où la réponse arrive : on peut l'affirmer sans attendre (le test sur processus réels le lit immédiatement après la réponse).
- (+) **Mesuré** (tests rouges avant, puis processus réels et mutations). *Avant* : Carol lit — `200`, zéro événement ; dix-sept lectures — zéro ; audit en panne — `200` avec la justification, le compte et le demandeur ; l'audit revenu — la lecture suivante n'enregistre rien de plus que les autres, c'est-à-dire rien. *Après*, sur processus réels : la lecture de Carol est **un** événement `session.read` en succès **sous son nom**, présent à l'instant où la réponse arrive, jamais sous celui d'Alice, ni sous celui qu'écrit un client dans `?callerId=` ; dix-sept lectures donnent dix-sept événements (aucun budget n'en laisse un de côté) ; Alice lit sa session trois fois : aucun événement ; l'audit en panne : Carol reçoit `503` sans la justification, le compte, le demandeur ni l'identifiant, Alice reçoit `200`, Bob (sans politique) reçoit `403`, et aucun événement n'est enregistré pendant la panne ; l'audit rétabli, la lecture de Carol est servie et laisse **un** événement ; la chaîne d'audit se vérifie encore. **23 mutations** sur le nouveau chemin (événement absent, panne ignorée, rendue en refus ou en « introuvable », cause ou session dans le message, écriture en arrière-plan, nom, type, ressource, issue et auteur de l'événement, qui est enregistré — requérant, décideur, refus, Authorization muette, session absente, appelant sans nom —, budget de refus dépensé ou consulté, refus rendu strict) : les 23 sont tuées. Rejeu des séries précédentes : ADR-0020 79 sur 79 hors 2 équivalentes (B26 et B31, déjà connues), ADR-0019 64 sur 64 hors 1 équivalente (R7, le garde du décideur vide, inatteignable tant que le refus de l'appelant vide tient), ADR-0017 53 sur 53, ADR-0018 96 sur 96. Tests : 561 unitaires sans base (607 avec) ; 52 PostgreSQL ; 39 d'intégration sans base (45 avec) ; `go test -race` propre.
- (−) **Une panne de l'Audit Service rend la lecture d'un auditeur indisponible.** C'est le prix choisi : un auditeur ne peut plus lire les sessions — y compris pour enquêter sur la panne — tant que l'audit ne répond pas. Ce n'est pas une dépendance nouvelle pour la plateforme (accorder une session ou une approbation l'est déjà, Guide HA §1), mais c'en est une nouvelle pour la lecture. Le demandeur et le décideur ne sont pas touchés.
- (−) **Un appel de plus avant de servir** (latence de l'Audit Service) et **deux dépendances** sur le chemin d'un tiers : l'Authorization Service, puis l'audit.
- (−) **Chaque lecture écrit, sans regroupement.** Une interface d'auditeur qui interroge à intervalles réguliers écrit un événement par interrogation. La borne est la limite par adresse du Gateway (ADR-0015) : un titulaire de politique compromis, *K* adresses, peut remplir la trace de lectures **vraies**, à *K* fois ce débit. Les valeurs ne sont pas mesurées sur un usage réel.
- (−) **Le demandeur et le décideur ne sont pas tracés.** Un décideur qui a perdu son rôle relit sans trace ce qu'il avait décidé (la limite d'ADR-0019, « le décideur garde le droit de relire », reste, sans trace).
- (−) **L'événement dit qui a lu quelle session et quand, pas ce qui s'affichait** (l'état à cet instant, l'échéance) **ni le compte** : il faut relire la session.
- (−) **Deux divulgations restent hors de la trace** (voir Contexte) : la liste des demandes en attente (ADR-0012) et la lecture de l'enregistrement par le Command Recorder. La seconde est la plus lourde : ce sont les commandes qui ont été tapées. Candidate à l'ADR suivant.
- (−) **Un événement peut précéder une réponse perdue** (règle 7) : la trace peut dire plus que ce qui a été vu.

**Alternatives envisagées**
- *Écrire « au mieux », comme pour un refus (ADR-0020)* : rejeté — la trace manquerait précisément quand l'audit est en panne, et la divulgation continuerait : on ne pourrait pas affirmer qu'un auditeur a *seul* lu cette session. L'asymétrie de la règle 3 est la raison.
- *Écrire après avoir servi* : rejeté — une panne de l'audit ne pourrait plus empêcher la divulgation, seulement la constater.
- *Appliquer le budget d'ADR-0020* : rejeté — un événement supprimé est une lecture sans preuve ; le budget borne ce qu'un porteur de jeton *sans droit* peut écrire, pas ce qu'une personne *habilitée* a lu.
- *Un `429` au-delà d'un débit de lecture* : rejeté — un code de plus pour une lecture, quand la limite par adresse existe déjà ; et un budget qui refuserait un auditeur légitime au milieu d'une enquête est pire que le volume.
- *Regrouper (un événement par lecteur et par session sur une fenêtre)* : repoussé — il perd les relectures dans la fenêtre alors que l'état de la session change ; à reconsidérer si le volume mesuré l'exige.
- *Auditer aussi le demandeur et le décideur* : rejeté — rien de nouveau ne leur est divulgué, et ce serait un événement par interrogation de leur propre session par une interface qui la suit.
- *Étendre à la liste des demandes en attente et à l'enregistrement dans cet ADR* : repoussé — d'autres routes, dont une d'un autre service (le Command Recorder n'a pas de client d'audit) ; le sujet d'un ADR à part.
- *Un événement de refus distinct* (`session.read_refused`) *plutôt que `success=false`* : rejeté — c'est la convention de tout l'audit du projet (une action, deux issues).

---

## ADR-0022 — Chaque page d'un enregistrement servie s'enregistre avant d'être servie, au nom de celui que le Gateway a vérifié — et sans enregistrement, elle n'est pas servie

**Contexte**
ADR-0021 avait laissé deux divulgations hors de la trace et désigné la plus lourde : *la lecture de l'enregistrement par le Command Recorder — ce sont les commandes qui ont été tapées.* Un enregistrement, c'est ce qu'un opérateur a tapé en root sur une cible de production : les chemins, les bases, les noms de clients, et tout secret passé en argument (`mysql -pXXXX`, Guide Sécurité §12). J'ai écrit le test d'abord, sur processus réels (Authentication, Authorization, Audit derrière un espion qui peut tomber en panne, Command Recorder, Gateway), et constaté qu'il échouait. Ce qui a été **mesuré** (7 sous-cas, **5 en échec avant**) :

- **Une lecture d'enregistrement ne laisse aucune trace.** Carol (rôle `session-auditor`, politique `recording:session:*`) lit l'enregistrement d'une session : `200`, avec `cat /etc/shadow`, `mysql -u root prod_customers` ; l'espion d'audit a vu **zéro** événement. Dix-sept lectures (dont trois pages) : zéro.
- **L'audit en panne ne change rien.** L'Audit Service ne répond plus : Carol reçoit toujours `200` et les trois commandes.
- **Le Recorder ne sait pas qui lit.** Le Gateway ne lui transmettait que les **rôles** du jeton (`?actorRoles=`), pas l'utilisateur ; le Recorder n'avait **aucun client d'audit** et l'Audit Service refusait explicitement `command-recorder` sur `emit-event` (règle et test d'appelants). Il n'y avait personne à nommer, ni de moyen d'écrire.
- **Il n'y a pas de lecteur « naturel ».** À la différence d'une session (ADR-0019 : le demandeur et le décideur lisent sans politique), toute lecture d'un enregistrement passe par la politique `recording:session:read` : l'opérateur ne relit pas sa propre session. Chaque lecture servie est donc une lecture *sur la force d'une politique*, celle qu'ADR-0021 rend fermée.
- **Deux défauts voisins, trouvés en lisant le code.** Une Authorization muette se lisait `403` (« refusé ») : une panne passait pour un refus, et le client ne savait pas qu'il pouvait réessayer — le commentaire de `statusFor` disait lui-même qu'« appeler une panne interdit la cacherait ». Une erreur du store était renvoyée **telle quelle** dans le corps du `500`, que le Gateway relaie au client (adresses et noms de tables possibles).

**Décision**
Huit règles.

1. **Chaque page servie d'un enregistrement est un événement** `recording.read` : `resource_type = session`, `resource_id` = l'identifiant de la session, `success = true`, auteur = **l'utilisateur que le Gateway a vérifié**. La ressource est la *session* (pas `recording:session:…`) : une recherche par session trouve qui l'a ouverte, qui a lu son dossier (`session.read`) et qui a lu ce qui y a été tapé (`recording.read`). Un nom d'action distinct de `session.read`, parce que ce n'est pas la même divulgation.
2. **Il est écrit *avant* que la page soit servie, et s'il ne s'écrit pas, la page n'est pas servie** : `503`, jamais un `403`. C'est la règle d'ADR-0021 (« enregistrer ou refuser » appliqué à ce qui divulgue), sans exception de demandeur puisqu'il n'y en a pas.
3. **Le store est lu avant d'écrire l'événement** : on n'écrit un événement que pour une page qui va être servie (une base en panne ne laisse pas de lecture fantôme) ; la page est tenue dans le Recorder, jamais remise, tant que l'événement n'est pas écrit. Un événement peut encore précéder une réponse qui se perd (ADR-0021, règle 7).
4. **Pas de budget.** Chaque page en est un, une page vide aussi (le Recorder ne sait pas quelles sessions existent ; une page vide est une lecture comme une autre).
5. **Qui lit vient du jeton.** Le Gateway ajoute `?callerId=` (l'utilisateur du jeton vérifié) à côté de `?actorRoles=` ; il ne recopie de la requête du client que `page` et `pageSize`, si bien qu'un `callerId` écrit par le client n'arrive jamais au Recorder. Le Recorder croit `callerId` parce que seul le Gateway peut appeler cette route (ADR-0010). Sans `callerId`, `403`, sans interroger personne. Le proto reçoit le champ additif `actor_user_id = 5` dans `GetCommandRecordingRequest`.
6. **L'ordre est : l'appelant vide (`403`), l'Authorization Service (`403` s'il refuse ; `503` s'il ne répond pas — fermé, mais plus appelé « refusé »), le store (`500`), l'audit (`503`), puis la page est servie.** Un refus n'écrit **rien** (ADR-0020 n'est pas étendu ici, voir les limites). *Amendé par ADR-0024 : un refus de politique est un événement en échec, dans un budget par identité ; un identifiant qui ne peut pas être une session est un `400` avant tout.*
7. **Ce que le client lit d'un échec ne dit rien.** Le `503` et le `500` du Recorder ont un corps générique (le texte du statut) ; la cause — adresse de l'audit, erreur de la base — reste dans le journal du Recorder (« reading the recording of session … for user … not done: … »).
8. **Le Recorder écrit à l'audit, et à lui seul ce droit est ajouté.** `AUDIT_URL` (défaut `127.0.0.1:8082`, client mTLS épinglé à `audit-service`), **sans réglage pour s'en passer** ; la règle `POST /audit/v1/emit-event` de l'Audit Service nomme désormais `command-recorder`, pour cette méthode seulement. L'écriture des commandes par le proxy (`command-entries`, ADR-0008) n'en dépend pas.

**Conséquences**
- (+) **On peut prouver qui a lu ce qui a été tapé**, page par page, sous le nom de la personne authentifiée, et il n'existe plus de lecture d'enregistrement sans trace : chaque lecture servie est un événement signé, ou n'a pas eu lieu.
- (+) **Une panne de l'audit ne se transforme pas en divulgation sans preuve** : `503`, sans les commandes, ni l'identifiant de la session, ni la cause (mesuré).
- (+) Une panne de l'Authorization Service se dit `503` au lieu de `403`, et une erreur de la base ne traverse plus le Gateway jusqu'au client.
- (+) **Mesuré** : *Avant* (test sur processus réels, 5 sous-cas sur 7 rouges) : Carol lit — `200`, zéro événement ; dix-sept lectures — zéro ; audit en panne — `200` avec les trois commandes. *Après*, sur processus réels (Authentication, Authorization, Audit derrière un espion, Command Recorder, Gateway) : la lecture de Carol est **un** événement `recording.read` en succès **sous son nom**, ressource `session`, présent à l'instant où la réponse arrive ; une requête forgée `?callerId=<Alice>&actorUserId=<Alice>&actorRoles=platform-admin` est servie à Carol et écrite sous **son** nom ; trois pages puis douze lectures donnent dix-sept événements pour dix-sept lectures ; Bob (sans politique) a `403`, sans commande ni événement de succès ; l'audit en panne : Carol reçoit `503` sans les commandes, l'identifiant de la session, la cause ni l'adresse de l'audit, Bob a toujours `403`, aucun événement n'est écrit ; l'audit revenu, la lecture est servie et laisse **un** événement ; la chaîne d'audit se vérifie. En unitaire : un événement par page aux champs exacts, page vide comprise ; pas de nom ⇒ `403` sans interroger Authorization ni l'audit ; Authorization muette ⇒ `ErrUnavailable`, rien de servi, rien d'écrit ; store en panne ⇒ ni refus ni indisponibilité, rien d'écrit ; corps `503`/`500` génériques et cause au journal ; client d'audit qui ne croit qu'un `200` ; Gateway qui écarte le `callerId` du client ; règle d'appelants (`command-recorder` en `POST` seulement). **32 mutations, toutes tuées** (31 d'emblée ; la dernière, « tout statut accepté » par le client d'audit, ne compilait pas sous sa première forme : réécrite, tuée) : événement absent, écrit en arrière-plan, avant la lecture du store ou pour un refus ; panne de l'audit ignorée, appelée refus ou panne du store ; auteur, action, type, ressource et issue de l'événement ; appelant vide accepté ; Authorization muette appelée refus ou qui sert ; `callerId` non lu ; cause dans le corps ; cause absente du journal ; `503` rendu `500` ; client d'audit (tout statut, tout 2xx, erreur réseau ignorée, chemin, champs inversés) ; Gateway (pas de `callerId`, celui du client, celui du client préféré) ; règle d'appelants (Recorder absent, sur toute méthode, tout le monde) ; composition (pair d'audit épinglé à la mauvaise identité, `AUDIT_URL` ignorée — tuées par les tests sur processus réels, mTLS compris). Les séries de mutations d'ADR-0017 à ADR-0021 n'ont **pas** été rejouées (elles ne sont pas dans le dépôt). Tests : 570 unitaires sans base (46 ignorés), 616 avec ; 52 PostgreSQL ; 40 d'intégration sans base (6 ignorés), 46 avec ; `go test -race` propre sur les modules touchés et le test d'intégration nouveau.
- (−) **Une panne de l'Audit Service rend les enregistrements illisibles** — y compris pour enquêter sur la panne. C'est le prix d'ADR-0021, choisi à nouveau. Le proxy, lui, continue d'enregistrer les commandes.
- (−) ~~**Un refus de lecture d'un enregistrement n'est pas audité.**~~ **Levé par ADR-0024.** Une sonde sur `recording:session:*` reste invisible ; c'est ce qu'ADR-0020 a fait pour les sessions, avec un budget. Non fait ici : un second budget par identité dans un autre service (ce serait le troisième limiteur — candidat au partage dans `pkg/`, ADR-0020).
- (−) **Le Recorder peut écrire dans la trace.** Un Recorder compromis peut y écrire des événements au nom de n'importe qui, comme le Broker et le proxy : les événements ne sont pas attribués par l'identité du certificat émetteur (limite déjà connue, `architecture.md`).
- (−) **L'événement ne dit ni la page, ni le nombre de commandes servies**, seulement la session : le port d'audit n'a pas de champ de détail. Lire un enregistrement de 100 pages en écrit 100 qui se ressemblent.
- (−) **Chaque page écrit, sans regroupement** ; la borne est la limite par adresse du Gateway (ADR-0015). Une interface qui suit un enregistrement en direct en écrit un par interrogation.
- (−) **Un appel de plus, et deux dépendances** (Authorization puis audit) avant de servir.
- (−) **Une page dont la réponse se perd après l'écriture** est dans la trace sans avoir été vue (on se trompe du côté de la trace).

**Alternatives envisagées**
- *Faire écrire l'événement par le Gateway* : rejeté — le Gateway ne sait pas si la lecture sera servie (il ne voit que la réponse, après), et le faire après serait écrire après avoir servi ; il n'a pas non plus de client d'audit, et n'en doit pas avoir.
- *Écrire après avoir servi, ou en arrière-plan* : rejeté — une panne de l'audit constaterait la divulgation sans pouvoir l'empêcher (ADR-0021).
- *Écrire avant de lire le store* : rejeté — une base en panne laisserait un événement pour une page jamais lue ; lire d'abord coûte une lecture de base quand l'audit est en panne, rien de plus.
- *Un budget ou un regroupement par lecteur et par session* : rejeté pour le budget (une page supprimée est une lecture sans preuve), repoussé pour le regroupement (il perd les pages relues pendant que l'enregistrement grandit).
- *Réutiliser `session.read`* : rejeté — on ne distinguerait plus « a lu le dossier de la session » de « a lu ce qui y a été tapé », la divulgation la plus lourde.
- *Une ressource `recording`* : rejeté — la session est l'objet qu'un enquêteur cherche ; l'action dit déjà ce qui a été lu.
- *Auditer aussi les refus, dans un budget* : repoussé — voir les limites.
- *Garder `403` quand l'Authorization Service ne répond pas* : rejeté — c'est appeler une panne un refus ; le Broker répond `503` dans le même cas (ADR-0019).

---

## ADR-0023 — Chaque demande servie par la liste des demandes en attente s'enregistre avant d'être servie — et sans enregistrement, la liste n'est pas servie

**Contexte**
ADR-0021 et ADR-0022 ont laissé une seule divulgation hors de la trace : la liste des demandes break-glass en attente (ADR-0012), `GET /sessions?status=pending_approval`. Elle montre à un approbateur, pour chaque demande, ce qu'ADR-0021 trace quand on la lit par son identifiant : le demandeur, le compte privilégié, la durée et la **justification d'une urgence** (« enregistreur en panne pendant l'incident P1 »). J'ai écrit le test d'abord, sur processus réels (Authentication, Authorization, Audit derrière un espion qui peut tomber en panne, Session Broker, Gateway), et constaté qu'il échouait. Ce qui a été **mesuré** (8 sous-cas, **5 en échec avant**) :

- **Une liste servie ne laisse aucune trace.** Bob (politique `breakglass-approve:account:…`) liste les demandes : `200`, avec la justification ; l'espion d'audit a vu **zéro** événement. Cinq listes, deux demandes : zéro.
- **L'audit en panne ne change rien** : Bob reçoit toujours `200`, avec la justification, le compte et le demandeur.
- **Ce qui était déjà juste.** Le Gateway transmet déjà l'appelant vérifié (ADR-0012, règle 3), un appelant sans nom est déjà refusé, une page vide ne dit pas si des demandes existent, et une dépendance muette donne déjà `503` sans liste partielle. Il ne manquait que la trace.
- **Toute la liste passe par une politique.** Les demandes de l'appelant en sont exclues (ADR-0012) : il n'y a pas de lecteur « naturel », chaque demande servie l'est sur la force d'une politique — le cas qu'ADR-0021 rend fermé.

**Décision**
Sept règles.

1. **Chaque demande de la page servie est un événement** `session.listed` : `resource_type = session`, `resource_id` = l'identifiant de la demande, `success = true`, auteur = **l'appelant que le Gateway a vérifié**. Un événement *par demande*, pas un par liste : la question d'un enquêteur est « à qui cette justification a-t-elle été montrée ? », et elle se pose par session. Un nom d'action distinct de `session.read`, pour distinguer « vu dans une liste » de « ouvert par son identifiant ».
2. **Seulement ce qui est servi.** Les demandes de la page renvoyée — pas celles comptées dans `totalItems`, pas celles que le filtre d'autorité a écartées, pas les autres pages.
3. **Écrit avant de servir ; un seul événement qui ne s'écrit pas, et la page n'est pas servie** (`503`, le corps générique d'ADR-0012, la cause dans le journal du Broker). C'est la règle d'ADR-0021, et c'est cohérent avec ADR-0012 : jamais de liste partielle.
4. **Une page vide n'écrit rien, et ne dépend pas de l'audit** : elle ne divulgue rien. Un approbateur sans demande à décider peut interroger la liste sans remplir la trace.
5. **Pas de budget** : chaque liste servie écrit à nouveau (ADR-0021, règle 4).
6. **L'ordre est inchangé, l'audit vient en dernier** : appelant sans nom (`403`), break-glass éteint (page vide), store (`503`), Authorization par compte (`503`), pagination, **audit (`503`)**, puis la page est servie.
7. **Le Gateway, les schémas et le proto ne changent pas.** Le contrat OpenAPI de `GET /sessions` dit désormais que chaque demande servie est enregistrée avant de l'être, et que le `503` peut venir de l'audit.

**Conséquences**
- (+) **Il n'existe plus, dans le Broker et le Recorder, de lecture divulguante sans trace** : la session par son identifiant (ADR-0021), l'enregistrement (ADR-0022) et la liste (cet ADR) sont chacun un événement signé sous le nom de la personne authentifiée — le demandeur et le décideur d'une session mis à part (ADR-0021, règle 5).
- (+) **On peut répondre à « à qui cette justification d'urgence a-t-elle été montrée ? »** en cherchant la session dans l'audit.
- (+) **Mesuré** : *Avant* (processus réels, 5 sous-cas sur 8 rouges) : Bob liste — `200` avec la justification, zéro événement ; cinq listes de deux demandes — zéro ; audit en panne — `200` avec la justification, le compte et le demandeur. *Après*, sur processus réels : la demande servie à Bob est **un** événement `session.listed` en succès **sous son nom** (jamais sous celui du demandeur), ressource `session`, présent à l'instant où la réponse arrive ; une requête forgée `&callerId=<le demandeur>&actorRoles=platform-admin` est écrite sous le nom de Bob ; trois listes de deux demandes ajoutent trois événements par demande ; une page de taille 1 n'écrit que la demande servie ; la liste vide d'Alice (sans autorité) n'écrit rien, y compris l'audit en panne, où elle reste `200` ; l'audit en panne, Bob reçoit `503` sans la justification, le compte, le demandeur ni les identifiants, et rien n'est écrit ; l'audit revenu, la liste est servie avec un événement par demande ; la chaîne se vérifie ; le test d'ADR-0012 passe inchangé. En unitaire : les champs exacts, seulement la page servie, 25 listes = 25 événements, trois sortes de pages vides sans événement, rien de servi sans l'audit puis servi à son retour, rien d'écrit pour une liste non décidée (Authorization muette, appelant sans nom). **14 mutations, toutes tuées** (événement absent, panne ignorée, appelée refus, servie après une panne en milieu de page, écritures en arrière-plan, auteur demandeur, action `session.read`, type, ressource du compte, issue, toutes les demandes visibles au lieu de la page, un seul événement par liste, toute la lecture avant le filtre, un événement pour une page vide). La série d'ADR-0022 n'a pas été rejouée (son code n'a pas changé). Tests : 575 unitaires sans base (46 ignorés), 621 avec ; 52 PostgreSQL ; 41 d'intégration sans base (6 ignorés), 47 avec ; `go test -race` propre sur le Broker et sur les tests d'intégration de la liste.
- (−) **Une panne de l'Audit Service cache les urgences en attente à leurs approbateurs.** Ce n'est pas une capacité perdue : approuver une demande dépend déjà de l'audit (ADR-0011, fail-closed), et la notification d'ADR-0012 continue d'annoncer les demandes. Mais l'approbateur ne voit plus la file pendant la panne.
- (−) **Une interface qui interroge la liste écrit un événement par demande et par interrogation**, sans regroupement. Trois demandes en attente et une interrogation toutes les 30 secondes : six événements par minute et par approbateur. La borne est la limite par adresse du Gateway (ADR-0015) et le plafond de demandes par demandeur (ADR-0013).
- (−) **Les écritures sont séquentielles** : au plus `pageSize` appels à l'Audit Service (100) avant de servir une page de 100. Le port d'audit n'a pas d'écriture par lot.
- (−) **Une écriture qui échoue au milieu d'une page** laisse dans la trace les demandes déjà écrites, sans qu'elles aient été vues (on se trompe du côté de la trace, ADR-0021 règle 7).
- (−) **Une demande vue dans plusieurs listes successives** donne autant d'événements : on sait qu'elle a été montrée, et combien de fois, pas si elle a été lue.

**Alternatives envisagées**
- *Un seul événement par liste* (ressource « liste », sans identifiant) : rejeté — il ne dit pas quelles justifications ont été montrées, ce qui est la question.
- *Réutiliser `session.read`* : rejeté — on ne distinguerait plus une liste d'une lecture par identifiant.
- *Écrire aussi pour une page vide* : rejeté — rien n'est divulgué, et une interface d'approbateur sans demande écrirait à chaque interrogation.
- *Servir la liste au mieux quand l'audit est en panne* : rejeté — c'est la divulgation sans preuve qu'ADR-0021 a refusée ; et l'approbation, elle, dépend déjà de l'audit.
- *Écrire en parallèle* : repoussé — plus rapide, mais une page partiellement écrite dans un ordre quelconque ; à reconsidérer si une écriture par lot arrive au port d'audit.
- *Un budget* : rejeté (ADR-0021, règle 4).

---

## ADR-0024 — Auditer les refus de lecture d'un enregistrement, dans un budget par identité — et un seul seau à jetons, partagé

**Contexte**
ADR-0022 avait rendu chaque lecture servie d'un enregistrement visible et déclaré la limite : *un refus de lecture d'un enregistrement n'est pas audité — une sonde sur `recording:session:*` reste invisible.* J'ai écrit le test d'abord, sur processus réels (Authentication, Authorization, Audit derrière un espion, Command Recorder, Gateway), et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Une sonde est invisible.** Bob (aucune politique) demande l'enregistrement d'une session : `403`, **zéro** événement. Mallory, onze fois sur deux sessions : onze `403`, zéro événement, aucune ligne de journal.
- **L'identifiant vient de l'appelant, sans borne.** Le Recorder lisait n'importe quel identifiant de session dans le chemin : un refus écrit tel quel aurait mis dans la trace signée une chaîne choisie par le porteur de jeton, de la taille qu'il veut (l'Audit Service ne borne ni le corps d'`emit-event` ni ses champs — vérifié en lisant le code). Une lecture servie (ADR-0022) avait déjà ce défaut pour un titulaire de politique : un identifiant de 257 octets était servi (page vide) et écrit. `Record`, lui, refuse depuis toujours un identifiant de plus de 256 octets : aucune session enregistrée ne peut en avoir un.
- **Le modèle existe déjà.** ADR-0020 a résolu exactement ce problème pour les sessions avec un seau à jetons par identité (`RefusalBudget`, dans le Broker), et avait noté : *partager le limiteur dans `pkg/` quand un troisième usage le justifie.* Le Recorder serait la troisième implémentation du même modèle (après le Gateway et le Broker) et la deuxième identique.

**Décision**
Huit règles.

1. **Un refus de politique est un événement** `recording.read` : `resource_type = session`, `resource_id` = l'identifiant demandé, **`success = false`**, auteur = l'utilisateur que le Gateway a vérifié. Le même nom d'action que la lecture servie (ADR-0022) : une action, deux issues.
2. **Seul ce refus écrit, de ce côté-là.** Un appelant sans nom (`403`), une Authorization muette (`503`) et un identifiant qui ne peut pas être une session (`400`) n'écrivent rien.
3. **Dans un budget par identité**, le même qu'ADR-0020 : rafale `RECORDING_READ_AUDIT_BURST` (**10**, de 1 à 1000), puis `RECORDING_READ_AUDIT_RATE_PER_MINUTE` (**6**, de 1 à 600) ; une valeur invalide arrête le Recorder en nommant la variable ; ni « illimité » ni « désactivé » ; un Recorder construit à la main a le budget strict ; la ligne de démarrage dit le budget appliqué, « per process ». Le budget est celui de l'identité, pas de la session ; une lecture servie n'en dépense aucun jeton.
4. **La réponse ne dépend jamais du budget ni de l'audit** : le même `403`, même message, que l'événement soit écrit, supprimé ou perdu. L'écriture est **au mieux** (ce qui réduit un accès, ADR-0021 règle 3) ; une panne laisse une ligne de journal avec sa cause.
5. **Une ligne de journal par épisode** quand le budget d'une identité est épuisé, pas une par refus.
6. **Un identifiant qui ne peut pas être une session est refusé avant toute question** : vide, plus de 256 octets (la borne de `Record`) ou pas UTF-8 ⇒ `400` « not a session id », pour tout le monde, sans interroger l'Authorization Service et sans événement. Aucune lecture, servie ou refusée, n'écrit plus dans la trace une chaîne arbitraire. C'est un contrôle de forme : il ne dit rien de l'existence d'une session.
7. **Un seul seau à jetons, partagé** : le `RefusalBudget` du Broker devient le module `pkg/refusalbudget` (bibliothèque standard seulement, ses 13 tests déplacés avec lui), utilisé par le Broker et le Recorder. Le comportement du Broker ne change pas ; ses constantes publiques (`DefaultReadAuditBurst`…) renvoient à celles du module. Le limiteur du Gateway reste à part (il répond un délai de reprise, pas un oui/non).
8. **Le Gateway, les schémas et le proto ne changent pas.** Le contrat OpenAPI de `GET /sessions/{id}/recording` dit le `400` et que le `403` est audité dans la limite du budget. ADR-0022 est **amendé** sur sa règle 6 (« un refus n'écrit rien »).

**Conséquences**
- (+) Une sonde sur les enregistrements est visible là où l'on cherche les tentatives, sous le nom de qui a essayé, sans ouvrir la trace à l'écriture à volonté : au plus 10 événements d'un coup par identité, puis 6 par minute, par processus.
- (+) Aucune lecture n'écrit plus dans la trace un identifiant arbitraire : la taille d'un événement écrit par le Recorder est bornée.
- (+) Un seul seau à jetons au lieu de deux copies : une correction du modèle vaut pour les deux services.
- (+) **Mesuré** : *Avant* (processus réels, rouge) : Bob refusé — zéro événement ; onze refus de Mallory sur deux sessions — zéro ; un identifiant de 257 octets — `403` à Alice et `200` (page vide) à Carol, avec un événement portant cet identifiant ; le Recorder démarrait avec n'importe quelle valeur de budget, sans rien dire. *Après*, sur processus réels : le refus de Bob est **un** `recording.read` en échec **sous son nom**, ressource `session`, l'identifiant demandé ; une requête forgée `?callerId=<Alice>&actorRoles=session-auditor` est refusée et écrite sous le nom de Bob ; avec un budget de 3 puis 1 par minute, onze refus de Mallory sur deux sessions sont **onze `403` identiques** et **trois** événements, et le budget de Bob n'est pas entamé ; cinq lectures servies de Carol ne sont pas des refus et sont cinq événements de succès (ADR-0022 tient) ; l'audit en panne, un refus est le même `403` ; un identifiant de 257 octets est un `400` pour Alice comme pour Carol, sans événement ; la chaîne se vérifie ; une configuration invalide (`0`, négatif, au-dessus des bornes, texte, décimal, « off », « unlimited ») arrête le Recorder en nommant la variable, les bornes sont acceptées, et la ligne de démarrage dit le budget appliqué. En unitaire : champs exacts, rafale par défaut de 10 sur 25 refus, budget propre à chaque identité, un jeton dix secondes plus tard, même refus écrit / supprimé / perdu, une ligne de journal par épisode, panne de l'audit journalisée avec sa cause, lectures servies sans jeton dépensé, rien d'écrit pour un appelant sans nom, une Authorization muette ou un identifiant impossible (qui n'atteint pas l'Authorization Service), 256 octets toujours lus ; `400` en HTTP. **25 mutations** (refus absent, écrit en succès, sous le nom de la session, sur la ressource RBAC ; budget absent, par session, ignoré, dépensé par une lecture servie ; réponse qui dépend du budget ; panne de l'audit rendue `503` ; une ligne de journal par refus ; refus perdu non journalisé ; borne absente, décalée d'un, UTF-8 et vide non contrôlés ; `400` rendu `500` ; composition : nom et bornes des variables, débit ignoré, ligne de démarrage menteuse ; module partagé : seau non plafonné, un seul seau pour toutes les clés, horloge qui recule, défaut non strict) : 24 tuées d'emblée, **une survivante réelle** (`400` rendu `500`, vu seulement par l'intégration) **close par un test HTTP**, 25 sur 25. Rejeu de la série d'ADR-0022 sur le code modifié : 30 tuées sur 30 applicables (deux motifs réécrits, C1 et A6 ; A14 est devenue R2). Tests : 582 unitaires sans base (46 ignorés), 628 avec ; 52 PostgreSQL ; 43 d'intégration sans base (6 ignorés), 49 avec ; `go test -race` propre sur `pkg/refusalbudget`, le Broker, le Recorder et les tests d'intégration des lectures.
- (−) **ADR-0022 est amendé** : un refus n'est plus silencieux.
- (−) **Le nombre exact de refus supprimés n'est pas enregistré** (même limite qu'ADR-0020).
- (−) **Un jeton volé épuise le budget de son titulaire** (même limite qu'ADR-0016 et ADR-0020).
- (−) **Chaque refus interroge toujours l'Authorization Service** : le budget borne ce qu'on écrit, pas ce qu'on interroge.
- (−) **Par processus** : *N* répliques du Recorder, *N* fois le budget.
- (−) **Un module de plus** dans le `go.work` et deux `replace` locaux ; un changement de `pkg/refusalbudget` change deux services à la fois (voulu, mais à tester des deux côtés).
- (−) **L'Audit Service lui-même ne borne toujours rien** (corps ni champs d'`emit-event`) : ce sont les émetteurs qui bornent. Constaté, non traité ici.

**Alternatives envisagées**
- *Copier `RefusalBudget` dans le Recorder* : rejeté — deux copies identiques du même code de sécurité, dont une finirait par diverger ; ADR-0020 avait prévu le partage au troisième usage.
- *Mettre le seau dans `pkg/proxycore` ou `pkg/mtls`* : rejeté — ni l'un ni l'autre n'est le sien, et `pkg/mtls` doit rester sans dépendance de domaine.
- *Auditer chaque refus, sans budget* : rejeté (ADR-0020 : une écriture à volonté dans la trace pour tout porteur de jeton).
- *Tronquer un identifiant trop long au lieu de le refuser* : rejeté — l'événement nommerait une session que personne n'a demandée.
- *Borner dans l'Audit Service* : à faire, mais c'est un autre service et une autre décision (refuser un événement trop gros fait échouer ce qui doit être fermé) ; repoussé, la limite est écrite.
- *Un budget commun aux refus de sessions et d'enregistrements* : rejeté — deux services, deux processus ; il faudrait un état partagé.

---

## ADR-0025 — L'Audit Service ne prend dans la trace que ce qu'un émetteur peut vouloir dire

**Contexte**
ADR-0024 l'avait constaté en lisant le code : l'Audit Service ne borne ni le corps d'`emit-event`, ni aucun de ses champs. Les émetteurs le faisaient chacun de leur côté (le Recorder borne l'identifiant de session depuis ADR-0024), mais la trace signée est l'endroit où une valeur, une fois chaînée, reste pour toujours. J'ai écrit le test d'abord, sur un processus réel, et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Tout est pris.** Un corps de 1 Mio est chaîné (`200`) ; une action « session read » (avec une espace), une action en capitales, un identifiant avec un saut de ligne — une fausse ligne dans tout journal qui l'affiche —, un octet d'échappement de terminal, un identifiant de 257 octets : tous chaînés.
- **Les erreurs parlaient trop.** Un corps qui n'est pas du JSON recevait le message du décodeur (qui nomme la structure Go interne) ; une erreur du store était renvoyée telle quelle à l'émetteur (adresse de la base, nom de table).
- **La méthode n'était pas vérifiée** : hors mTLS, un `GET` était décodé (`400`, pas `405`).
- **Ce que les émetteurs écrivent vraiment** (relevé de tous les appels) : quinze actions, toutes en minuscules à points et soulignés (`session.breakglass_requested`, `recording.read`…), un seul type (`session`), des identifiants de session créés par le Broker ou bornés à 256 octets par le Recorder, un auteur qui est un identifiant d'utilisateur ou vide (le proxy).

**Décision**
Six règles.

1. **Chaque champ a une forme et une taille** : `action` de 1 à 64 octets dans `[a-z0-9_.]` ; `resource_type` de 1 à 64 octets dans `[a-z0-9_]` ; `resource_id` de 1 à 256 octets et `actor_id` de 0 à 256 octets (vide = action système), en UTF-8 valide **sans caractère de contrôle**. Les bornes sont plus larges que tout ce qui est émis aujourd'hui.
2. **Le corps est borné à 16 Kio** (le plus gros événement permis tient en moins de 2 Kio de JSON) : au-delà, `413`, sans le lire en entier.
3. **Validé avant de toucher la chaîne** : un événement refusé ne prend pas de verrou, ne lit pas le dernier hash, n'est pas ajouté.
4. **Un refus nomme le champ et la règle, jamais la valeur** (`400`) ; un corps qui n'est pas du JSON reçoit un message fixe ; une erreur du store est un `500` générique, sa cause au journal de l'Audit Service.
5. **`POST` seulement** (`405`), même hors mTLS.
6. **Les émetteurs ne changent pas de comportement** : pour eux, un `400` est un échec d'écriture comme une panne — fermé là où ils sont fermés (création de session, lecture servie…), au mieux ailleurs. Le Recorder refuse en amont (`400`, « not a session id ») un identifiant qui contient un caractère de contrôle, pour qu'aucune lecture servie ne bute sur l'audit avec un `503` incompréhensible.

**Conséquences**
- (+) La trace n'est plus un endroit où l'on stocke ce qu'on veut : forme et taille de chaque événement sont bornées, et aucun identifiant ne peut y forger une ligne de journal.
- (+) Un émetteur défaillant ou usurpé qui écrit hors de la forme est refusé et le dit dans son journal.
- (+) **Mesuré** : *Avant* (processus réel, rouge) : un corps de 1 Mio, une action « session read », une action en capitales, un identifiant avec un saut de ligne ou un échappement de terminal, 257 octets : tous chaînés (`200`) ; `GET` répondu `400`. *Après*, sur processus réel : les quinze actions émises aujourd'hui, avec et sans auteur, et un identifiant de 256 octets sont pris ; treize formes hors bornes sont des `400` qui ne répètent rien de ce qui a été envoyé ; 1 Mio est un `413` ; `GET` est un `405` ; la chaîne prend encore des événements et se vérifie. En unitaire : les bornes exactes sont acceptées, quinze formes refusées sans que l'erreur répète la valeur, ni brute ni échappée, et la chaîne n'en garde aucune ; en HTTP : `400` qui nomme le champ, corps non JSON ou mal typé sans citer le corps ni le code, 17 Kio `413` et 15 Kio `200`, `405` pour trois méthodes, erreur du store générique et journalisée. Le Recorder refuse en amont un identifiant avec un caractère de contrôle. **24 mutations distinctes** (validation absente ; longueur des noms et des identifiants absente ou décalée d'un ; capitales, tiret, point dans le type acceptés ; action, type ou identifiant vides acceptés ; auteur vide refusé ou auteur non contrôlé ; UTF-8 et caractères de contrôle non contrôlés ; valeur répétée dans l'erreur ; corps non borné, borne trop petite, `413` rendu `400` ; message du décodeur renvoyé ; événement invalide rendu `500` ; erreur du store renvoyée ou non journalisée ; toute méthode ; Recorder qui accepte un caractère de contrôle) : 19 tuées d'emblée, **2 survivantes réelles** (l'erreur qui répète la valeur sous sa forme échappée ; le message du décodeur, qui nomme la structure Go interne) **closes par deux tests**, 3 réécrites parce qu'elles ne compilaient pas (import devenu inutile) et tuées ; une vingt-cinquième, doublon de la première, retirée du compte. Tests : 586 unitaires sans base (46 ignorés), 632 avec ; 52 PostgreSQL ; 44 d'intégration sans base (6 ignorés), 50 avec ; `go test -race` propre sur l'Audit Service, le Recorder et les tests d'intégration concernés.
- (−) **Les bornes sont dans le code** ; un futur émetteur dont les valeurs sortent de la forme (une action avec un tiret, un identifiant de 300 octets) sera refusé — c'est voulu, et cela se lit dans son journal, mais il faudra élargir la règle dans l'Audit Service.
- (−) **Un émetteur compromis écrit toujours des événements vrais dans la forme, au nom de n'importe qui** : les événements ne sont pas attribués par l'identité du certificat (limite connue).
- (−) **Le hash de la chaîne concatène les champs sans séparateur ni longueur** (constaté en lisant `computeHash` pendant cet incrément) : un octet déplacé d'un champ au voisin laisse le hash inchangé. Les bornes ne le corrigent pas. **Objet d'ADR-0026.**

**Alternatives envisagées**
- *Laisser chaque émetteur borner* : rejeté — la trace dépend alors du moins soigneux, et d'un certificat d'émetteur volé.
- *Tronquer ou échapper au lieu de refuser* : rejeté — l'événement chaîné ne serait plus celui qui a été émis.
- *Refuser les champs inconnus du JSON* : rejeté — ils ne sont ni stockés ni hachés ; les refuser casserait un ajout de champ futur (le proto est additif).
- *Une liste fermée d'actions connues* : repoussé — plus strict, mais chaque nouvelle action demanderait de changer l'Audit Service en même temps que l'émetteur ; l'alphabet suffit à ce que la trace ne contienne rien d'arbitraire.

---

## ADR-0026 — Le hash d'un événement d'audit couvre chaque champ comme un champ : un format versionné, et l'ancien seulement pour vérifier

**Contexte**
En lisant `computeHash` pendant ADR-0025, j'ai trouvé que le hash de chaque événement était le SHA-256 de ses champs **concaténés tels quels** : `prev_hash ‖ id ‖ actor_id ‖ action ‖ resource_type ‖ resource_id ‖ success ‖ ts`. Deux suites de champs qui s'écrivent avec les mêmes octets ont donc le même hash. J'ai écrit le test d'abord, et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Un octet déplacé entre deux champs voisins n'est pas vu.** Sur les cinq frontières (`id`/`actor_id`, `actor_id`/`action`, `action`/`resource_type`, `resource_type`/`resource_id`, un champ vidé dans son voisin), un événement stocké modifié ainsi laisse `VerifyChain` dire la chaîne intègre : **5 sur 5 non détectés**. Exemple : `actor_id = user_ab`, `action = session.read` réécrits en `user_a` / `bsession.read`, ou `action = session.rea`, `resource_type = dsession` : même hash, même lien.
- **Ce que les documents affirmaient** : « toute altération rétroactive d'un événement casse la chaîne » (doc 06, Guide Sécurité). C'était faux pour cette forme d'altération — qui ne demande même pas de recalculer un hash.
- **Ce que les documents ne disaient pas** : la chaîne n'a **pas de clé**. Quelqu'un qui peut écrire dans `audit_events` peut modifier un événement et recalculer **toute la fin** de la chaîne : `verify-chain` la dira intègre. Seule une modification qui laisse intacts les événements suivants est détectée. Cette limite n'était écrite nulle part (le README disait « même quand l'attaquant recalcule le hash de l'événement modifié », sans dire « et pas les suivants »).
- **Des chaînes existent déjà** au format actuel, en PostgreSQL : les re-hacher détruirait la preuve qu'elles portent ; un nouveau format doit coexister avec l'ancien.

**Décision**
Sept règles.

1. **Format 2** : `SHA-256( "openbastion.audit.event.v2" 0x00 ‖ L(prev_hash) ‖ L(id) ‖ L(actor_id) ‖ L(action) ‖ L(resource_type) ‖ L(resource_id) ‖ success (1 octet) ‖ ts en nanosecondes (8 octets, gros-boutiste) )`, où `L(x)` est la longueur de `x` sur 4 octets gros-boutistes suivie de `x`. L'étiquette de domaine empêche qu'un hash d'un format soit pris pour celui d'un autre format ou d'un autre type d'enregistrement.
2. **Seul le format 2 s'écrit.** Le format 1 (la concaténation) est gardé **pour vérifier** les événements écrits avant, et jamais pour en écrire.
3. **La version est stockée avec l'événement** : colonne `hash_version SMALLINT NOT NULL DEFAULT 1`, ajoutée en place (`ADD COLUMN IF NOT EXISTS`) — les lignes existantes reçoivent 1, ce qui est vrai ; toute ligne écrite depuis porte 2. La version est couverte par le hash v2 lui-même (l'étiquette) : changer la version d'une ligne v2 change le hash qu'elle doit avoir.
4. **Une version ne recule jamais dans la chaîne** : après une ligne v2, une ligne v1 est une falsification (on ne peut pas faire passer un événement récent pour un événement de l'ancien format, plus faible).
5. **Une version inconnue n'a pas de hash** (`nil`) et est refusée par `VerifyChain` avant même la comparaison — une ligne au hash vide (`''`, que `BYTEA NOT NULL` accepte) sous une version inventée « correspondrait » sinon à ce `nil`.
6. **Les formats sont figés** par des vecteurs de référence calculés indépendamment du code (Python, à partir de la description de chaque format) ; le vecteur v1 prouve que l'ancien format n'a pas bougé. Changer un format, c'est créer une version 3.
7. **Pas de clé dans cet ADR.** Rendre la chaîne résistante à un recalcul complet demande une clé hors de la base (HMAC) ou un ancrage du dernier hash hors de la base : c'est une autre décision (gestion de clé, rotation, vérification par l'outil d'exploitation), repoussée ; la limite est écrite partout où l'intégrité est promise.

**Conséquences**
- (+) **Tout événement écrit depuis ADR-0026 est protégé contre le déplacement d'octets entre champs**, et contre le changement de sa version.
- (+) **Les chaînes existantes se vérifient toujours** et continuent au format 2, sans migration de données.
- (+) **Les documents disent maintenant la vérité** sur ce que la chaîne détecte, et sur ce qu'elle ne détecte pas.
- (+) **Mesuré** : *Avant* (unitaire, rouge) : un octet déplacé sur chacune des cinq frontières — 5 sur 5 non détectés. *Après* : 5 sur 5 détectés ; un nouvel événement est au format 2 (et son hash diffère du format 1) ; une chaîne v1 se vérifie, continue en v2 (le premier v2 chaîne sur le dernier v1) et se vérifie ; v1-v1-v2-v2 accepté, v2-v1, v1-v2-v1-v2, une version 3, 0 ou négative refusés même avec hashes et liens recalculés ; une ligne v2 relabellisée 1 ou 3 et une ligne v1 relabellisée 2 sont détectées ; une version inconnue n'a pas de hash ; une ligne au hash vide sous une version inventée est refusée ; vecteurs v1 et v2 figés, recalculés en Python à partir de la description. Sur processus réel et vraie PostgreSQL 16 : une table sans `hash_version` portant une chaîne v1 écrite en SQL est mise à niveau en place (versions [1 1 1]), se vérifie, grandit en v2 ([1 1 1 2 2]) et se vérifie ; un octet déplacé d'`action` vers `resource_type` dans une ligne v2 donne `409`, puis `200` une fois restauré ; une ligne v2 relabellisée 1 donne `409` ; le même déplacement dans une ligne v1 n'est pas vu (la limite écrite, assertée) ; le test de redémarrage existant passe. **14 mutations** (nouveaux événements en v1 ; v2 sans encadrement, sans étiquette, sans le dernier champ encadré, sans `prev_hash`, longueur sur un octet ; v1 modifié ; version inconnue hachée en v1 ou en v2, ou acceptée ; version qui recule ; version non stockée ou non relue en PostgreSQL ; lignes anciennes marquées 2) : 8 tuées d'emblée, **3 survivantes réelles** (version inconnue hachée en v1, en v2, ou acceptée — chacune masquée par l'autre défense) **closes par deux tests**, 3 réécrites pour compiler et tuées. Tests : 594 unitaires sans base (47 ignorés), 641 avec ; 54 PostgreSQL ; 44 d'intégration sans base (7 ignorés), 51 avec ; `go test -race` propre sur l'Audit Service.
- (−) **Les événements écrits avant restent au format 1**, sensibles au déplacement d'octets (asserté par le test sur PostgreSQL, pour que les documents qui le disent restent vrais).
- (−) **La chaîne n'a pas de clé** : un attaquant qui peut écrire en base et recalculer toute la fin de la chaîne n'est pas détecté.
- (−) **Un octet de plus par événement** en base (la colonne) et seize octets de plus hachés.

**Alternatives envisagées**
- *Re-hacher toute l'histoire au format 2* : rejeté — ce serait réécrire la preuve, et un attaquant passé serait blanchi par la réécriture.
- *Un séparateur (`\x00`) entre les champs plutôt qu'une longueur* : rejeté — un champ qui contient le séparateur recrée l'ambiguïté ; les bornes d'ADR-0025 l'interdisent aujourd'hui, mais l'encodage ne doit pas dépendre d'une validation faite ailleurs.
- *Hacher une sérialisation JSON* : rejeté — le JSON de Go n'est pas canonique par contrat (ordre, échappements) ; un encodage défini octet par octet se vérifie dans n'importe quel langage.
- *Déduire la version de la date de l'événement* (avant/après une date de mise à niveau) : rejeté — la date est elle-même une donnée de la ligne, et la mise à niveau n'a pas lieu au même moment partout.
- *Une chaîne à clé (HMAC) dès maintenant* : repoussé — voir la règle 7.

---

## 3. Prochaine étape

Le document suivant établit la **feuille de route** MVP → v1.0 → v2.0, qui s'appuiera sur ces décisions comme jalons de faisabilité (ex. le MVP peut se limiter à un sous-ensemble des 9 proxies).

---
*Document suivant : `OpenBastion_04_Roadmap.md`*
