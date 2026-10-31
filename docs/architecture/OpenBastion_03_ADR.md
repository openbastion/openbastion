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
| ADR-0027 | La chaîne d'audit est à clé (HMAC), et chaque événement dit quel service l'a écrit | Accepté |
| ADR-0028 | La tête de la chaîne d'audit est ancrée hors de la base, et la chaîne se vérifie contre ses ancres | Accepté |
| ADR-0029 | L'accès aux données reste en `database/sql` et SQL écrit à la main ; pas d'ORM | Accepté |
| ADR-0030 | Des migrations de schéma versionnées, appliquées une fois, sous verrou, et dont le texte appliqué ne change plus | Accepté |
| ADR-0031 | `audit_events` n'est pas partitionné tant qu'une rétention ne garde pas la chaîne vérifiable | Accepté |
| ADR-0032 | Archiver la chaîne d'audit hors de la base sans la rendre invérifiable : un point de contrôle ancré | Accepté |
| ADR-0033 | Un déploiement `docker-compose` reproductible, sous mTLS, une base par service, et le premier outil du CLI | Accepté |
| ADR-0034 | Une session ou une demande arrivée à échéance est marquée expirée, une fois, et l'expiration est écrite dans la trace | Accepté |
| ADR-0035 | Le connecteur OIDC : un code d'autorisation avec PKCE, un jeton d'identité vérifié champ par champ, des rôles tirés d'une table de groupes déclarée | Accepté |
| ADR-0036 | L'Admin UI : React, Vite et TypeScript, servie par la Gateway sous `/ui/`, de même origine que l'API, sous une CSP stricte | Accepté |
| ADR-0037 | La rotation d'un secret atteint la cible : un compte de réconciliation, une version en attente, une vérification avant de la rendre courante | Accepté |
| ADR-0038 | SFTP et SCP à travers le proxy : chaque transfert est enregistré, avant d'être transmis | Accepté |
| ADR-0039 | La clé d'hôte de chaque cible est épinglée au Vault, et livrée au proxy avec le secret | Accepté |
| ADR-0040 | Les rotations planifiées sont exécutées : un intervalle par compte, un balayage du Vault, une prise par compare-échange | Accepté |
| ADR-0041 | Une rotation planifiée qui échoue se voit : échecs comptés, alerte à l'audit ; et elle peut être tenue dans une fenêtre horaire | Accepté |
| ADR-0042 | Un refus dit son motif à l'opérateur par un code stable, et une panne ne dit jamais sa cause | Accepté |

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
7. **Pas de clé dans cet ADR** (*fait par ADR-0027*). Rendre la chaîne résistante à un recalcul complet demande une clé hors de la base (HMAC) ou un ancrage du dernier hash hors de la base : c'est une autre décision (gestion de clé, rotation, vérification par l'outil d'exploitation), repoussée ; la limite est écrite partout où l'intégrité est promise.

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

## ADR-0027 — La chaîne d'audit est à clé (HMAC), et chaque événement dit quel service l'a écrit

**Contexte**
ADR-0026 a déclaré la limite que rien n'écrivait jusque-là : *la chaîne n'a pas de clé — qui peut écrire dans `audit_events` peut recalculer toute la fin de la chaîne.* Bony Kiss a choisi de la fermer par **deux** mécanismes : une chaîne à clé (cet ADR) et un ancrage périodique hors de la base (ADR-0028). J'ai écrit le test d'abord, sur un processus réel et une vraie PostgreSQL, et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Une fin de chaîne recalculée passe.** L'attaquant modifie le `resource_id` d'un événement puis recalcule tous les hashes et liens suivants au format public v2 : `verify-chain` répond `200`.
- **Le service démarre avec une base et sans aucune clé**, et un changement de clé ne se voit pas (il n'y en a pas).
- **Le format est figé une fois écrit** (ADR-0026, règle 6) : tout ce qu'un événement doit couvrir se décide maintenant. L'attribution d'un événement au service qui l'a écrit — d'après son certificat mTLS — était la limite suivante (« événements non attribués par l'identité du certificat ») : elle entre dans le même format.

**Décision**
Huit règles.

1. **Format 3** : `HMAC-SHA256(clé, "openbastion.audit.event.v3" 0x00 ‖ L(prev_hash) ‖ L(id) ‖ L(actor_id) ‖ L(action) ‖ L(resource_type) ‖ L(resource_id) ‖ L(emitter) ‖ L(chain_key_id) ‖ success ‖ ts_ns)`, avec l'encadrement d'ADR-0026. **Seul le format 3 s'écrit**; 1 et 2 restent pour vérifier.
2. **La clé** : `AUDIT_CHAIN_KEY_HEX`, 32 octets en hexadécimal, **obligatoire avec `DATABASE_URL`** — l'Audit Service refuse de démarrer sans elle ou avec une valeur qui n'en est pas une, en nommant la variable et **jamais la valeur**. En mémoire, la chaîne meurt avec le processus : une clé aléatoire suffit, et l'annonce le dit. La clé n'est jamais stockée, journalisée ni renvoyée.
3. **Un identifiant de clé, pas la clé** : `chain_key_id` = les 8 premiers octets de `SHA-256("openbastion.audit.chain-key-id" 0x00 ‖ clé)`, stocké avec chaque événement et couvert par le HMAC.
4. **Rotation** : `AUDIT_CHAIN_PREVIOUS_KEYS_HEX` (séparées par des virgules) vérifient ce qu'elles ont signé et ne signent rien. Un événement signé par une clé que le service ne tient pas est un `409` qui nomme l'identifiant de la clé : le service ne peut pas s'en porter garant.
5. **L'émetteur** : le service que nomme le certificat mTLS de l'appelant (`mtls.CallerFrom`), jamais une valeur du corps ; vide quand `INTERNAL_TLS=disabled`. Borné (0 à 64 octets `[a-z0-9-]`) et couvert par le HMAC : passer un événement pour celui d'un autre service le casse.
6. **Les formats sans clé ne portent ni émetteur ni clé** : une ligne v1 ou v2 qui en porte n'a pas été écrite ainsi.
7. **Comparaison en temps constant** (`hmac.Equal`).
8. **Le contrat ne change pas** : `EmitEventRequest` n'a pas de champ émetteur (il vient du certificat) ; la table reçoit deux colonnes additives (`emitter`, `chain_key_id`, vides par défaut pour les lignes antérieures).

**Conséquences**
- (+) **Sans la clé, une fin de chaîne réécrite ne se vérifie pas**, quel que soit le format dans lequel l'attaquant la recalcule.
- (+) **Chaque événement dit quel service l'a écrit**, d'après une preuve et non une déclaration : un Recorder compromis écrit à son propre nom.
- (+) **Mesuré** : *Avant* (processus réel, vraie PostgreSQL, rouge) : une fin de chaîne réécrite et recalculée au format public v2 — `200` ; démarrage avec une base et sans clé ; changement de clé invisible. *Après*, sur processus réel : sans clé, avec une clé de 2 octets, une clé non hexadécimale, ou une clé précédente invalide, l'Audit Service refuse de démarrer en nommant la variable et sans jamais afficher la clé ; une fin de chaîne réécrite et recalculée sans la clé, étiquetée v2 ou v3, est un `409`, puis `200` une fois restaurée ; un redémarrage avec la même clé continue la chaîne et la vérifie ; une autre clé seule donne `409` « … does not hold » ; la même avec l'ancienne en clé précédente vérifie et signe avec la nouvelle ; le test mTLS de bout en bout (huit processus) passe avec l'émetteur tiré des certificats. En unitaire : lecture des clés (bornes, espaces, erreur qui ne répète aucune clé), identifiant stable, propre à chaque clé et qui ne révèle pas la clé, fin de chaîne recalculée sans clé en v2 et en v3 sous une autre clé, rotation, émetteur stocké, couvert et borné, émetteur du certificat et non du corps, ligne sans clé qui porte un émetteur ou une clé, vecteur v3 recalculé en Python (`hmac`). **22 mutations** (HMAC remplacé par une clé constante ; émetteur, identifiant de clé ou étiquette non couverts ; identifiant non dérivé de la clé ; longueur de clé non contrôlée ; clés précédentes ignorées ; erreur qui répète la clé ; événements écrits en v2 ; émetteur non stocké ou non contrôlé ; clé non tenue acceptée ; v3 vérifié sans clé ; ligne sans clé qui porte un émetteur acceptée ; v3 rendu inconnu ; émetteur du corps ; émetteur ou identifiant de clé non stockés en PostgreSQL ; clé non exigée avec une base, clés précédentes non lues, clé non utilisée) : 18 tuées d'emblée, **une survivante réelle** (l'émetteur non stocké en PostgreSQL, que rien ne relisait) **close par un test**, 2 réécrites pour compiler et tuées, **une équivalente** (`len(want) == 0`, inatteignable tant qu'une version inconnue est refusée avant) : 21 sur 21 hors équivalente. Tests : 602 unitaires sans base (47 ignorés), 649 avec ; 55 PostgreSQL ; 44 d'intégration sans base (8 ignorés), 52 avec ; `go test -race` propre.
- (−) **Une chaîne réécrite entièrement, depuis son premier événement, dans un format sans clé (1 ou 2) se vérifie** : rien dans la base ne dit qu'elle a déjà été à clé. **Refermé par ADR-0028** (une ancre hors de la base nomme un événement à clé que la réécriture fait disparaître).
- (−) **La troncature de la fin de la chaîne** (supprimer les derniers événements) n'est pas vue par la clé seule : refermé par ADR-0028 jusqu'à la dernière ancre.
- (−) **La clé est dans l'environnement du processus** : qui contrôle l'hôte de l'Audit Service la lit et peut tout re-signer. Un KMS/HSM qui ne livre jamais la clé est l'étape suivante, pas faite.
- (−) **Une clé perdue rend invérifiable, définitivement, l'histoire qu'elle a signée** : c'est une donnée à sauvegarder hors de la base, pour toute la rétention (guides Administrateur §8 et PRA §3).
- (−) **Un émetteur compromis écrit toujours n'importe quelle action**, à son nom : il n'y a pas encore de liste des actions permises par émetteur.
- (−) **Une opération de plus** (HMAC) par événement, négligeable.

**Alternatives envisagées**
- *Signer avec une clé asymétrique (Ed25519)* : repoussé — la vérification resterait dans le même service ; l'avantage (un vérificateur tiers sans pouvoir de signer) ne vaut qu'avec un vérificateur hors de l'Audit Service, qui n'existe pas encore.
- *Tirer une clé au démarrage quand aucune n'est donnée* : rejeté avec une base — l'histoire de la veille deviendrait invérifiable à chaque redémarrage, sans bruit.
- *Stocker la clé dans la base, chiffrée par la KEK* : rejeté — la clé doit être hors de ce que l'attaquant écrit.
- *Prendre l'émetteur dans le corps de la requête* : rejeté — c'est une déclaration ; le certificat est une preuve (ADR-0010).
- *Faire de l'émetteur une liste d'actions permises dans cet ADR* : repoussé — une décision d'autorisation distincte ; l'attribution d'abord.

---

## ADR-0028 — La tête de la chaîne d'audit est ancrée hors de la base, et la chaîne se vérifie contre ses ancres

**Contexte**
C'est le second des deux mécanismes demandés par Bony Kiss (le premier, la clé, est ADR-0027). ADR-0027 avait écrit ce que la clé seule ne ferme pas ; j'ai écrit le test d'abord, sur un processus réel et une vraie PostgreSQL, et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Une chaîne réécrite entièrement, depuis son premier événement, au format sans clé v2** (que l'attaquant sait calculer) se vérifie : rien dans la base ne dit qu'elle a déjà été à clé — les règles d'ADR-0026 (une version ne recule pas) ne voient rien quand **toutes** les lignes reculent ensemble.
- **La fin de la chaîne coupée** (les derniers événements supprimés) se vérifie : la chaîne restante est cohérente.
- **Aucun fichier d'ancres n'est demandé ni écrit**, et la période n'est pas bornée (elle n'existe pas).
- **Un défaut de conception trouvé en écrivant l'ancrage** (avant de le livrer) : une ancre qui prend la tête *telle que la base la donne au moment d'ancrer* valide la base falsifiée entre deux ancres. L'ancre doit nommer **ce que le processus a écrit**.
- **Une limite préexistante, jamais écrite** : l'extension de la chaîne est sérialisée par un verrou *dans le processus* ; deux réplicas de l'Audit Service sur la même base feraient bifurquer la chaîne. L'ancrage ajoute la même contrainte.

**Décision**
Neuf règles.

1. **Une ancre** = `{event_id, hash, at, key_id, mac}` : le dernier événement écrit, son hash, la date de l'ancre, l'identifiant de la clé de chaîne, et `mac = HMAC-SHA256(clé, "openbastion.audit.anchor.v1" 0x00 ‖ L(event_id) ‖ L(hash) ‖ L(key_id) ‖ at_ns)` — l'étiquette empêche qu'un MAC d'ancre soit pris pour un MAC d'événement.
2. **L'ancre nomme `tip`**, le dernier événement que **ce processus** a ajouté, avec le hash qu'il a calculé ; la base n'est lue (`Last`) qu'avant le premier ajout du processus (un redémarrage), faute de mieux.
3. **Une ancre par période où la tête a avancé** : `AUDIT_ANCHOR_INTERVAL_SECONDS`, **60** par défaut, de 1 à 3600, hors bornes fatal. Pas de nouvelle ancre pour une tête déjà ancrée ; un échec d'écriture n'avance pas la mémoire de la dernière ancre (la même tête est réessayée).
4. **Où** : un fichier en ajout seul, `AUDIT_ANCHOR_FILE`, **absolu**, créé au démarrage (droits 0600) puis seulement complété, chaque ancre écrite avec `fsync` — **jamais recréé** : un fichier disparu, ce sont des ancres illisibles, pas une installation neuve. Volontairement pas une table : la base ne doit avoir aucun pouvoir sur ce qui la contredit. Le déploiement le met sur un autre volume, idéalement en ajout seul (WORM) et répliqué hors de l'hôte de la base.
5. **Obligatoire avec `DATABASE_URL`** (refus de démarrer sans lui, ou si son répertoire n'existe pas) ; en mémoire, pas d'ancrage (rien ne réécrit la chaîne derrière le processus), et l'annonce le dit.
6. **`verify-chain` vérifie la chaîne contre ses ancres** : chaque ancre est authentique (MAC, sous une clé tenue), son événement est **dans la chaîne avec le même hash**, et les ancres suivent l'ordre de la chaîne. Sinon `409`, qui dit laquelle et pourquoi.
7. **Des ancres illisibles ne sont pas un verdict** : `503` (« the chain cannot be vouched for »), jamais `200` ; le chemin reste dans le journal.
8. **L'ancrage ne bloque pas l'audit** : un échec d'écriture d'ancre est une ligne de journal par épisode ; les événements restent écrits et signés.
9. **L'Audit Service est en instance unique** (guide HA), ce qui était déjà vrai de la chaîne.

**Conséquences**
- (+) **Une chaîne réécrite — même entièrement, dans un format sans clé — ou coupée avant la dernière ancre est trahie** par une ancre hors de la base.
- (+) **Une ancre ne valide jamais une base falsifiée entre deux ancres** (règle 2).
- (+) La limite « instance unique » de l'Audit Service est enfin écrite.
- (+) **Mesuré** : avant, une chaîne réécrite entièrement au format v2 → `200`, une fin coupée → `200`, aucun fichier d'ancres demandé ; après, les deux → `409` qui nomme l'ancre, une ancre modifiée dans le fichier → `409`, un fichier disparu → `503`, une seule ancre par tête. Audit Service : application +5 (22 → 27), infrastructure +4 (fichier d'ancres), interfaces +1 (4 → 5) ; un test d'intégration sur processus réel et vraie PostgreSQL. **26 mutations : 24 tuées, 1 survivante équivalente (chemin vide) close par un test renforcé, et l'`fsync` retiré n'est pas observable par un test** (il ne se prouve qu'en coupant le courant). 659 unitaires (612 sans base, 47 ignorés), 56 PostgreSQL, 53 d'intégration (44 sans base, 9 ignorés), `-race` propre.
- (−) **Ce qui a été écrit depuis la dernière ancre peut être tronqué sans être vu** : la période (60 s par défaut) est la fenêtre d'exposition.
- (−) **Quelqu'un qui écrit à la fois dans la base et dans le fichier d'ancres**, ou qui tient l'hôte de l'Audit Service (donc la clé), peut tout réécrire : la protection vaut ce que vaut la séparation des deux.
- (−) **Un fichier d'ancres vidé** (et non supprimé) ressemble à une installation neuve : seule une destination en ajout seul l'empêche.
- (−) **Seule une destination fichier est implémentée** : pas de stockage objet WORM ni de journal de transparence distant.
- (−) **Le `fsync` de chaque ancre n'est prouvé par aucun test** (il faudrait simuler une coupure de courant).
- (−) **`verify-chain` lit tout le fichier d'ancres**, comme il lit toute la chaîne : linéaire.
- (−) **Instance unique** (règle 9).

**Alternatives envisagées**
- *Une table d'ancres dans la même base* : rejeté — celui qui réécrit la chaîne réécrit les ancres.
- *Ancrer `store.Last` au moment de l'ancre* : rejeté (règle 2) — trouvé en écrivant le test unitaire, avant livraison.
- *Une ancre à chaque événement* : rejeté — une écriture hors base (et un `fsync`) par événement sur le chemin fermé des sessions ; la période borne le coût et dit la fenêtre.
- *Bloquer l'audit quand l'ancrage échoue* : rejeté — l'ancrage est une défense de la preuve passée, pas une condition pour en écrire de nouvelles.
- *Recréer le fichier s'il manque* : rejeté — ce serait renoncer en silence aux ancres passées.
- *Une destination distante (stockage objet WORM, journal de transparence)* : repoussé — dépendance réseau et SDK (bloqués dans le sandbox d'origine) ; le port `AnchorSink` est fait pour l'accueillir.

---

## ADR-0029 — L'accès aux données reste en `database/sql` et SQL écrit à la main ; pas d'ORM

**Contexte**
Bony Kiss a demandé une analyse de l'intégration d'un ORM dans le modèle de données (`OpenBastion_08_Analyse_ORM.md`). Mesuré : 1 077 lignes de magasins PostgreSQL, 54 appels SQL, 10 tables, 2 clés étrangères, 0 jointure, une base par service. Les garanties de concurrence et d'usage unique tiennent au SQL lui-même (verrou consultatif d'ADR-0013, comparer-échanger d'ADR-0011, `RETURNING` d'ADR-0003). Quatre options ont été présentées (A : rester en `database/sql` ; B : pilote sqlc ; C : sqlx ; D : ORM complet). **Bony Kiss a choisi l'option A.**

**Décision**
1. Les magasins restent écrits en `database/sql` avec du SQL explicite, derrière les ports de domaine existants.
2. Aucun ORM ni constructeur de requêtes n'est ajouté ; aucune dépendance n'est ajoutée.
3. Le manque réel relevé par l'analyse, les migrations versionnées, est traité à part (ADR-0030).

**Conséquences**
- (+) Les verrous, comparer-échanger et `RETURNING` restent lisibles dans le diff, là où porte la revue de sécurité.
- (+) Aucun arbre de dépendances supplémentaire dans six modules.
- (−) Le code de lecture des lignes (19 `Scan`) reste écrit à la main.
- (−) Décision renversable : sqlc (option B) reste possible plus tard derrière les mêmes ports, sans toucher domaine ni application.

**Alternatives envisagées**
Options B, C et D de l'analyse, écartées par le choix du propriétaire ; leurs motifs sont dans `OpenBastion_08_Analyse_ORM.md` §4 à §6.

---

## ADR-0030 — Des migrations de schéma versionnées, appliquées une fois, sous verrou, et dont le texte appliqué ne change plus

**Contexte**
Chacun des six services applique à **chaque démarrage** la totalité de son `migrations/001_init.sql`, idempotent (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`), et les évolutions passées ont été ajoutées **dans ce même fichier** (`tasks.md` §4). Ce qui a été **mesuré** ou constaté :

- **Deux réplicas qui démarrent en même temps sur une base neuve** : le schéma du Session Broker appliqué par deux processus simultanés sur une vraie PostgreSQL 16 → **dans 14 essais sur 20, l'un des deux échoue** (`duplicate key value violates unique constraint "pg_type_typname_nsp_index"`, 13 fois ; `pg_class_relname_nsp_index`, 1 fois). `IF NOT EXISTS` ne protège pas d'une création concurrente.
- **Rien ne dit quelle version du schéma une base a atteinte** : ni l'exploitant, ni le service, ni une procédure de reprise (PRA).
- **Une évolution qui n'est pas purement additive n'a pas de place** : un `NOT NULL` posé après un remplissage, un index reconstruit, une donnée transformée une seule fois — rejoués à chaque démarrage, ils seraient faux ou coûteux.
- **Le texte d'un schéma déjà appliqué peut être modifié** sans que rien ne le voie : la base d'une installation existante diverge alors en silence d'une installation neuve.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 ; règles 2 et 3 précisées avant l'implémentation, voir la note)*
1. **Une migration** = un fichier `migrations/NNN_nom.sql` embarqué (`embed.FS`), `NNN` sur trois chiffres, continu à partir de `001`. Les fichiers sont lus dans l'ordre ; un trou ou un doublon de numéro refuse le démarrage (et un test unitaire de chaque service le dit avant).
2. **Une table `schema_migrations`** : `component TEXT, version INTEGER, name TEXT, checksum BYTEA` (SHA-256 du texte), `applied_at TIMESTAMPTZ`, **clé `(component, version)`** — chaque service s'y nomme (`authentication`, `authorization`, `session-broker`, `password-vault`, `audit-service`, `command-recorder`).
3. **Sous verrou** : tout le passage se fait sous `pg_advisory_lock` d'une **clé propre au service** (les 8 premiers octets de SHA-256(`openbastion.migrate.lock` 0x00 ‖ service)), sur une connexion dédiée, relâché au retour ; un second réplica attend, puis trouve tout appliqué. La création de `schema_migrations` elle-même prend un verrou de transaction commun à tous les services. Ferme la course mesurée ci-dessus.

   *Note d'implémentation* : le texte proposé disait « `version` clé primaire » et « une clé propre à OpenBastion ». En écrivant le code, j'ai constaté qu'en développement et en test **les six services partagent une seule base** (`TEST_DATABASE_URL`) : six « version 1 » différentes s'y seraient heurtées, et un verrou unique aurait fait attendre chaque service derrière les autres. D'où la clé `(component, version)` et un verrou par service.
4. **Une fois, en transaction** : chaque migration manquante est appliquée dans sa propre transaction, avec sa ligne dans `schema_migrations` ; un échec annule la migration et refuse le démarrage, en nommant la version.
5. **Le texte appliqué ne change plus** : si le checksum d'une version déjà appliquée diffère du fichier embarqué, le service **refuse de démarrer** en nommant la version. Corriger une migration publiée, c'est en écrire une nouvelle.
6. **Une base plus récente que le binaire** (une version appliquée que le binaire ne connaît pas) : le service démarre et le journal le dit, parce que les migrations restent additives par défaut et qu'un retour arrière du binaire (PRA) doit rester possible. Une migration qui casse les anciens binaires doit le dire dans son ADR.
7. **Bases existantes** : `001_init.sql` est figé tel qu'il est aujourd'hui. Sur une base qui le porte déjà sans `schema_migrations`, il est rejoué une fois (il est idempotent, c'est déjà ce qui se passe à chaque démarrage) et enregistré comme version 1. Aucune autre reprise manuelle.
8. **Un seul code** : `pkg/migrate`, bibliothèque standard et `database/sql` seulement (comme `pkg/refusalbudget`), utilisé par les six magasins PostgreSQL. Aucune dépendance ajoutée.
9. **Le workflow change** : `tasks.md` §4 dit « une nouvelle migration numérotée », plus « dans le même `InitSQL` » ; le doc 06, le guide Administrateur et le PRA disent comment lire la version d'une base.

**Conséquences**
- (+) Deux réplicas qui démarrent ensemble ne se gênent plus (test : N démarrages concurrents sur une base neuve, 0 échec ; contre-épreuve : sans le verrou, le test échoue).
- (+) La version d'une base se lit dans une table ; une migration modifiée après publication est refusée.
- (+) Une migration non additive a sa place, appliquée une seule fois.
- (−) Une migration longue bloque le démarrage de tous les réplicas sous le verrou.
- (−) Pas de migration descendante (`down`) : revenir en arrière, c'est restaurer une sauvegarde ou écrire une migration montante.
- (−) ~~Le verrou consultatif est par base : deux services sur la même base partageraient la clé~~ — sans objet : le verrou est par service (note de la règle 3).
- (−) Une migration s'exécute en transaction : `CREATE INDEX CONCURRENTLY` et les instructions qui refusent une transaction n'y ont pas leur place.
- (−) Un démarrage sur une base qui n'a jamais connu ADR-0030 rejoue `001_init.sql` une dernière fois, comme avant ; ce n'est qu'ensuite qu'il ne l'est plus.
- (−) **Un schéma abîmé à la main n'est plus réparé au démarrage** : avant, `001_init.sql` rejoué recréait une table, une colonne ou un index supprimés ; maintenant la version 1 est enregistrée et n'est plus rejouée — le service démarre, puis échoue à la première requête qui en a besoin. Constaté par les tests du Session Broker qui fabriquaient une « ancienne base » en retirant une colonne sans retirer sa ligne de `schema_migrations` (une vraie base d'avant n'en a pas : ils ont été corrigés pour le dire). Réparer, c'est restaurer, ou supprimer la ligne du service dans `schema_migrations` pour que `001_init.sql` soit rejoué.
- (+) **Mesuré** : avant, sur processus réels, quatre Session Brokers démarrés ensemble sur une base neuve, cinq tours → **15 réplicas sur 20 ne démarrent pas** ; après, **20 sur 20**, et 8 applicateurs × 20 tours sans un échec. Une migration modifiée après application refuse le démarrage en la nommant ; une base plus récente que le binaire démarre avec `WARNING` ; une base d'avant ADR-0030 garde ses données et devient version 1. **19 mutations : 18 tuées, 1 équivalente** (la migration exécutée sur la connexion plutôt que la transaction : `BEGIN` était déjà envoyé sur cette connexion) **remplacée par la vraie** (aucune transaction), tuée par un test ajouté (une migration et sa ligne sont une seule chose). 664 unitaires (617 sans base), 57 PostgreSQL, 61 d'intégration (44 sans base), `-race` propre.

**Alternatives envisagées**
- **golang-migrate, goose** : éprouvés, mais une dépendance par service, et rien qu'ils apportent ici ne manque à une centaine de lignes de bibliothèque standard (`policies.md` §4.1).
- **Garder `001_init.sql` rejoué à chaque démarrage** : laisse la course mesurée et l'absence de version.
- **Appliquer les migrations par un outil séparé, avant le déploiement** : plus de contrôle pour l'exploitant, mais un service qui démarrerait sur un schéma en retard ; possible plus tard en ajoutant un mode « vérifier seulement » au même code.

---

## ADR-0031 — `audit_events` n'est pas partitionné tant qu'une rétention ne garde pas la chaîne vérifiable

**Contexte**
Le doc 06 §3 prévoit `audit_events` partitionné par mois (`PARTITION BY RANGE (ts)`), pour garder les index performants et pour archiver « par partition entière ». `001_init.sql` ne l'a jamais fait. ADR-0030 donnait enfin sa place à une migration non additive ; avant de l'écrire, j'ai mesuré sur PostgreSQL 16, dans un schéma jetable :

- **Plus d'unicité globale** : `UNIQUE (id)` et `PRIMARY KEY (seq)` sont refusés sur une table partitionnée par `ts` (« unique constraint on partitioned table must include all partitioning columns ») ; avec `UNIQUE (id, ts)`, **le même identifiant est accepté deux fois**, dans deux mois.
- **Une insertion hors de toute partition échoue** (« no partition of relation … found for row »). L'audit est fail-closed : une partition manquante arrêterait toute action auditée de la plateforme.
- **La conversion d'une table existante** : **41 s par million d'événements**, en une transaction, sous le verrou de migration — l'Audit Service, donc l'audit de toute la plateforme, est indisponible pendant ce temps.
- **Lire toute la chaîne** (`ORDER BY seq`, ce que fait `verify-chain`) : **1,0 s → 2,3 s** pour un million d'événements ; `Last` (`ORDER BY seq DESC LIMIT 1`) devient un `Merge Append` sur toutes les partitions, parce que `seq` n'est pas la clé de partition.
- **Le bénéfice attendu n'existe pas encore** : supprimer une vieille partition casse `verify-chain` (le premier événement restant a un `prev_hash` que plus rien ne justifie) et les ancres d'ADR-0028 qui nomment les événements supprimés. Partitionner ne sert à archiver qu'une fois une rétention qui garde la chaîne vérifiable conçue — ce qui manque.

Bony Kiss a choisi « la rétention d'abord ».

**Décision**
1. `audit_events` reste une table non partitionnée ; aucune migration de partitionnement n'est écrite.
2. La rétention est conçue d'abord (ADR-0032), sans dépendre du partitionnement.
3. Le partitionnement reviendra si un volume **mesuré** le justifie, avec ce que cet ADR a trouvé : unicité de l'identifiant gardée à part, partition par défaut ou partitions créées à l'avance, conversion hors du chemin de démarrage.

**Conséquences**
- (+) Aucune des quatre régressions mesurées.
- (−) Le doc 06 §3 décrit un DDL cible qui n'est pas le schéma réel : il le dit maintenant.
- (−) Le volume d'`audit_events` n'est pas borné tant qu'ADR-0032 n'est pas implémenté.

**Alternatives envisagées**
- **Partitionner quand même** (clé `(seq, ts)`, table d'identifiants pour l'unicité, partition par défaut, partitions créées par le service) : écarté par le propriétaire — tout le coût, aucun bénéfice avant la rétention.
- **Partitionner par `seq`** : garderait `PRIMARY KEY (seq)` et `Last`, mais une partition par plage de numéros ne correspond à aucune durée de rétention.

---

## ADR-0032 — Archiver la chaîne d'audit hors de la base sans la rendre invérifiable : un point de contrôle ancré

**Contexte**
Une rétention est un besoin réglementaire (garder N ans, puis détruire) et un besoin d'exploitation (borner la base). Aujourd'hui, retirer des événements d'`audit_events` — par ligne ou par partition — rend la chaîne invérifiable : `verify-chain` part du premier événement, dont `prev_hash` doit être vide, et les ancres d'ADR-0028 doivent nommer des événements présents. Le Guide Sécurité §9 dit qu'archiver par partition plutôt que par ligne évite d'« affaiblir la chaîne » : c'est faux, les deux la cassent de la même façon. Il manque un moyen de dire, hors de la base et sous la clé : « tout ce qui précède tel événement a été vérifié puis archivé là ».

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 ; trois précisions faites en l'implémentant, voir la note)*
1. **Désactivé par défaut.** Activé par `AUDIT_ARCHIVE_DIR` (chemin absolu, répertoire existant, idéalement un autre volume en ajout seul / WORM) et `AUDIT_RETENTION_MONTHS` (durée gardée en base, de 1 à 120, obligatoire avec le répertoire ; hors bornes, fatal). Sans eux, rien n'est jamais retiré de la base, comme aujourd'hui.
2. **Ce qui s'archive** : des **mois civils entiers**, les plus anciens, plus vieux que la rétention, un mois à la fois, dans l'ordre de la chaîne (`seq`) — jamais un trou au milieu.
3. **Rien ne s'archive sans être vérifié** : avant chaque mois, `VerifyChain` complet (événements et ancres) ; s'il échoue, rien n'est archivé ni supprimé, une ligne de journal par épisode, et l'on réessaie à la période suivante.
4. **L'archive** : un fichier `audit-AAAA-MM.jsonl` par mois (un événement par ligne, tous les champs tels qu'en base, hash compris), écrit dans un fichier temporaire, `fsync`, mis en place par un lien (`link`, qui échoue si le nom existe : jamais remplacé), répertoire `fsync`, **relu et son SHA-256 recalculé** avant d'aller plus loin. Jamais écrasé : un fichier de même nom déjà présent et différent arrête l'archivage.
5. **Le point de contrôle** est ajouté au **fichier d'ancres** (ADR-0028 : hors de la base, que la base ne contrôle pas) : `{kind: "checkpoint", archive, sha256, count, first_id, prev_hash, last_id, last_hash, last_version, anchors_covered, key_id, at, mac}` — `prev_hash` est le `last_hash` du point de contrôle précédent : la série des points de contrôle est elle-même chaînée, un point retiré du milieu se voit, `mac = HMAC(clé de chaîne, "openbastion.audit.checkpoint.v1" 0x00 ‖ champs encadrés)`. `anchors_covered` est le nombre d'ancres qui nomment des événements archivés : elles forment un préfixe de la liste des ancres, puisque les ancres suivent l'ordre de la chaîne et que l'archive en est un préfixe.
6. **Un événement `audit.archived`** (`resource_type = audit`, `resource_id` = nom de l'archive, émetteur l'Audit Service) est écrit dans la chaîne **avant** la suppression : l'archivage lui-même est audité.
7. **Puis la suppression**, en une transaction : `DELETE … WHERE seq <= <seq du dernier événement archivé>`.
8. **`verify-chain` repart du dernier point de contrôle** : le premier événement en base doit avoir `prev_hash` = `last_hash` du dernier point de contrôle (ou être vide s'il n'y en a pas) ; la règle « une version ne recule pas » repart de `last_version` ; les `anchors_covered` premières ancres peuvent nommer des événements absents (archivés), les suivantes doivent être dans la chaîne. Un premier événement que rien ne justifie → `409` (« the chain starts at … which no checkpoint vouches for »).
9. **Reprise après une panne** : un point de contrôle dont les événements sont encore en base (panne entre 5 et 7) est repris — archive relue et comparée, l'événement `audit.archived` écrit s'il manque (une seule fois), puis suppression ; ces événements se vérifient normalement en attendant, et leur dernier doit avoir le hash que le point de contrôle a gardé.

   *Note d'implémentation* : trois précisions par rapport au texte proposé — `prev_hash` dans le point de contrôle (la série chaînée) ; l'événement `audit.archived` écrit à la reprise s'il manque ; un lien plutôt qu'un renommage (un renommage remplace un fichier existant). L'archivage tourne au démarrage puis toutes les heures.
10. **Détruire une archive** (fin de la durée légale) relève du stockage (rétention WORM, cycle de vie), pas du service : la chaîne en base reste vérifiable sans elle, grâce au point de contrôle. Une archive se vérifie hors ligne avec la clé, du `last_hash` du point de contrôle précédent au sien (un outil, incrément suivant).

**Conséquences**
- (+) **Mesuré** : avant, sur un processus réel et une vraie PostgreSQL, les variables de rétention étaient ignorées (le service démarrait avec `AUDIT_ARCHIVE_DIR` seule) et rien n'était archivé en 10 s ; après, une chaîne de janvier et février 2025 est archivée au démarrage (3 et 2 événements, deux points de contrôle, deux `audit.archived`), `verify-chain` répond `200`, et le premier événement restant supprimé ou le point de contrôle de février retiré du fichier d'ancres donnent `409`. **31 mutations : 29 tuées** (dont 3 par des tests ajoutés après coup : clé du point de contrôle non tenue, chaîne réécrite sans clé pendant une suppression en attente, chaîne restante réécrite en v2 avant toute ancre), **1 équivalente retirée du code** (« `anchors_covered` ne décroît pas » : un point authentique qui en couvrirait moins rend obligatoires des ancres absentes, donc `409` de toute façon), **1 non prouvable par un test** (la relecture de l'archive : il faudrait un disque qui corrompt, comme pour `fsync`).
- (+) La base est bornée à la rétention, et la chaîne restante reste vérifiable contre ses ancres.
- (+) Tronquer le **début** de la chaîne en base reste détecté : sans point de contrôle authentique qui le justifie, un premier événement au `prev_hash` non vide est un `409`, comme aujourd'hui.
- (−) La clé de chaîne signe aussi les points de contrôle : la perdre rend leur vérification impossible, comme pour les ancres.
- (−) Écrire un faux point de contrôle demande la clé : tenir la base et le fichier d'ancres ne suffit pas. Qui tient l'hôte de l'Audit Service (donc la clé) le peut : même limite qu'ADR-0028.
- (−) Une archive détruite ne se vérifie plus, par construction ; ce qu'elle contenait n'est plus consultable.
- (−) L'archivage d'un mois lit et vérifie toute la chaîne restante : son coût croît avec la rétention gardée en base.
- (−) Un binaire d'avant ADR-0032 ne lit pas un fichier d'ancres qui contient des points de contrôle (`409` « not an anchor ») : le retour arrière après un premier archivage n'est pas transparent.
- (−) Un mois dont des événements sont datés après des événements du mois suivant (horloge reculée) est archivé en deux segments sous le même nom : le second est refusé (« never overwritten ») et l'archivage s'arrête, avec une ligne de journal.

**Alternatives envisagées**
- **Supprimer sans point de contrôle** : rend la chaîne invérifiable — c'est ce que le Guide Sécurité promettait d'éviter.
- **Point de contrôle dans la base** : la base aurait un pouvoir sur ce qui la contredit (même motif qu'ADR-0028).
- **Archiver par une commande d'exploitant** plutôt que périodiquement : possible, mais un deuxième processus qui écrit `audit.archived` ferait bifurquer la chaîne (Audit Service en instance unique) ; il faudrait une route interne et une identité d'exploitant qui n'existent pas.
- **Garder tout en base** : simple, mais ni borné ni conforme à une obligation de destruction.

---

## ADR-0033 — Un déploiement `docker-compose` reproductible, sous mTLS, une base par service, et le premier outil du CLI

**Contexte**
Le MVP a trois critères de sortie (doc 04 §2) ; le troisième, « déploiement reproductible via `docker-compose/` en environnement de développement », n'avait **rien** dans le dépôt : ni `deploy/`, ni image, ni fichier Compose. Les huit services ne tournaient qu'en processus lancés à la main (`make run-*`) ou par les tests. En le préparant, j'ai constaté deux manques qui empêchent une installation de démarrer seule :

- **Aucun moyen de créer le premier utilisateur** sans écrire une requête mTLS à la main : `POST /auth/v1/users` n'accepte que l'identité `admin-cli` (ADR-0010), et aucun outil ne la porte. Le CLI est au périmètre du MVP (doc 04 §2, doc 02 : `cli/openbastion-cli/`) et n'existe pas.
- **L'amorce de démonstration de l'Authentication Service** (`demo-dba` / `demo-password`, faute de `SKIP_DEMO_SEED`) est un mot de passe connu dans une installation qui en a une base.

Mesuré dans cet environnement : Docker Compose v5, les images `golang:1.23-alpine`, `gcr.io/distroless/static-debian12:nonroot` et `postgres:16` se tirent, et un build multi-étapes résout les modules Go dans le conteneur (le service Authorization se construit). Les certificats de `make pki` portent par défaut le nom du service comme nom DNS (`pkg/mtls/pki`), ce qui suffit à la vérification du nom d'hôte quand chaque conteneur porte le nom de son service.

**Décision** *(acceptée sur la consigne de Bony Kiss du 30 octobre 2026 de continuer l'implémentation du MVP ; renversable)*
1. **`deploy/docker-compose/`** : un `Dockerfile` multi-étapes unique (`golang:1.23-alpine` → `distroless/static-debian12:nonroot`, utilisateur 65532, binaire statique `CGO_ENABLED=0 -trimpath`), un `docker-compose.yml`, un `init.sh`.
2. **mTLS obligatoire** (`INTERNAL_TLS=required`, ADR-0010) : les certificats sont produits par l'outil du dépôt (`openbastion-pki all`) par un service Compose ponctuel (`pki`), à chaque `up` (l'autorité est gardée, les certificats des services renouvelés, 720 h par défaut). **L'autorité et sa clé restent dans le volume `pki-ca`, monté par ce seul service** ; chaque service ne monte, en lecture seule, que **son** sous-répertoire du volume `pki` (son certificat, sa clé, le certificat de l'autorité). Aucun mode « développement sans TLS » dans ce fichier.

   *Trouvé en le concevant* : monter tout le répertoire de certificats dans chaque service, comme `make pki` le produit, aurait donné à chacun la clé de l'autorité et les clés des autres — de quoi se fabriquer n'importe quelle identité.
3. **Une base par service** (ADR-0002) : un PostgreSQL 16, six bases et six rôles, chaque rôle propriétaire de sa seule base, mots de passe distincts.
4. **Les secrets** (six mots de passe de base, `KMS_KEY_HEX` du Vault et celui du Recorder — distincts —, `TOKEN_SIGNING_KEY_HEX`, `AUDIT_CHAIN_KEY_HEX`) sont tirés par `init.sh` dans `deploy/docker-compose/.env`, droits 0600, **jamais commité** ; `init.sh` **refuse d'écraser** un `.env` existant (des clés perdues rendent la chaîne et les secrets illisibles).
5. **Volumes séparés** : base, certificats, ancres de la chaîne (ADR-0028), archives (ADR-0032) — ancres et archives jamais dans le volume de la base.
6. **Seuls deux ports sont publiés**, sur `127.0.0.1` par défaut : l'API publique de la Gateway et le port SSH du proxy. Les routes internes ne sortent pas du réseau Compose.
7. **Pas d'amorce de démonstration** : `SKIP_DEMO_SEED=1` partout. Le premier administrateur se crée avec le CLI.
8. **`cli/openbastion-cli`**, premier outil : `user create` et `audit verify-chain`, avec l'identité `admin-cli` (certificat du volume `pki`), mot de passe lu sur l'entrée standard, jamais en argument. Il tourne dans le réseau Compose (`docker compose run --rm cli …`).
9. **Une cible SSH de démonstration** (profil `demo`) : un petit serveur SSH en Go (un shell qui répond à chaque ligne), pour exercer le parcours sans dépendre d'une image tierce.
10. **Le critère de sortie est un test** : `test/integration/compose_test.go`, sous `COMPOSE_TEST=1` (il construit et démarre la pile réelle) — premier administrateur par le CLI, politiques, compte, session, connexion SSH à travers le proxy, relecture des commandes par un auditeur, chaîne vérifiée, **le secret de la cible absent des journaux de la Gateway et du Broker**, puis redémarrage de la pile et tout est encore là.

**Conséquences**
- (+) **Mesuré** : `TestCompose_TheMVPJourneyOnARealDockerComposeStack` (`make test-compose`) passe en 58 s sur la pile réelle — premiers utilisateurs par le CLI, politiques, compte, session, connexion SSH par le port publié, `whoami` et `id` relus par un auditeur, chaîne vérifiée par le CLI, trace en base exactement `session.create,session.connect,recording.read`, aucun secret (clés, mots de passe de base, mot de passe de la cible, ticket) dans les journaux, chaque service seul avec ses trois fichiers, le rôle du Broker n'ouvre aucune autre base, pas de compte de démonstration ; après `restart`, la trace, l'enregistrement et le compte sont là. **11 contre-épreuves sur le déploiement, 11 tuées** : Recorder, Vault ou Audit en mémoire ; clé de l'autorité donnée aux services ; Authentication publié ; Gateway sans mTLS ; amorce de démonstration revenue ; bases ouvertes à tous les rôles ; publication sur toutes les interfaces ; `init.sh` qui écrase ; `.env` lisible par tous.
- (+) Le troisième critère de sortie du MVP a une preuve exécutable.
- (−) Le PostgreSQL du Compose parle en clair sur le réseau Compose (`sslmode=disable`) : acceptable pour un hôte unique, pas pour des bases sur un autre hôte.
- (−) Les images ne sont pas épinglées par empreinte (`@sha256:`) : « reproductible » vaut ici pour le code (`go.sum`), pas pour les images de base.
- (−) Une seule instance de chaque service : ce fichier n'est pas une installation HA (guide HA).
- (−) Le CLI ne fait que l'amorçage ; les comptes, politiques et sessions passent encore par l'API publique (`curl`).
- (−) Deux défauts trouvés en le faisant tourner : `authorization` est un mot réservé de PostgreSQL (identifiants maintenant entre guillemets) ; un test qui sondait la disponibilité par des connexions épuisait le budget de connexion par adresse (ADR-0014) — il attend maintenant les lignes « listening ».
- (−) **Dans le codespace de développement**, deux conteneurs d'un même réseau Compose ne se joignaient pas (une table `iptables-legacy` en `FORWARD DROP`) ; le test n'y a tourné qu'avec une règle temporaire posée sur autorisation explicite de Bony Kiss, puis retirée (`.agents/settings/environments/local.yaml`).

**Alternatives envisagées**
- **Binaires construits sur l'hôte puis copiés** : plus rapide, mais l'image dépendrait de la chaîne d'outils de l'hôte.
- **`INTERNAL_TLS=disabled` dans Compose** : plus simple, mais le fichier serait copié tel quel en production ; un invariant (identité tirée du certificat) ne doit pas avoir de mode faible par défaut.
- **Une image SSH tierce comme cible** : une dépendance externe de plus pour une démonstration ; un serveur de 100 lignes sur `x/crypto/ssh`, déjà dans le dépôt, suffit.

---

## ADR-0034 — Une session ou une demande arrivée à échéance est marquée expirée, une fois, et l'expiration est écrite dans la trace

**Contexte**
Le Scheduler du MVP n'a qu'une tâche : l'expiration des sessions (doc 04 §2). Aujourd'hui l'expiration est **paresseuse** : `Session.EffectiveStatus` répond `expired` quand on lit une session passée son échéance, et le proxy coupe une connexion ouverte à l'échéance en écrivant `session.expire` (ADR-0009). Ce qui manque, mesuré sur un vrai Broker et une vraie PostgreSQL (rouge avant) :

- **une session accordée mais jamais connectée, ou une demande break-glass restée sans décision, expire sans aucune trace** — ni événement, ni changement en base (déjà noté comme limite d'ADR-0011 : « l'expiration d'une demande en attente n'est pas auditée ») ;
- **en base, son statut reste `active` ou `pending_approval` pour toujours** : la base dit le contraire de ce que le Broker répond.

**Décision** *(acceptée sur la consigne de Bony Kiss du 30 octobre 2026 de continuer l'implémentation du MVP ; renversable)*
1. **Le Broker balaie** les sessions échues, toutes les `SESSION_EXPIRY_SWEEP_SECONDS` (**30** par défaut, de 1 à 3600, hors bornes fatal), sans interrupteur : une échéance est un fait, pas une option.
2. **Une seule étape atomique par session** : `UPDATE … SET status = 'expired' WHERE id IN (SELECT … WHERE status IN ('active', 'pending_approval') AND expires_at < now … FOR UPDATE SKIP LOCKED) RETURNING …`. Une session expire **une fois**, quel que soit le réplica qui balaie ; une décision ou une terminaison concurrente gagne ou perd son comparer-échanger, jamais les deux.
3. **L'expiration est un événement** `session.expire`, `resource_type = session`, acteur vide (action du système), écrit par le Broker (son émetteur le dit, ADR-0027) — à côté de celui du proxy, qui dit qu'une connexion a été coupée.
4. **Écrit au moins une fois** : la ligne expirée porte `expiry_audited = false` jusqu'à ce que l'événement soit accepté. Un audit en panne laisse la ligne à écrire : le processus qui l'a expirée la réessaie **dès son balayage suivant** ; une ligne qu'un réplica arrêté a laissée est reprise par n'importe quel balayage après `ExpiryAuditGrace` (**30 s**, plus long qu'un balayage, borné à 10 s : pour ne pas doubler ce qu'un réplica écrit à l'instant). Une panne entre l'événement et la marque peut le doubler : c'est voulu plutôt que de le perdre.

   *Note d'implémentation* : le texte proposé disait « reprise après une minute » pour toutes ; un audit revenu aurait attendu une minute pour des expirations que le processus lui-même retenait — d'où les deux chemins.
5. **Le schéma change par une migration numérotée** (ADR-0030) : `002_session_expiry.sql` ajoute `expired_at`, `expiry_audited` et un index partiel des expirations à écrire.
6. **Rien ne change pour un client** : la réponse `expired` était déjà celle de `EffectiveStatus` ; elle est maintenant aussi en base.

**Conséquences**
- (+) **Mesuré** : avant (rouge, vrai Broker, vraie PostgreSQL), la variable était ignorée, une session accordée jamais connectée et une demande jamais décidée restaient `active` et `pending_approval` en base, aucun `session.expire`. Après : toutes deux `expired` en moins d'une seconde ; l'audit coupé, les deux expirations attendent (`expiry_audited = false`) puis sont écrites une fois à son retour, sans acteur ; les sessions en cours, terminées ou refusées restent telles quelles ; deux Brokers qui balaient ensemble 40 sessions les expirent et les écrivent **une fois chacune** (et, au niveau du magasin, huit balayeurs sur deux connexions, 300 sessions, une fois chacune). **12 mutations, 12 tuées.** Deux défauts trouvés par les tests avant de livrer : `RETURNING` ne rend pas les lignes dans l'ordre (trié par une CTE) ; un service construit sans horloge faisait planter le balayage (`s.now` nil → `s.clock()`).
- (+) Chaque expiration est dans la trace, une demande break-glass oubliée comprise.
- (+) La base dit ce que le Broker répond.
- (−) La trace peut porter deux fois la même expiration (panne entre l'écriture et la marque).
- (−) L'expiration d'une demande n'est toujours notifiée à personne (le webhook d'ADR-0012 ne part pas).
- (−) Entre l'échéance et le balayage (30 s au plus par défaut), la base dit encore `active` ; le Broker, lui, répond déjà `expired`.

**Alternatives envisagées**
- **Un service Scheduler à part** : doc 00 le prévoit ; pour une seule tâche qui touche les seules lignes du Broker, un processus de plus et un appel réseau de plus n'apportent rien — il viendra avec les rotations planifiées.
- **Écrire l'événement puis marquer** (audit d'abord) : deux réplicas écriraient chacun l'expiration de la même session.
- **Expirer à la lecture** (écrire en base dans `Get`) : une session que personne ne relit n'expirerait jamais.

---

## ADR-0035 — Le connecteur OIDC : un code d'autorisation avec PKCE, un jeton d'identité vérifié champ par champ, des rôles tirés d'une table de groupes déclarée

**Contexte**
Le MVP fédère l'identité par OIDC seulement, la MFA restant chez le fournisseur (doc 04 §2) ; le modèle de données prévoit `identity_source` (`local`, `oidc`) et `external_subject` sur `users` (doc 06), l'OpenAPI une connexion « locale ou fédérée OIDC ». **Rien n'existe** : seule la connexion par mot de passe local fonctionne. ADR-0007 fait de Keycloak l'IdP de plateforme qui fédère les annuaires ; ce connecteur ne le contredit pas — il fait de l'Authentication Service un **client OIDC** (Relying Party) de *n'importe quel* fournisseur conforme, Keycloak compris, et l'Authentication Service reste le seul émetteur des jetons OpenBastion. Bony Kiss a choisi la règle des rôles : **une table déclarée des groupes du fournisseur vers les rôles d'OpenBastion**, et une implémentation sans dépendance nouvelle (bibliothèque standard et `golang-jwt`, déjà présent).

Le point de sécurité central est que **le fournisseur ne décide pas des rôles** : il dit qui est l'utilisateur et à quels groupes il appartient ; OpenBastion seul décide de ce que chaque groupe vaut, et ne croit un jeton qu'après l'avoir vérifié entièrement.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — la règle des rôles et « sans dépendance nouvelle » sont son choix ; le reste est renversable)*
1. **Désactivé par défaut.** Activé par `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`, `OIDC_ROLE_MAP_FILE` — **tous ou aucun** (sinon refus de démarrer) ; `OIDC_GROUPS_CLAIM` (`groups` par défaut). L'émetteur et l'URL de retour sont en `https`, sauf vers une adresse de boucle locale (développement). Le secret n'est jamais journalisé.
2. **Découverte au démarrage** : `<issuer>/.well-known/openid-configuration` ; l'`issuer` du document doit être **exactement** `OIDC_ISSUER` ; les points d'entrée d'autorisation, de jeton et de clés (`jwks_uri`) sont en `https` (même exception). Fournisseur injoignable au démarrage : refus de démarrer.
3. **Flux par code d'autorisation avec PKCE (S256)**, `state` et `nonce` tirés au hasard (32 octets), gardés en base (`oidc_login_attempts`, migration `002`), **à usage unique** et valables **10 minutes**. Deux routes publiques de la Gateway, sans cookie : `POST /auth/oidc/start` rend l'URL d'autorisation ; `POST /auth/oidc/callback {code, state}` rend le jeton OpenBastion. Elles comptent dans le budget de connexion par adresse (ADR-0014).
4. **Le jeton d'identité est vérifié champ par champ** : signature par une clé du `jwks_uri` désignée par son `kid`, algorithmes **RS256 et ES256 seulement**, l'algorithme imposé par le type de la clé (pas de `none`, pas de HS256 avec une clé publique) ; `iss` = l'émetteur ; `aud` contient l'identifiant client, et `azp`, s'il est là, l'est aussi ; `exp` dans le futur, `iat` et `nbf` pas dans le futur, à 60 s près ; `nonce` = celui de la tentative ; `sub` non vide. Un `kid` inconnu fait relire les clés au plus une fois par minute.
5. **Les rôles viennent de la table**, fichier JSON `{"groupe": ["rôle", …]}`, lu au démarrage (fichier illisible ou mal formé : refus de démarrer). Un groupe absent de la table ne donne rien ; **une identité sans aucun rôle est refusée** (`403`, sans dire quels groupes elle avait). Les rôles sont **recalculés à chaque connexion** : quitter un groupe chez le fournisseur retire le rôle à la connexion suivante.
6. **Le compte** est créé à la première connexion, retrouvé ensuite par `(identity_source = 'oidc', external_subject = sub)`. Son nom est `oidc:<sub>` — **jamais** le `preferred_username` du fournisseur, qui pourrait prendre le nom d'un compte local ; le nom affiché vient de `name` ou `preferred_username`. Un compte OIDC n'a pas de mot de passe : la connexion locale le refuse.
7. Le jeton émis est le même que celui d'une connexion locale (HS256, ADR-0007 inchangé sur ce point), avec les rôles calculés.

**Conséquences**
- (+) **Mesuré** : avant (rouge, sur `HEAD`), une configuration OIDC à moitié faite était ignorée et aucune connexion fédérée n'existait. Après, sur une vraie Gateway et un vrai Authentication Service avec PostgreSQL, face à un fournisseur joué par le test : la connexion donne `[platform-admin vault-admin]` pour le groupe `bastion-admins` et **rien** pour les groupes `platform-admin` et `marketing`, qui ne sont pas dans la table ; un retour rejoué ou un `state` forgé donne `401` ; quitter le groupe retire le rôle à la connexion suivante, en base aussi ; une identité sans groupe connu donne `403` et aucun compte ; le compte fédéré ne se connecte pas par mot de passe ; une connexion commencée avant un redémarrage de l'Authentication Service se termine après (l'état est en base) ; les deux routes prennent dans le budget de connexion ; le secret du client n'est dans aucun journal. Au niveau du client OIDC, **20 jetons forgés ou mal adressés, tous refusés** (`none`, HS256 avec la clé publique, algorithme contraire au type de la clé, autre clé, clé RSA de 1024 bits, sans `kid`, charge modifiée, autre émetteur, audience, `azp`, expiré, sans `exp`, émis dans le futur, `nbf` futur, autre `nonce`, sans `nonce`, sans `sub`, groupes qui ne sont pas une liste, pas un JWT). **21 mutations, 21 tuées** (une survivante, « rôles non enregistrés », a révélé que le magasin mémoire rendait l'objet qu'il garde — il rend maintenant des copies — et que le test ne regardait pas les rôles en base).
- (+) Une connexion fédérée de bout en bout, la MFA chez le fournisseur.
- (+) Un fournisseur compromis ou mal configuré ne donne aucun rôle que la table ne prévoit pas.
- (−) Un rôle retiré chez le fournisseur reste dans le jeton OpenBastion jusqu'à son expiration (1 h) : pas de révocation par le fournisseur.
- (−) Ni déconnexion fédérée, ni jeton de rafraîchissement du fournisseur.
- (−) Les connexions, locales ou fédérées, ne sont toujours pas des événements d'audit.
- (−) **Une connexion fédérée prend deux fois dans le budget de connexion par adresse** (début et retour) : derrière un proxy non déclaré (`TRUSTED_PROXY_CIDRS`), tous les utilisateurs partagent le budget du proxy.
- (−) Deux contrôles sont doublés par construction et ne se prouvent pas séparément : l'algorithme imposé par le type de la clé et la liste RS256/ES256 (golang-jwt refuse aussi une clé du mauvais type) ; le refus explicite de la connexion locale d'un compte OIDC et son mot de passe vide (Argon2 le refuse aussi).

**Alternatives envisagées**
- **Comptes pré-créés seulement** : écarté par le propriétaire (chaque utilisateur à la main).
- **`coreos/go-oidc` et `golang.org/x/oauth2`** : écartés par le propriétaire (dépendances nouvelles, `golang.org/x/*`).
- **Flux implicite ou jeton dans l'URL** : déconseillé par l'OAuth 2.0 Security BCP (RFC 9700) ; le code avec PKCE est le seul flux retenu.
- **Prendre les rôles directement d'un claim du fournisseur** : le fournisseur déciderait de ce qu'un utilisateur peut faire dans le bastion.

---

## ADR-0036 — L'Admin UI : React, Vite et TypeScript, servie par la Gateway sous `/ui/`, de même origine que l'API, sous une CSP stricte

**Contexte**
Le MVP prévoit une Admin UI (comptes, politiques, consultation d'audit — doc 04 §2), sous `web/admin-ui/` en React, TypeScript et Vite (doc 02 §5). Rien n'existe. Bony Kiss a choisi cette pile, et avec elle les dépendances npm qu'elle demande. La connexion fédérée (ADR-0035) attend aussi une page de retour qui renvoie `code` et `state` à `POST /auth/oidc/callback`.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — la pile est son choix ; le reste est renversable)*
1. **`web/admin-ui/`** : React et React DOM à l'exécution, **rien d'autre** (ni routeur, ni bibliothèque d'interface, ni gestion d'état) ; à la construction : Vite, son greffon React, TypeScript, et pour les tests Vitest, jsdom et Testing Library. Versions **exactes** dans `package.json`, `package-lock.json` commité, `npm ci` seulement.
2. **L'interface ne parle qu'à l'API publique de la Gateway** (doc 05), avec le jeton porteur. Elle ne demande aucune route nouvelle aux services : elle fait ce que l'API permet (connexion locale et OIDC ; comptes du Vault : liste, enregistrement, détail, rotation, désactivation ; création de politiques ; sessions : demande, demandes en attente, approbation, refus, détail, terminaison ; relecture d'un enregistrement), et dit ce qu'elle ne peut pas faire (lister les politiques : l'API ne le permet pas).
3. **Servie par la Gateway, sous `/ui/`, de même origine que l'API** : pas de CORS à ouvrir, pas de second serveur. `ADMIN_UI_DIR` (absolu, contenant `index.html`) l'active ; absent, rien n'est servi sous `/ui/` ; un répertoire qui ne convient pas est fatal.
4. **Chaque réponse de `/ui/` porte** : `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` (aucun script en ligne, aucune origine tierce), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (le `code` d'OIDC ne fuit pas par l'en-tête Referer), `X-Frame-Options: DENY`, et `Cache-Control: no-store` sur `index.html`. Un chemin sans extension sert `index.html` (la page de retour OIDC, `/ui/oidc/callback`) ; un chemin qui sort du répertoire est refusé.
5. **Le jeton vit en mémoire seulement** : ni `localStorage`, ni `sessionStorage`, ni cookie. Recharger la page déconnecte : c'est le prix d'un jeton qu'un script injecté ne trouve nulle part à relire.
6. **La page de retour OIDC** lit `code` et `state`, les **efface de l'URL** (`history.replaceState`) avant tout, puis les envoie à `/auth/oidc/callback`.
7. **L'image Compose** construit l'interface (étape Node) et la Gateway la sert (`ADMIN_UI_DIR`) ; le test Compose vérifie qu'elle est servie avec ses en-têtes.

**Conséquences**
- (+) **Mesuré** : avant, rien sous `/ui/` ni dans `web/`. Après : 17 tests de composants (Vitest, Testing Library, jsdom) — jeton jamais dans un stockage ni un cookie, en-tête porteur seulement une fois connecté, `code` et `state` effacés de l'URL **avant** l'envoi et envoyés une fois, rien d'envoyé si le fournisseur a refusé, une commande `<img src=x onerror=…>` affichée comme texte (aucun élément `img`), le secret effacé du formulaire après l'enregistrement et envoyé en octets, la déconnexion oublie le jeton ; 4 tests Go du service de `/ui/` (en-têtes sur chaque réponse, la page pour les routes, `no-store`, rien hors du répertoire, lecture seule, rien sans `ADMIN_UI_DIR`) ; le test Compose sert l'interface construite dans l'image avec ses en-têtes. **12 contre-épreuves, 12 tuées** (7 sur l'interface, 5 sur le service). La page construite ne contient **aucun script en ligne**. Dépendances : **3 paquets à l'exécution** (`react`, `react-dom`, `scheduler`), 94 en tout ; `npm audit` : **0** vulnérabilité connue.
- (+) Les trois usages du MVP — comptes, politiques, consultation — ont une interface, et la connexion fédérée a sa page de retour.
- (−) Des dizaines de paquets npm à la construction (le compte exact et `npm audit` sont dans NOTES_SANDBOX.md) ; deux seulement à l'exécution.
- (−) Pas de test dans un vrai navigateur (Playwright demanderait des navigateurs téléchargés) : les composants sont testés sous jsdom, les en-têtes et le service des fichiers en Go.
- (−) Recharger la page déconnecte (rule 5).
- (−) Pas de liste des politiques ni des événements d'audit : l'API publique n'en a pas.

**Alternatives envisagées**
- **Go et `html/template` sans npm** : écarté par le propriétaire.
- **Un serveur d'interface à part** (nginx ou Go) : une origine de plus, donc CORS à ouvrir sur l'API, et un service de plus à durcir.
- **Le jeton dans `localStorage`** : lisible par tout script de la page, pour toujours.

---

## ADR-0037 — La rotation d'un secret atteint la cible : un compte de réconciliation, une version en attente, une vérification avant de la rendre courante

**Contexte**
Le MVP promet une rotation « manuelle et post-usage » (doc 04 §2). Constaté le 30 octobre 2026 : `VaultService.Rotate` enregistrait un nouveau secret **sans le poser sur la cible** — aucun composant ne change un mot de passe sur une cible. Après une rotation, le Vault injectait un mot de passe que la cible refusait : le compte devenait inutilisable. `post_use` et `scheduled` étaient enregistrés et rien ne les exécutait. Et la rotation remplaçait l'ancienne version **avant** d'écrire la nouvelle, hors transaction : une panne entre les deux laissait un compte sans secret courant. Bony Kiss a choisi le modèle du **compte de réconciliation**.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — le modèle du compte de réconciliation est son choix ; le reste est renversable)*
1. **Un compte peut nommer son compte de réconciliation** (`reconciliationAccountId`) : un autre compte du Vault, actif, **sur la même cible**, jamais lui-même, qui peut changer les mots de passe — `root`, ou un compte autorisé à `sudo chpasswd`. Son secret est au Vault comme les autres, jamais ailleurs.
2. **Sans compte de réconciliation, pas de rotation** : `409` qui le dit. Il n'existe plus de rotation qui ne change que le Vault.
3. **Une version en attente** (`pending`) : le nouveau secret est d'abord écrit chiffré, **à côté** de la version courante, qui reste celle qu'on injecte. Une seule version en attente par compte (une seconde rotation simultanée : `409`).
4. **Poser, puis vérifier, puis rendre courant** : le Vault se connecte en SSH à la cible avec le compte de réconciliation, pose le mot de passe (`chpasswd`, par `sudo -S` si le compte n'est pas `root`), **se connecte avec le nouveau secret** ; seulement alors, **en une transaction**, la version en attente devient courante et l'ancienne est remplacée. La cible refuse : la version en attente est jetée, l'ancienne reste courante. Posée mais non vérifiée : la version en attente est gardée, et la rotation suivante commence par **réconcilier** — le nouveau secret ouvre la cible ? il devient courant ; l'ancien l'ouvre encore ? l'attente est jetée ; aucun des deux ? `502` et rien n'est décidé à la place d'un humain.
5. **Auditée, fail-closed** : `vault.rotate_requested` est écrit **avant** de toucher la cible (audit en panne : pas de rotation), `vault.rotate` (succès ou échec) après, au nom de qui l'a demandée (l'identité vérifiée par la Gateway) ou sans acteur pour une rotation après usage.
6. **Après usage** : quand une session accordée se termine (terminaison, ou expiration par le balayage d'ADR-0034), le Broker le dit au Vault (`POST /vault/v1/rotate-after-use`, réservé au Broker) ; le Vault tourne le secret si le compte est `post_use`, ne fait rien sinon. Un échec est audité et journalisé ; il n'est pas réessayé.
7. **`scheduled` reste enregistré et n'est exécuté par rien** (pas de Scheduler de rotation) : c'est dit.
8. L'Admin UI retrouve le bouton de rotation, et l'enregistrement d'un compte son champ de réconciliation.

**Conséquences**
- (+) **Mesuré** : avant (rouge, sur `HEAD`, huit processus et une vraie cible SSH), après une rotation **l'ancien mot de passe ouvrait encore la cible** et la session suivante **échouait** (le proxy injectait un secret que la cible refusait) ; une rotation sans compte de réconciliation et une rotation l'audit coupé répondaient `202`. Après : le mot de passe de la cible change, l'ancien ne l'ouvre plus, la session suivante s'ouvre avec le nouveau ; une session terminée fait tourner un compte `post_use`, et l'ancien secret n'ouvre plus la cible ; sans compte de réconciliation `409` et rien ne change ; l'audit coupé `503` et la cible n'est pas touchée ; les événements de rotation nomment l'administrateur vérifié, ceux d'après usage personne. `chpasswd` direct (`root`) et par `sudo -S` sont tous deux exercés sur un vrai serveur SSH, et aucun secret ne passe sur une ligne de commande. **17 mutations, 17 tuées.** Quatre tests existants ont changé par construction : la rotation sans cible n'existe plus (tests unitaires du Vault, test des routes d'administration, test de redémarrage du Vault), et « le Vault écrit dans l'audit » n'est plus une attaque (deux tables d'appelants).
- (+) Une rotation change vraiment le mot de passe de la cible, ou ne change rien.
- (+) Aucun moment où un compte n'a pas de secret courant.
- (−) ~~**La clé d'hôte de la cible n'est pas vérifiée** (comme par le proxy, MVP) : quelqu'un qui se place entre le Vault et la cible voit passer le nouveau secret et celui du compte de réconciliation.~~ Refermé par ADR-0039 : le Vault ne se connecte qu'à la clé épinglée.
- (−) Entre la pose et la promotion (quelques secondes), une nouvelle connexion reçoit encore l'ancien secret et échoue.
- (−) Une rotation après usage échouée n'est pas réessayée.
- (−) ~~`scheduled` n'est exécuté par rien (décision 7).~~ Refermé par ADR-0040 : le Vault balaie et fait tourner les comptes planifiés échus.
- (−) Le Vault ouvre maintenant des connexions SSH vers les cibles : un chemin réseau de plus à autoriser (guide HA, pare-feu).
- (−) Le module du Vault dépend désormais de `golang.org/x/crypto` (même version et même miroir que le proxy), et le Vault d'un Audit Service (`AUDIT_URL`).

**Alternatives envisagées**
- **Le compte change son propre mot de passe** (`passwd` interactif) : écarté par le propriétaire (dépend des messages de chaque système).
- **Refuser toute rotation** : écarté par le propriétaire.
- **Faire poser le mot de passe par le proxy** : le proxy est déjà l'unique composant qui joint les cibles, mais il deviendrait détenteur des secrets de réconciliation hors d'une session ; garder la rotation dans le Vault laisse ces secrets là où ils vivent.

---

## ADR-0038 — SFTP et SCP à travers le proxy : chaque transfert est enregistré, avant d'être transmis

**Contexte**
Le MVP prévoit un « SSH/SFTP/SCP Proxy » (doc 04 §2). Le proxy n'acceptait que le shell interactif et refusait `exec` et les sous-systèmes : sûr, mais sans transfert de fichiers. Depuis OpenSSH 9.0, `scp` passe par défaut par le sous-système SFTP ; l'ancien protocole SCP (`scp -O`) existe encore. Bony Kiss a choisi d'**enregistrer chaque transfert** — sens, chemin, taille, SHA-256 du contenu — sans en garder le contenu, et, pour les tests, la bibliothèque `github.com/pkg/sftp` v1.13.7 (la plus récente compatible avec `golang.org/x/crypto` v0.24 du dépôt), **dans les tests seulement**.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — enregistrer chaque transfert et `pkg/sftp` dans les tests seulement sont ses choix ; le reste est renversable)*
1. **Ce que le proxy accepte sur un canal de session** : un shell (comme avant), le sous-système `sftp`, ou une commande exactement `scp -t <chemin>` / `scp -f <chemin>` (avec les options `-r -p -d -v` de l'ancien protocole). Toute autre commande, tout autre sous-système : refusé, comme avant.
2. **Enregistrer ou refuser s'applique aux transferts** (ADR-0008) : chaque événement ci-dessous est écrit au Command Recorder et **acquitté avant** que le paquet qui le déclenche soit transmis à la cible ; non acquitté, le paquet n'est pas transmis et la session s'arrête, comme une commande.
3. **SFTP** — le proxy lit le protocole (version 3) dans les deux sens :
   - **avant** de transmettre une ouverture de fichier : `sftp open <chemin> for <reading|writing|reading and writing>` ;
   - **avant** de transmettre une modification : `sftp remove`, `rename`, `mkdir`, `rmdir`, `setstat`, `symlink`, `hardlink`, et toute requête étendue par son nom ;
   - **avant** de transmettre la fermeture d'un fichier ouvert : `sftp upload|download <chemin> (<n> bytes, sha256 <hex>)` — le SHA-256 des octets écrits ou lus, dans l'ordre des décalages ; si les écritures ou lectures ne sont pas contiguës depuis zéro, `sha256 not computed: non-sequential` ;
   - les lectures de métadonnées (`stat`, `readdir`, `realpath`…) ne sont pas enregistrées ;
   - un paquet de plus de 1 Mio, ou qui ne se lit pas, arrête la session.
4. **SCP (ancien protocole)** — **avant** d'exécuter : `scp upload to <chemin>` ou `scp download from <chemin>` ; **avant** de transmettre chaque en-tête de fichier : `scp upload|download <nom> into|from <chemin> (<n> bytes)` ; **avant** de transmettre l'octet qui clôt son contenu : la même ligne avec `sha256 <hex>`. Le nom est celui que le protocole porte et le chemin celui de la commande, écrits séparément : le proxy ne sait pas si le chemin est un fichier ou un répertoire.
5. **Les chemins sont écrits entre guillemets, échappés** (`strconv.Quote`) : un nom de fichier ne forge pas de ligne dans l'enregistrement.
6. **Le contenu n'est pas gardé** : l'enregistrement dit quoi, combien et l'empreinte ; une copie servirait de preuve complète, mais son volume n'est pas borné et elle contiendrait les secrets transférés.

**Conséquences**
- (+) **Mesuré** : avant (rouge, sur le commit qui précède ADR-0038, huit processus et les vrais clients OpenSSH 9.6), `sftp`, `scp` et `scp -O` échouaient. Après : `sftp` (envoi, réception, `mkdir`, `rename`), `scp` (par SFTP) et `scp -O` (envoi et réception) passent, le fichier arrive intact, et un auditeur relit chaque transfert avec sa taille et un SHA-256 **égal à celui du fichier** ; `ssh … id` reste refusé. L'ordre « enregistré, puis transmis » est vérifié paquet par paquet ; un enregistrement refusé arrête l'ouverture, la modification ou la fermeture ; un nom de fichier qui tente de forger une ligne reste une ligne ; treize commandes `scp` d'injection (`;`, `$( )`, deux chemins, `-o ProxyCommand`…) sont refusées. **17 mutations, 17 tuées** (dont une survivante — « pas de borne de taille » — que mon test ne voyait pas faute de corps de paquet, maintenant vue). Le proxy envoie le statut de sortie **puis ferme le canal**, comme un sshd : sans cela, un `scp -O` attendait cinq secondes de trop.
- (+) Un fichier ne passe plus à travers le bastion sans laisser son nom, sa taille et son empreinte dans l'enregistrement, avant de partir.
- (−) L'empreinte d'un transfert parallèle ou par blocs non contigus n'est pas calculée (la taille l'est).
- (−) Le contenu n'est pas gardé : l'empreinte prouve ce qui a été transféré à qui détient le fichier, elle ne le restitue pas.
- (−) Un téléchargement est enregistré à la fermeture du fichier, quand les octets sont déjà partis vers le client ; l'ouverture, elle, est enregistrée avant.
- (−) `pkg/sftp` (et ses dépendances de test) entre dans le module des tests d'intégration.

**Alternatives envisagées**
- **Garder le contenu** (chiffré) : écarté par le propriétaire.
- **Refuser les transferts** : écarté par le propriétaire.
- **Enregistrer chaque bloc écrit** : des milliers d'aller-retours par fichier, pour une information que l'empreinte finale porte déjà.

## ADR-0039 — La clé d'hôte de chaque cible est épinglée au Vault, et livrée au proxy avec le secret

**Contexte**
Le proxy (depuis le MVP) et le Vault (depuis ADR-0037) se connectaient aux cibles **sans vérifier leur clé d'hôte** (`ssh.InsecureIgnoreHostKey`). Quiconque s'interpose entre eux et une cible — ARP, DNS, une route, l'adresse d'une machine arrêtée — se fait passer pour elle : le proxy lui donne le mot de passe du compte privilégié, le Vault celui du compte de réconciliation et le nouveau secret. Celui qui s'interpose voit donc le secret que l'opérateur, lui, ne voit jamais. Et l'adresse de la cible arrive au proxy **par le Broker** : un Broker compromis pourrait l'orienter vers un serveur à lui.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — clé enregistrée au Vault, vérifiée par le proxy et par le Vault, c'est sa demande ; le reste est renversable)*
1. **Chaque compte porte la clé d'hôte de sa cible** (`hostKey` : une ligne `ssh-ed25519 AAAA…`, telle qu'un fichier `.pub` ou une ligne `known_hosts`, dont les noms d'hôtes sont retirés). Elle est vérifiée et normalisée à l'enregistrement. Les marqueurs `@revoked` et `@cert-authority`, deux lignes ou une ligne illisible sont refusés. `GET` d'un compte rend la clé et son empreinte (`SHA256:…`). C'est une donnée publique, pas un secret.
2. **Elle est obligatoire à l'enregistrement** d'un compte (`400` sans elle). Un compte enregistré avant cet ADR n'en a pas : **aucune session ni rotation** ne s'y ouvre tant qu'un administrateur ne l'a pas épinglée. Le Vault répond `409` (« no pinned host key ») à `authorize-scope`, `fetch-credential` et `rotate`, et `connect` répond `409` à l'opérateur.
   - L'épinglage passe par `PUT /vault/accounts/{id}/host-key`, réservé aux administrateurs du compte.
   - Il est audité **avant** le changement (`vault.host_key_set`, fail-closed, sous le nom du jeton), et le journal du Vault garde l'ancienne et la nouvelle empreinte.
   - Pas de « confiance au premier usage » : le premier usage est justement celui qu'un attaquant attend.
3. **La clé arrive au proxy par le Vault, avec le secret** : `fetch-credential` rend, en plus du secret, l'adresse et la clé épinglée de la cible. Le proxy n'envoie le mot de passe qu'à une cible qui présente exactement cette clé, et refuse une session dont l'adresse (celle du Broker) n'est pas celle que le Vault connaît. Un Broker compromis peut se tromper d'adresse ; il ne peut plus faire accepter un autre serveur.
4. **Le Vault vérifie la même clé** quand il se connecte pour une rotation (`ssh.FixedHostKey` ; le compte de réconciliation est sur la même cible).
5. **Une cible qui ne présente pas sa clé** est refusée explicitement :
   - le journal du proxy garde l'empreinte vue et l'empreinte attendue ;
   - l'audit enregistre `session.host_key_mismatch` (en plus de `session.terminate`) ;
   - l'opérateur lit que rien n'a été envoyé et qu'il doit prévenir un administrateur.

**Conséquences**
- (+) **Mesuré** : avant (rouge, sur 2e9166f), un serveur présentant une autre clé à l'adresse de la cible recevait le mot de passe `root` du compte, et le relais répondait sans erreur ; le changeur de mot de passe du Vault se connectait en `root` à des cibles dont il n'avait jamais vu la clé.
- (+) **Mesuré, après** — huit processus réels et le vrai client OpenSSH :
  - l'imposteur reçoit **zéro** mot de passe ;
  - l'opérateur est prévenu et `session.host_key_mismatch` est audité ;
  - un opérateur ne peut pas ré-épingler (`403`) ;
  - un administrateur ré-épingle, l'audit l'attribue au nom du jeton et non à celui que le client écrit dans sa requête, et la session suivante passe ;
  - un enregistrement sans clé, avec une clé vide, illisible ou privée est refusé (`400`).
- (+) **Mesuré, en unitaire** :
  - un compte sans clé n'obtient ni scope, ni secret (même pour un scope accordé avant), ni rotation ;
  - un épinglage sans l'audit n'a pas lieu ;
  - une session dont l'adresse diffère de celle du Vault n'envoie rien.
  - **25 mutations, 25 tuées.** Deux survivaient au départ. Le repli `known_hosts` était du code mort : il est retiré, et le marqueur `@revoked` sans nom d'hôte est maintenant refusé. Le refus d'une rotation sans clé n'était pas distingué d'un autre `409` : le test exige maintenant le motif.
- (+) Celui qui s'interpose entre le bastion et une cible ne reçoit plus aucun secret ; un Broker compromis ne peut plus envoyer le proxy vers un serveur qu'il contrôle.
- (−) **Les comptes existants doivent être épinglés** avant leur prochaine session : c'est une opération d'exploitation, décrite dans le guide d'administration.
- (−) Une cible qui change de clé (réinstallation) refuse les sessions jusqu'à un nouvel épinglage. C'est le comportement voulu, et c'est une panne si personne ne la prévoit.
- (−) Une seule clé par compte : pas de liste de clés acceptées, pas d'autorité de certificats SSH. Une cible qui présente plusieurs types de clé n'est acceptée que par celui qui est épinglé, et le client SSH du bastion négocie ce type-là.
- (−) ~~L'enregistrement et l'épinglage sont deux écritures. Si la seconde échoue, le compte reste sans clé : inutilisable, donc sûr, et réparable par `PUT host-key`.~~ Refermé par ADR-0040 : le compte est écrit en une fois, clé, réconciliation et intervalle compris.

**Alternatives envisagées**
- **Confiance au premier usage** (enregistrer la clé vue à la première connexion) : protège tout sauf la première connexion, qui est celle que l'attaquant vise.
- **La clé par le Broker** (avec l'adresse) : un Broker compromis la changerait avec l'adresse.
- **Autorité de certificats SSH** : plus souple, mais elle suppose une PKI SSH chez l'exploitant ; possible plus tard, à côté de l'épinglage.

## ADR-0040 — Les rotations planifiées sont exécutées : un intervalle par compte, un balayage du Vault, une prise par compare-échange

**Contexte**
`rotationPolicy: scheduled` est accepté à l'enregistrement depuis le MVP, mais **rien ne l'exécute** (ADR-0037, limite écrite) : un compte réglé ainsi ne change jamais de mot de passe, alors que l'exploitant croit le contraire. Le Scheduler complet de la feuille de route n'existe pas ; la rotation, elle, existe (ADR-0037) et tient déjà ses garanties : réconciliation, version en attente, vérification, clé d'hôte épinglée (ADR-0039), audit avant de toucher la cible.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — exécuter les rotations planifiées, c'est sa demande ; le reste est renversable)*
1. **Un intervalle par compte** : `rotationIntervalDays`, de 1 à 365.
   - Il est **obligatoire** pour `scheduled`, et **refusé** pour les autres politiques (`400`) : un intervalle qu'aucune politique n'exécute serait une promesse vide.
   - Un compte `scheduled` doit nommer son compte de réconciliation dès l'enregistrement (`409` sinon) : sans lui, il ne tournerait jamais.
2. **Les comptes `scheduled` d'avant cette décision** reçoivent 30 jours à la migration (`004_rotation_schedule.sql`). Ils commencent donc à tourner après la mise à jour : c'est ce que leur politique promettait.
3. **Échéance** : dernière rotation, ou création si le compte n'a jamais tourné, plus l'intervalle. Un compte désactivé n'est pas concerné.
4. **Le Vault balaie** toutes les `ROTATION_SWEEP_SECONDS` (300 par défaut, de 1 à 86 400, hors bornes fatal, sans interrupteur). À chaque passage, il prend au plus 20 comptes échus, les plus en retard d'abord, et les tourne **un par un**, par le même chemin qu'une rotation après usage : action du système (acteur vide), `vault.rotate_requested` écrit avant de toucher la cible, `vault.rotate` après.
5. **Une prise par compare-échange** avant chaque rotation (`rotation_attempted_at`) : entre réplicas du Vault, un seul tente un compte donné. Un compte tenté — réussi ou non — n'est **pas** retenté avant une heure : une cible en panne ou un compte mal configuré ne sont pas martelés à chaque balayage, et l'audit n'est pas inondé.
6. **La réponse d'un compte** dit `rotationIntervalDays` et `nextRotationAt` ; l'Admin UI les montre.

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `8d76787`, vraie base PostgreSQL et vraie cible SSH) : un compte `scheduled` en retard de deux jours ne tourne pas — quinze secondes plus tard, la cible a toujours son mot de passe.
- (+) **Mesuré, après**, deux Vaults réels sur la même base, balayage chaque seconde :
  - un compte qui n'est pas échu ne tourne pas ;
  - échu, il tourne **une fois** à travers les deux Vaults (une demande, une rotation à l'audit) : sur la cible, l'ancien mot de passe ne l'ouvre plus, et le Vault injecte ce que la cible prend ;
  - l'audit l'attribue au système (acteur vide) ;
  - un compte manuel aussi ancien, à côté, n'est pas touché.
- (+) **Mesuré en unitaire et sur PostgreSQL** :
  - intervalle absent, nul, négatif ou supérieur à 365 jours : refusé ; intervalle sur une autre politique : refusé ; `scheduled` sans réconciliation : refusé, et rien n'est enregistré ;
  - un compte désactivé, manuel ou après usage ne tourne pas ; un échec n'est pas retenté avant une heure, puis l'est ;
  - sans audit, la cible n'est pas touchée ; deux Vaults au même instant : une seule rotation (`-race` propre) ;
  - ordre du plus en retard ; prise unique ; un compte qui vient de tourner n'est plus échu ;
  - la migration donne 30 jours à un compte `scheduled` d'avant, et rien aux autres.
  - **19 mutations, 19 tuées.** Deux survivaient au départ : une mutation mal écrite (la prise avait lieu avant que je la force), réécrite ; et « l'échéance ignore la dernière rotation », que seul le SQL couvrait : un test du domaine le couvre maintenant.
- (+) Un compte `scheduled` tient enfin sa promesse, par le même chemin, et donc les mêmes garanties, qu'une rotation manuelle.
- (+) L'enregistrement écrit maintenant le compte **en une fois** — clé d'hôte, réconciliation et intervalle compris —, ce qui referme la limite des deux écritures d'ADR-0039.
- (−) ~~La cadence est en jours, sans heure ni fenêtre : un compte peut tourner en pleine journée de travail.~~ Refermé par ADR-0041 (`ROTATION_WINDOW_UTC`). La session ouverte à ce moment garde sa connexion ; la suivante reçoit le nouveau secret.
- (−) Les comptes `scheduled` d'avant ADR-0040 tournent **dès la mise à jour** s'ils ont plus de 30 jours (20 par passage).
- (−) ~~Un compte qui échoue est retenté toutes les heures, sans limite ni alerte autre que le journal et l'événement `vault.rotate` en échec ; un compte sans réconciliation ou sans clé ne laisse qu'une ligne de journal par heure, pas d'événement d'audit.~~ Refermé par ADR-0041 : les échecs sont comptés et `vault.rotation_overdue` est écrit tous les N échecs, y compris pour un compte sans réconciliation ou sans clé.
- (−) Les comptes d'un passage tournent un par un : beaucoup de comptes échus en même temps s'étalent sur plusieurs passages.
- (−) Il n'y a ni modification de la politique ni de l'intervalle d'un compte existant par l'API, comme avant pour la politique.

**Alternatives envisagées**
- **Un Scheduler séparé** (doc 04) : un service de plus, avec son identité et ses appels au Vault, pour une seule tâche. Il viendra avec la feuille de route ; le balayage du Vault suffit à tenir la promesse aujourd'hui.
- **Un intervalle global** pour tous les comptes : simple, mais un compte de base de données et un compte `root` n'ont pas la même cadence.
- **Une expression cron par compte** : plus riche, mais un analyseur à écrire ou une dépendance, pour un besoin qu'un intervalle couvre.
- **Retenter à chaque balayage** : une cible arrêtée recevrait une tentative toutes les cinq minutes, chacune écrite à l'audit.

## ADR-0041 — Une rotation planifiée qui échoue se voit : échecs comptés, alerte à l'audit ; et elle peut être tenue dans une fenêtre horaire

**Contexte**
Depuis ADR-0040, un compte `scheduled` échu est tourné par le Vault ; s'il échoue (cible injoignable, compte de réconciliation qui ne se connecte plus, clé d'hôte changée), le Vault retente chaque heure, **sans que personne le sache** autrement qu'en lisant son journal : le secret vieillit en silence, contre la politique que l'exploitant a choisie. Et une rotation peut tomber en pleine journée de travail.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — « Go pour la prochaine étape » : alerte après plusieurs échecs et fenêtres horaires ; la forme est renversable)*
1. **Chaque compte compte ses échecs consécutifs** de rotation planifiée (`rotation_failures`, migration `005_rotation_failures.sql`). Toute rotation réussie — planifiée, manuelle ou après usage — le remet à zéro.
2. **L'alerte est un événement d'audit** : `vault.rotation_overdue` (acteur système, échec), écrit au N-ième échec consécutif puis tous les N échecs (`ROTATION_ALERT_AFTER_FAILURES`, 3 par défaut, de 1 à 100). L'audit est ce que lit un SIEM ; le rappel tous les N échecs rattrape une alerte perdue si l'audit était coupé à ce moment-là.
3. **La réponse d'un compte** dit `rotationFailures` ; l'Admin UI montre un compte en échec.
4. **Une fenêtre horaire**, une pour la plateforme, en UTC : `ROTATION_WINDOW_UTC=HH:MM-HH:MM` (elle peut passer minuit). Hors de la fenêtre, le balayage ne prend aucun compte ; un compte échu attend la fenêtre suivante. Absente : à toute heure (comportement d'ADR-0040) ; mal formée, ou de durée nulle : le Vault refuse de démarrer. Une rotation demandée par un administrateur n'est pas tenue par la fenêtre.

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `cc081f7`, processus réels et vraie base) : le Vault démarrait avec une fenêtre illisible ; hors de sa fenêtre, il prenait et tournait les deux comptes échus ; un compte dont la cible ne répond pas ne laissait aucune alerte.
- (+) **Mesuré, après** :
  - une fenêtre illisible, de durée nulle, ou un seuil de 0 : le Vault refuse de démarrer, en nommant la variable ;
  - hors de sa fenêtre, aucun compte n'est pris, si en retard soit-il ; un Vault dont la fenêtre est maintenant tourne le compte échu ;
  - un compte dont la cible ne répond pas compte un échec et écrit `vault.rotation_overdue` (acteur système) ; sa réponse dit `rotationFailures: 1`.
- (+) **Mesuré en unitaire et sur PostgreSQL** :
  - lecture des fenêtres, passage de minuit, bornes (début inclus, fin exclue), comparaison en UTC quelle que soit la zone de l'heure donnée ;
  - une alerte au N-ième échec, aucune entre deux, une perdue (audit coupé) rattrapée au 2N-ième ;
  - une rotation réussie, planifiée ou manuelle, remet le compte à zéro ; le compteur avance d'un `UPDATE` à la fois.
  - **17 mutations, 17 tuées.** Deux survivaient d'abord, et c'étaient mes tests : un exemple de fuseau qui tombait dans la fenêtre dans les deux lectures, et des alertes comptées par sous-chaîne, qui laissaient passer un acteur ajouté.
- (+) Un secret qui vieillit contre sa politique se voit dans l'audit, et dans l'Admin UI (« en échec (N) »).
- (−) Une seule fenêtre pour la plateforme, en UTC ; pas de fenêtre par compte ni de jour de la semaine.
- (−) L'alerte n'est qu'un événement d'audit : il faut un SIEM ou une revue pour la voir. Pas de notification poussée.
- (−) Les comptes échus qui attendent la fenêtre s'y accumulent : 20 par passage, au rythme du balayage.

**Alternatives envisagées**
- **Un webhook d'alerte** (comme la notification du break-glass, ADR-0012) : un canal de plus à sécuriser ; l'audit est déjà le registre que surveille un SIEM.
- **Une fenêtre par compte** : plus fine, mais un champ de plus à l'API et à l'UI pour un besoin que l'exploitant exprime d'abord à l'échelle de la plateforme.
- **Arrêter de retenter après N échecs** : le secret vieillirait plus encore ; on alerte et on continue.

## ADR-0042 — Un refus dit son motif à l'opérateur par un code stable, et une panne ne dit jamais sa cause

**Contexte**
Depuis ADR-0039, un compte sans clé d'hôte épinglée n'ouvre aucune session : le Vault répond `409` à `authorize-scope`. Mais le Broker transformait toute réponse non `200` en « authorize-scope: status 409 », et `connect` renvoyait à l'opérateur le texte de **toute** erreur en `409`. L'opérateur ne savait donc pas quoi faire. Et une panne du proxy, du Vault ou du réseau lui arrivait avec son texte interne, adresse comprise (« establishing session on proxy: Post http://…: dial tcp … »). `POST /sessions` avait le même défaut : une panne de l'Authorization Service, de l'audit ou du magasin sortait en `403`, avec son texte, alors que le contrat (doc 05) promet `503` sans la cause.

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « Go pour la prochaine étape » : relayer le motif d'un 409 du Vault ; le reste est renversable)*
1. **Le Vault dit ses refus d'`authorize-scope` par un code stable**, en JSON : `{"code": "no_pinned_host_key", "error": "…"}` (`409`) ; tout autre refus : `{"code": "refused", …}` (`403`). Le code est le contrat ; le texte ne l'est pas.
2. **Le Broker traduit les codes qu'il connaît** en erreurs de domaine (`ErrAccountNotPinned`) ; un code inconnu reste une erreur sans texte du Vault.
3. **`connect` répond** :
   - `409` pour un état de la session, ou pour un compte qui n'est pas épinglé, avec une phrase qui dit quoi faire ;
   - `404` pour une session inconnue ;
   - `503` pour une dépendance qui ne répond pas, avec une phrase générique : la cause va au journal du Broker, jamais au client.
4. **`POST /sessions` répond `503`**, sans la cause, quand l'Authorization Service, l'audit ou le magasin ne répondent pas, comme le doc 05 le promettait ; un refus d'accès reste un `403`.

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `9cd7be3`, processus réels et vraie base, à travers la Gateway) :
  - l'opérateur lisait « authorizing vault scope: authorize-scope: status 409 » pour un compte non épinglé ;
  - le Vault arrêté, il lisait `409` « resolving account: Get "http://127.0.0.1:18481/vault/v1/accounts/…": dial tcp 127.0.0.1:18481: connect: connection refused » : l'adresse et l'URL interne du Vault.
- (+) **Mesuré, après** : `409` « the privileged account has no pinned host key: an administrator must pin it (PUT /vault/accounts/{id}/host-key) before any session » ; le Vault arrêté, `503` sans adresse, sans port, sans « dial tcp ».
- (+) **Mesuré en unitaire** :
  - le client du Broker ne reconnaît le code que sur un `409`, ignore le texte, et ne laisse passer aucune adresse ;
  - `connect` : `404` pour une session inconnue, `409` pour une session terminée, `503` sans la cause pour un proxy injoignable ;
  - `POST /sessions` : `503` sans la cause quand l'Authorization Service ou l'audit ne répondent pas, `403` motivé pour un refus.
  - **11 mutations, 11 tuées.**
- (+) Jumeaux trouvés et refermés : `connect` et `POST /sessions` laissaient sortir des causes internes ; terminer, décider, lire une session ne le faisaient déjà plus.
- (−) Le test qui fixait `409` pour une panne du proxy (`TestConnect_OtherProxyFailuresStayAConflict`) est remplacé : ce `409` n'était pas un état de la session, et doc 05 réserve `409` à l'état.
- (−) Une session peut encore être **créée** sur un compte non épinglé ; c'est `connect` qui la refuse.
- (−) Les autres routes publiques n'ont pas été passées en revue de la même façon : celles de la Gateway vers le Vault relaient encore le texte des erreurs d'administration (`403`, `409` des écritures), destinées à un administrateur.

**Alternatives envisagées**
- **Relayer le texte du Vault** : il n'est pas un contrat, et il peut porter un détail interne.
- **Vérifier la clé dès `POST /sessions`** : une session ouverte sur un compte non épinglé ne pourrait jamais servir, mais refuser plus tôt demande un appel au Vault de plus à chaque demande ; c'est possible plus tard.

---

## 3. Prochaine étape

Le document suivant établit la **feuille de route** MVP → v1.0 → v2.0, qui s'appuiera sur ces décisions comme jalons de faisabilité (ex. le MVP peut se limiter à un sous-ensemble des 9 proxies).

---
*Document suivant : `OpenBastion_04_Roadmap.md`*
