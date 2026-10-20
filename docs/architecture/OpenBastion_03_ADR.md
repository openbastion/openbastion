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
- (−) **Une seule personne suffit** : pas de double validation (le Workflow Service et l'Approval Engine sont v1.0). Atténué par une politique étroite et la désactivation par défaut ; à compléter en v1.0 par une approbation à deux et une revue post-incident obligatoire.
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
- (+) Un service compromis ne peut faire que ce que sa table lui permet. Prouvé sur 8 processus réels sous `INTERNAL_TLS=required` : le parcours complet (connexion, session, SSH, enregistrement, lecture par un auditeur) fonctionne ; 20 appels forgés par une identité valide mais *mauvaise* (un Gateway qui crée des utilisateurs ou génère des scopes, un Broker qui forge des rôles ou des entrées de recording, le Vault qui écrit dans l'audit, une demande break-glass d'un non-Broker…) sont arrêtés à la porte, et rien n'a eu lieu ; un jeton de scope volé est inutilisable par toute autre identité que le proxy (et ne brûle pas à chaque tentative) ; sans certificat, avec un certificat d'une autre autorité, d'un autre domaine ou expiré, aucun échange n'a lieu ; un Broker dont l'adresse du Vault mène à un imposteur ne lui envoie rien.
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

## 3. Prochaine étape

Le document suivant établit la **feuille de route** MVP → v1.0 → v2.0, qui s'appuiera sur ces décisions comme jalons de faisabilité (ex. le MVP peut se limiter à un sous-ensemble des 9 proxies).

---
*Document suivant : `OpenBastion_04_Roadmap.md`*
