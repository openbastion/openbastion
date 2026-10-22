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
- (−) `terminate` n'a toujours ni contrôle d'appartenance ni politique RBAC propre (un utilisateur authentifié qui connaît l'identifiant peut couper la session d'un autre) ; c'est un déni de service, pas une élévation, et il est consigné.
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

---

---

## 3. Prochaine étape

Le document suivant établit la **feuille de route** MVP → v1.0 → v2.0, qui s'appuiera sur ces décisions comme jalons de faisabilité (ex. le MVP peut se limiter à un sous-ensemble des 9 proxies).

---
*Document suivant : `OpenBastion_04_Roadmap.md`*
