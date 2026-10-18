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

## 3. Prochaine étape

Le document suivant établit la **feuille de route** MVP → v1.0 → v2.0, qui s'appuiera sur ces décisions comme jalons de faisabilité (ex. le MVP peut se limiter à un sous-ensemble des 9 proxies).

---
*Document suivant : `OpenBastion_04_Roadmap.md`*
