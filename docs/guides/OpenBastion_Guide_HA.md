# OpenBastion — Guide Haute Disponibilité

**Version** 0.1 · **Statut** Draft de travail
**Public visé** Équipes SRE/exploitation, architectes infrastructure
**Portée** Résilience face à la panne d'un composant, dans un site unique ou un cluster unique multi-zones. La résilience face à la perte d'un site entier relève du guide PRA/PCA (à venir), qui s'appuiera sur celui-ci.

---

## 1. Principe directeur

Le document 00 (§11) posait déjà l'exigence : **stateless-first**, état externalisé vers PostgreSQL, Redis et MinIO. Ce guide en tire les conséquences concrètes, composant par composant, et introduit une règle qui n'était pas encore explicite : **fail-closed sur tout ce qui touche au secret ou à l'audit, fail-open sur le reste**.

| Comportement en cas de panne | Composants concernés | Justification |
|---|---|---|
| **Fail-closed** (bloquer plutôt que dégrader) | Password Vault, Secrets Manager, Audit Service, PostgreSQL | Un accès privilégié non auditable ou un secret servi sans garantie d'intégrité viole les invariants (doc 00 §2) — mieux vaut refuser une session que la rendre non conforme |
| **Fail-open dégradé** (continuer avec fonctionnalité réduite) | Search Engine, Reporting Service, Notification Service | Leur indisponibilité dégrade l'expérience (pas de recherche, pas d'alerte Slack) mais ne compromet aucun invariant |

## 2. Topologie par composant

| Composant | Stratégie HA |
|---|---|
| Microservices stateless (Gateway, Authn, Authz, Broker, Workflow, Approval, connecteurs…) | Plusieurs répliques K8s, `PodDisruptionBudget`, `HorizontalPodAutoscaler`, sondes `readiness`/`liveness` dédiées |
| Autorité de certification interne et émission des certificats de service (ADR-0010) | Composant de rang 1 **hors ligne par défaut** : les services lisent des fichiers et ne dépendent pas de l'autorité à l'exécution, mais ne se renouvellent que si elle (ou cert-manager/SPIRE) émet à temps — l'autorité doit être sauvegardée (clé hors des services) et son émission supervisée. Une autorité tombée n'arrête rien jusqu'à la première échéance ; **c'est l'échéance qui fait la panne** (§4) |
| PostgreSQL | Primaire + répliques en streaming replication, bascule automatisée (ex. Patroni), pooling de connexions (PgBouncer) devant chaque service |
| Redis | Redis Sentinel (ou Cluster) — perte du cache tolérée en dégradé (§4), perte de l'état de session Broker traitée en fail-closed sur les nouvelles créations |
| MinIO | Cluster distribué avec erasure coding — HA native du produit, pas de configuration supplémentaire requise |
| OpenSearch (v1.0) | Cluster multi-nœuds, réplicas de shard ≥ 1 — dégradable sans impact sur l'invariant (§1) |
| NATS | Cluster NATS JetStream, quorum Raft ≥ 3 nœuds |
| Kafka | Cluster multi-broker, facteur de réplication ≥ 3, répartition multi-zone |
| Keycloak | Mode cluster (plusieurs instances derrière load balancer, base partagée) — dépendance critique signalée dès ADR-0007 |
| Envoy (mesh) / Traefik (edge) | Plusieurs répliques derrière un load balancer externe, sans état |

## 3. Particularité de la couche proxy

Les proxies protocolaires détiennent un état qu'aucun des autres composants n'a : **une session active avec un credential en mémoire** (doc 01 §4.2). Ce n'est ni un état à répliquer, ni un état à externaliser — le faire violerait ADR-0003.

- **Une instance de proxy qui crashe termine immédiatement les sessions qu'elle porte.** Le credential associé était déjà en mémoire uniquement ; il disparaît avec le processus, ce qui est correct du point de vue sécurité, mais interrompt l'opérateur sans préavis.
- **Détection** : le `StreamHealth` de `ProxyControl` (doc 07 §4) permet au Session Broker de retirer une instance défaillante de son pool avant qu'elle ne reçoive de nouvelles sessions.
- **Conséquence assumée** : une session interrompue par panne de proxy doit être re-demandée par l'opérateur — pas de reprise transparente possible sans réintroduire un état partagé de credential, ce qui est exclu par conception.
- **Mitigation opérationnelle** : `PodDisruptionBudget` sur les proxies pour interdire l'éviction simultanée de plusieurs répliques lors d'une mise à jour de nœud, et drainage progressif (`terminationGracePeriodSeconds` suffisant pour laisser les sessions en cours se terminer naturellement) plutôt qu'un arrêt brutal lors d'un déploiement.
- **Traçabilité** : toute terminaison anormale de session (crash proxy, expiration forcée) génère un `AuditEvent` avec `result = failure` — cohérent avec Full Auditability, une panne n'est jamais un trou dans le journal.

## 4. Dégradation gracieuse par domaine

| Panne | Effet | Sessions déjà actives | Nouvelles sessions |
|---|---|---|---|
| Search Engine indisponible | Pas de recherche plein texte | Aucun impact | Aucun impact |
| Notification Service indisponible | Pas d'alerte Slack/Teams | Aucun impact | Approbation possible via l'UI seule (v1.0) |
| Reporting Service indisponible | Pas de rapport agrégé | Aucun impact | Aucun impact |
| Redis indisponible | Perte de cache | Risque d'incohérence sur `Session Registry` (doc 01 §4.1) | **Bloquées** — le Broker ne peut plus garantir l'état de session |
| Audit Service / Kafka indisponible | — | Sessions déjà établies continuent (le proxy ne dépend pas de l'audit pour fonctionner) | **Bloquées** — cohérent avec le principe fail-closed (§1) |
| Command Recorder indisponible, ou sa base passée en lecture seule (ADR-0008) | — | **Terminées à la prochaine commande** : une commande qui ne peut pas être enregistrée n'est pas exécutée sur la cible, l'opérateur est prévenu (`session.recording_lost`) | **Bloquées** (`503 recording unavailable`, `session.recording_unavailable`) — une session non enregistrable n'a pas lieu, **sauf** une session break-glass (ADR-0009) : admise si la plateforme l'autorise, auditée (`session.breakglass`) et enregistrée au mieux |
| Webhook de notification break-glass indisponible, lent ou hostile (ADR-0012) | — | **Sans effet** : aucune demande ni décision n'est retardée ni refusée ; une notification perdue est perdue (pas de nouvelle tentative) et laisse une ligne dans le journal du Broker | **Sans effet** — la liste `GET /sessions?status=pending_approval` est le filet |
| Certificat de service expiré (mTLS interne, ADR-0010) | Les pairs refusent ce service, et lui-même est refusé par eux : pour tout appel qui le traverse, c'est la panne du service. Se voit au journal : `mtls: the certificate of … EXPIRED` | Selon le service refusé — un proxy refusé par le Vault n'obtient plus de credential ; le Gateway refusé par le Broker ne crée plus de session | **Bloquées** si le service concerné est sur le chemin (Gateway, Broker, Vault, Authorization, recorder, audit) — le cas typique d'une panne totale sans panne de machine |
| Password Vault indisponible | — | Aucun impact (credential déjà en mémoire proxy) | **Bloquées** — aucune nouvelle session ne peut obtenir de credential |
| PostgreSQL indisponible | — | Dépend du composant (voir ci-dessus, PostgreSQL sous-tend Vault et Audit) | **Bloquées** |

## 5. Objectifs cibles indicatifs

| Niveau de criticité | Composants | RTO cible | RPO cible |
|---|---|---|---|
| Tier 0 — bloquant | Gateway, Authn, Authz, Broker, Vault, **Command Recorder** (ADR-0008), PostgreSQL, **émission des certificats de service** (ADR-0010) | < 1 min (bascule automatisée) | 0 (réplication synchrone ou quasi-synchrone) |
| Tier 1 — dégradable court terme | Proxies, Audit/Kafka | < 5 min | < 1 min |
| Tier 2 — dégradable | Search Engine, Reporting, Notification | < 30 min | best-effort |

Ces chiffres sont indicatifs et devront être révisés une fois des mesures réelles disponibles post-MVP (doc 04) — ils servent de point de départ pour dimensionner l'exercice de bascule mentionné au guide PRA/PCA.

## 6. Tests de résilience

- Injection de panne périodique (chaos engineering) : tuer une instance de proxy avec sessions actives et vérifier que (a) l'audit enregistre la terminaison anormale, (b) aucun credential n'apparaît dans les logs post-mortem, (c) le Broker retire l'instance de son pool dans le délai attendu.
- Bascule PostgreSQL forcée en environnement de test, mesure du temps réel de rétablissement de la création de session (Tier 0).
- Coupure volontaire du Command Recorder (ou passage de sa base en lecture seule) pendant une charge de sessions : vérifier que les nouvelles sessions sont refusées en `503` et que les sessions en cours s'arrêtent à leur prochaine commande, **sans qu'aucune commande atteigne la cible** — à surveiller via `GET /readyz`, pas seulement `/healthz`.
- Coupure volontaire du Command Recorder **avec** une session break-glass : vérifier que (a) la session est admise et que `session.breakglass` précède l'accès au credential dans l'audit, (b) elle ne se coupe pas à la panne du recorder, (c) elle est coupée à son échéance (`session.expire`), (d) une session **ordinaire** demandée au même moment est refusée en `503`. Puis couper aussi l'Audit Service : la session break-glass doit être refusée — une dérogation que personne ne peut voir n'est pas accordée (fail-closed, §1). Avec l'approbation requise (ADR-0011, défaut) : une demande en attente vit dans la table `sessions` (avec la base ; en mémoire, elle ne survit pas à un redémarrage du Broker) ; deux approbations simultanées, y compris sur deux répliques, ne produisent qu'**une** décision effective ; couper l'Audit Service pendant l'approbation la refuse (la décision est auditée avant d'agir).
- **Notification en panne** (ADR-0012) : pendant qu'une demande break-glass est déposée puis décidée, rendre le webhook injoignable, puis muet (il accepte la connexion et ne répond pas), puis le rediriger : vérifier que la demande et la décision se terminent normalement et sans délai, que la liste reste exacte, qu'une ligne « notification … not delivered / refused » apparaît dans le journal du Broker **sans l'URL**, et que la redirection n'est pas suivie. Avec plusieurs réplicas du Broker, chaque événement est émis une seule fois, par le réplica qui a enregistré la demande ou gagné la décision (comparaison-échange) ; un réplica qui perd la course n'émet rien. Si ce réplica tombe entre l'enregistrement et l'envoi, la notification est perdue : la liste fait foi.
- **Plafond de demandes en attente** (ADR-0013) : avec deux réplicas du Broker (base PostgreSQL partagée), lancer en même temps beaucoup de demandes break-glass d'un **même** demandeur : exactement `BREAKGLASS_MAX_PENDING_PER_REQUESTER` sont acceptées, les autres reçoivent `429`, et l'audit montre un événement `session.breakglass_requested` avec `success=false` par refus (une demande qui perd la course pour la dernière place en laisse deux pour la même session : le dernier décide). Le décompte et l'enregistrement se font dans une transaction sous un verrou consultatif PostgreSQL par demandeur (`pg_advisory_xact_lock`) : il est tenu le temps d'une écriture, ne touche pas les autres demandeurs et se libère au `COMMIT` comme à la perte de la connexion. Couper la base pendant le décompte : `503`, jamais une demande acceptée. Le stockage en mémoire n'est pas partagé entre réplicas : son plafond est celui d'un processus, et il ne convient pas à un déploiement à plusieurs Brokers.
- **Limitation de débit du Gateway** (ADR-0014, ADR-0016, ADR-0017) : le budget de `POST /sessions` et celui des actions (`approve`, `reject`, `connect`, `DELETE /sessions/{id}`) vivent dans la mémoire de **chaque** réplica du Gateway ; avec *N* réplicas, un utilisateur obtient jusqu'à *N* fois `SESSION_REQUEST_BURST` puis *N* fois `SESSION_REQUEST_RATE_PER_MINUTE` — et de même *N* fois `SESSION_ACTION_BURST` puis *N* fois `SESSION_ACTION_RATE_PER_MINUTE` pour les actions — la borne d'écriture du Broker est donc *N* fois celle annoncée au démarrage (les lignes annoncent « this process only »). À dimensionner en conséquence ; un état partagé (Redis) n'est pas fourni. Test : avec deux réplicas, envoyer en rafale, avec un jeton **sans aucun droit**, davantage de `POST /sessions` que le budget d'un seul réplica, et compter les lignes `denied` écrites par le Broker : elles doivent rester sous *N* × (rafale + débit × durée). Vérifier aussi qu'un réplica redémarré **repart avec un seau neuf** (un redémarrage rend le budget) : c'est la limite du dispositif, pas une panne.
- **Adresse du client derrière l'arête** (ADR-0015) : les limites par adresse (login, requêtes authentifiées) sont, comme le budget de `POST /sessions`, **par processus** de Gateway. Elles ne valent que si `TRUSTED_PROXY_CIDRS` contient l'adresse **telle que chaque réplica du Gateway la voit** : si Traefik est lui-même en haute disponibilité (plusieurs instances, ou un équilibreur devant lui), déclarez le réseau qui les contient **toutes** ; une instance oubliée est un pair non fiable dont l'en-tête est ignoré — ses utilisateurs retombent dans un seul seau, celui de l'instance. Test : pour chaque instance de Traefik, envoyer en rafale (plus que `CLIENT_LOGIN_BURST`, 5 par défaut) des tentatives de login avec un `X-Forwarded-For` différent à chaque fois : elles doivent être refusées après la rafale **quelle que soit l'instance traversée** ; puis, depuis **deux** machines différentes à travers la même instance, vérifier que chacune a sa propre rafale (sans quoi `TRUSTED_PROXY_CIDRS` ne contient pas cette instance). Rien de cela n'a été essayé sur un vrai Traefik.
- **Échéance de certificat** (ADR-0010) : sur un environnement de test, laisser expirer — ou émettre avec une durée de quelques minutes — le certificat d'un service du chemin d'accès (le Vault, par exemple), et vérifier que (a) l'alerte d'approche d'échéance a bien été reçue **avant**, (b) l'échéance se manifeste comme prévu (nouvelles sessions refusées, jamais acceptées sans authentification), (c) le dépôt d'un certificat renouvelé rétablit le service **sans redémarrage** après au plus `TLS_RELOAD_INTERVAL`. Refaire l'exercice avec un renouvellement invalide (mauvaise autorité) : le service doit garder l'ancien certificat et le dire dans son journal.
- **Sondes** : les sondes HTTP du kubelet ne présentent pas de certificat client et échouent sur un port mTLS. Utiliser des sondes `tcpSocket` ; ne **pas** désactiver le mTLS pour « faire passer » une sonde.
- Coupure volontaire de Kafka pendant une charge de sessions actives, vérification que les nouvelles créations sont bien refusées (fail-closed) plutôt que silencieusement non auditées.

## 7. Prochaine étape

Le guide **PRA/PCA** s'appuiera sur cette topologie pour couvrir la perte d'un site entier : réplication cross-site de PostgreSQL/MinIO/Kafka, procédure de bascule, et — point spécifique à un PAM — la question de savoir si un Vault répliqué sur un site sinistré doit être considéré comme potentiellement compromis avant réouverture des accès.

---
*Guide restant à venir : Guide PRA/PCA.*
