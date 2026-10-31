# Reprise après sinistre (PRA/PCA)

**Public** équipes SRE/exploitation, RSSI, direction des risques. Reprise après la perte d'un site entier ; la panne d'un composant isolé relève de [`high-availability.md`](high-availability.md), dont ce document reprend la topologie.

## 1. PRA vs PCA vs HA — distinction opérationnelle

| | Périmètre | Question posée |
|---|---|---|
| **HA** (guide précédent) | Panne d'un composant, site unique | Comment continuer à fonctionner malgré la panne d'une réplique ? |
| **PCA** | Continuité de service pendant un sinistre | Comment les opérateurs continuent-ils à accéder aux systèmes critiques pendant que le site principal est indisponible ? |
| **PRA** | Reprise après sinistre | Comment reconstruire un site principal sain et y revenir, sans réintroduire de risque ? |

Un PAM a une particularité que peu d'autres systèmes partagent : **la question n'est pas seulement « le service revient-il ? » mais « peut-on faire confiance à ce qui revient ? »** — développé au §4.

## 2. Scénarios considérés

| Scénario | Nature | Implication spécifique |
|---|---|---|
| Perte physique d'un site (incendie, coupure électrique prolongée, catastrophe naturelle) | Non malveillant | Bascule technique pure, pas de doute sur l'intégrité des données |
| Corruption de données (bug, erreur d'exploitation) | Non malveillant, mais intègre potentiellement compromise localement | Vérification d'intégrité avant réouverture (§5) |
| Compromission majeure du site principal (ransomware, intrusion confirmée) | Malveillant | **Le site sinistré est traité comme hostile** — voir §4 |
| Erreur humaine catastrophique (suppression massive de comptes/politiques) | Non malveillant | Restauration ciblée depuis sauvegarde, sans bascule de site nécessairement |

Ces quatre scénarios ne déclenchent pas la même procédure — la qualification de la cause (§5, étape 2) est un point de décision, pas une formalité.

## 3. Stratégie de réplication cross-site

| Composant | Mécanisme | RPO indicatif |
|---|---|---|
| PostgreSQL | Réplication en streaming asynchrone vers le site DR | Quelques secondes à quelques minutes selon la latence inter-site |
| MinIO (enregistrements de session) | Réplication de bucket cross-site native | Minutes |
| Kafka (flux d'audit durable) | Cluster étendu multi-site ou MirrorMaker vers le site DR | Quasi temps réel — l'audit est la donnée la moins tolérante à la perte (Full Auditability, `docs/architecture/principles.md`) |
| Password Vault / Secrets Manager | Réplication des blobs chiffrés (`vault_secrets.encrypted_material`) au même rythme que PostgreSQL — **la clé KMS reste dans un service de gestion de clés multi-région, jamais répliquée par le même mécanisme que les données** | Aligné sur PostgreSQL |
| Command Recorder (replay des commandes) | Réplication des lignes chiffrées (`session_command_entries`, `session_recording_keys`) avec PostgreSQL — **sans la KEK, ces lignes sont définitivement illisibles** : la KEK (`KMS_KEY_HEX` aujourd'hui) se sauvegarde et se restaure séparément des données, jamais dans la même sauvegarde | Aligné sur PostgreSQL |
| Audit Service (chaîne d'audit) | Réplication de `audit_events` avec PostgreSQL — **sans les clés de chaîne (`AUDIT_CHAIN_KEY_HEX` et les précédentes, ADR-0027), l'histoire répliquée n'est plus vérifiable** : elles se sauvegardent et se restaurent séparément des données, comme la KEK | Aligné sur PostgreSQL |
| Audit Service (archives, ADR-0032) | Les archives `AUDIT_ARCHIVE_DIR` se répliquent comme les ancres, **par un autre chemin que la base** ; elles ne sont pas nécessaires pour vérifier la chaîne restante (le point de contrôle suffit), seulement pour consulter les mois archivés | À chaque archive |
| Audit Service (ancres, ADR-0028) | Le fichier `AUDIT_ANCHOR_FILE` se réplique **par un autre chemin que la base** (stockage en ajout seul, autre site) — restaurer base et ancres depuis la même source rendrait une réécriture indétectable ; sur le site DR, `verify-chain` contre les ancres répliquées dit si la base restaurée est celle qui a été ancrée | Période d'ancrage (60 s par défaut) |
| Keycloak | Réplication de la base partagée, ou appui sur des IdP externes déjà nativement multi-site (Entra ID, etc.) | Minutes |

**Point d'attention** : répliquer le blob chiffré ne suffit pas à répliquer la capacité à le déchiffrer — la disponibilité du KMS/HSM sur le site DR est une dépendance à valider indépendamment, pas une conséquence automatique de la réplication PostgreSQL.

## 4. La question spécifique PAM : le site sinistré doit-il être traité comme compromis ?

C'est le point que la plupart des guides PRA génériques n'abordent pas, et qui est pourtant central pour un système qui existe précisément pour contenir des accès privilégiés.

**Principe** : tant que la cause du sinistre n'est pas formellement qualifiée comme non malveillante (§2), **le site principal sinistré est traité comme potentiellement compromis**, avec les conséquences suivantes :

- Toute clé de chiffrement (KMS) ayant été accessible depuis le site sinistré est considérée comme potentiellement exposée.
- Une **rotation complète et forcée** de tous les comptes privilégiés (`privileged_accounts`, `docs/architecture/data-architecture.md` §3) est déclenchée après bascule, pas seulement une reprise de service — même si cela dégrade temporairement l'expérience opérateur.
- Les certificats de service (mTLS interne, `docs/security/network-security.md`, ADR-0010) émis depuis l'autorité du site sinistré sont écartés : il n'y a pas de liste de révocation, donc on **remplace l'autorité** — une nouvelle autorité sur le site DR, l'identité de chaque service réémise depuis elle, et l'ancienne autorité retirée des bundles `TLS_CA_FILE` (procédure de `docs/administration/initial-setup.md` « Remplacer l'autorité »). C'est cette étape qui rend inutilisable un certificat de service volé sur le site compromis ; sans elle, quiconque détient la clé d'un service du site sinistré reste accepté par les services du site DR.
- La chaîne d'audit (`prev_hash` → `hash`, `docs/architecture/data-architecture.md` §4) est vérifiée intégralement avant réouverture des accès — une rupture de chaîne est traitée comme un indicateur de compromission, pas comme une simple anomalie technique.

**Si la cause est qualifiée comme non malveillante** (ex. incendie, panne électrique), cette procédure lourde peut être allégée à la seule vérification d'intégrité de la chaîne d'audit, sans rotation forcée systématique — décision qui reste de la responsabilité du RSSI, pas automatisée.

## 5. Procédure de bascule — squelette de runbook

1. **Détection et déclaration du sinistre** — critères objectifs (ex. Tier 0 de `docs/deployment/high-availability.md` indisponible au-delà du RTO cible), déclarée par une personne désignée à l'avance, pas par consensus en temps de crise.
2. **Qualification de la cause** (§2) — gate décisionnel : détermine si la procédure allégée ou la procédure « site potentiellement compromis » (§4) s'applique. En cas de doute, la procédure la plus stricte s'applique par défaut.
3. **Bascule du trafic** vers le site DR (DNS ou load balancer global), promotion des répliques PostgreSQL/Kafka/MinIO en écriture primaire.
4. **Vérification d'intégrité de la chaîne d'audit** avant toute réouverture — étape bloquante, pas informative.
   *La version du schéma de chaque base restaurée se lit dans `schema_migrations` (ADR-0030). Des binaires plus anciens que la base démarrent (journal `WARNING`) ; une base plus ancienne que les binaires est mise à niveau à leur démarrage. Un service qui refuse de démarrer avec « changed after it was applied » signale une base ou un binaire qui n'est pas celui que l'on croit : à traiter comme un indice au gate de l'étape 2.*
5. **Rotation forcée des comptes privilégiés**, si le gate de l'étape 2 l'exige.
   *Si le site est traité comme compromis, le remplacement de l'autorité interne (ADR-0010) se fait ici aussi — avant la réouverture : sinon un certificat de service volé reste valide face aux services du site DR.*
6. **Réouverture progressive des accès** — un sous-ensemble restreint d'opérateurs/administrateurs d'abord, le temps de confirmer la stabilité du site DR, avant réouverture générale.
7. **Post-mortem documenté**, injecté lui-même dans l'audit (`audit_events`, `action = "dr.failover"`) — la bascule elle-même est un événement auditable, pas une exception au principe Full Auditability.

## 6. Objectifs cibles indicatifs — scénario désastre

| Niveau | RTO cible | RPO cible | Différence avec `docs/deployment/high-availability.md` |
|---|---|---|---|
| Tier 0 (Vault, Auth, Broker, PostgreSQL) | < 1 heure | < 5 minutes | RTO nettement plus large qu'en HA — une bascule de site implique une qualification humaine (§5, étape 2), pas une automatisation pure |
| Tier 1 (Proxies, Audit/Kafka) | < 2 heures | < 5 minutes (Kafka quasi temps réel) | La disponibilité de l'audit conditionne la réouverture (§4) — pas de compromis possible sur son RPO |
| Tier 2 (Search, Reporting, Notification) | < 24 heures | best-effort | Peut être reconstruit après coup depuis les sources de vérité (PostgreSQL/MinIO) |

## 7. Exercice de bascule

- **Fréquence recommandée** : au moins un exercice complet par an, plus des exercices « tabletop » (simulation de décision sans bascule technique réelle) plus fréquents, notamment sur l'étape de qualification de la cause (§5, étape 2), qui est la plus sujette à erreur de jugement en situation de stress.
- **Participants obligatoires** : au-delà de l'équipe SRE, la personne habilitée à déclencher une rotation forcée (§4) doit participer activement, pas seulement être informée après coup.
- **Critère de réussite** : non seulement le service revient dans les RTO/RPO cibles (§6), mais la chaîne d'audit est vérifiée sans rupture et la décision de rotation forcée (ou son absence justifiée) est documentée.

## 8. Hors périmètre de ce guide

- Sécurité physique du site DR lui-même (contrôle d'accès, alimentation, contrats avec l'hébergeur) — relève de la politique de sécurité physique de l'organisation déployant OpenBastion, pas du projet.
- Plan de continuité pour les processus métier de l'organisation cliente au sens large — ce guide couvre la continuité d'*OpenBastion*, pas celle de l'ensemble du système d'information qu'il protège.
