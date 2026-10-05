# OpenBastion — Guide PRA/PCA

**Version** 0.1 · **Statut** Draft de travail
**Public visé** Équipes SRE/exploitation, RSSI, direction des risques
**Document précédent** `OpenBastion_Guide_HA.md`
**Portée** Reprise après perte d'un site entier ou désastre majeur — la panne d'un composant isolé relève du guide HA, dont ce document réutilise la topologie et les tiers de criticité (§1).

---

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
| Kafka (flux d'audit durable) | Cluster étendu multi-site ou MirrorMaker vers le site DR | Quasi temps réel — l'audit est la donnée la moins tolérante à la perte (Full Auditability, doc 00 §2) |
| Password Vault / Secrets Manager | Réplication des blobs chiffrés (`vault_secrets.encrypted_material`) au même rythme que PostgreSQL — **la clé KMS reste dans un service de gestion de clés multi-région, jamais répliquée par le même mécanisme que les données** | Aligné sur PostgreSQL |
| Keycloak | Réplication de la base partagée, ou appui sur des IdP externes déjà nativement multi-site (Entra ID, etc.) | Minutes |

**Point d'attention** : répliquer le blob chiffré ne suffit pas à répliquer la capacité à le déchiffrer — la disponibilité du KMS/HSM sur le site DR est une dépendance à valider indépendamment, pas une conséquence automatique de la réplication PostgreSQL.

## 4. La question spécifique PAM : le site sinistré doit-il être traité comme compromis ?

C'est le point que la plupart des guides PRA génériques n'abordent pas, et qui est pourtant central pour un système qui existe précisément pour contenir des accès privilégiés.

**Principe** : tant que la cause du sinistre n'est pas formellement qualifiée comme non malveillante (§2), **le site principal sinistré est traité comme potentiellement compromis**, avec les conséquences suivantes :

- Toute clé de chiffrement (KMS) ayant été accessible depuis le site sinistré est considérée comme potentiellement exposée.
- Une **rotation complète et forcée** de tous les comptes privilégiés (`privileged_accounts`, doc 06 §3) est déclenchée après bascule, pas seulement une reprise de service — même si cela dégrade temporairement l'expérience opérateur.
- Les certificats de service (mTLS interne, doc Guide Sécurité §3) émis depuis l'autorité du site sinistré sont révoqués et réémis depuis le site DR.
- La chaîne d'audit (`prev_hash` → `hash`, doc 06 §4) est vérifiée intégralement avant réouverture des accès — une rupture de chaîne est traitée comme un indicateur de compromission, pas comme une simple anomalie technique.

**Si la cause est qualifiée comme non malveillante** (ex. incendie, panne électrique), cette procédure lourde peut être allégée à la seule vérification d'intégrité de la chaîne d'audit, sans rotation forcée systématique — décision qui reste de la responsabilité du RSSI, pas automatisée.

## 5. Procédure de bascule — squelette de runbook

1. **Détection et déclaration du sinistre** — critères objectifs (ex. Tier 0 du guide HA indisponible au-delà du RTO cible), déclarée par une personne désignée à l'avance, pas par consensus en temps de crise.
2. **Qualification de la cause** (§2) — gate décisionnel : détermine si la procédure allégée ou la procédure « site potentiellement compromis » (§4) s'applique. En cas de doute, la procédure la plus stricte s'applique par défaut.
3. **Bascule du trafic** vers le site DR (DNS ou load balancer global), promotion des répliques PostgreSQL/Kafka/MinIO en écriture primaire.
4. **Vérification d'intégrité de la chaîne d'audit** avant toute réouverture — étape bloquante, pas informative.
5. **Rotation forcée des comptes privilégiés**, si le gate de l'étape 2 l'exige.
6. **Réouverture progressive des accès** — un sous-ensemble restreint d'opérateurs/administrateurs d'abord, le temps de confirmer la stabilité du site DR, avant réouverture générale.
7. **Post-mortem documenté**, injecté lui-même dans l'audit (`audit_events`, `action = "dr.failover"`) — la bascule elle-même est un événement auditable, pas une exception au principe Full Auditability.

## 6. Objectifs cibles indicatifs — scénario désastre

| Niveau | RTO cible | RPO cible | Différence avec le guide HA |
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

## 9. Clôture de la séquence documentaire

Avec ce document se referment les trois guides demandés (Sécurité, HA, PRA/PCA), qui complètent la séquence architecture initiale (`OpenBastion_00` à `OpenBastion_07`). L'ensemble forme désormais une base cohérente — de l'invariant posé au tout premier document jusqu'à la procédure de bascule d'un site entier — prête à guider soit l'implémentation du MVP, soit la rédaction des guides restants du brief initial (documentation développeur, documentation administrateur, guide utilisateur), selon la priorité souhaitée.

---
*Séquence documentaire initiale complète.*
