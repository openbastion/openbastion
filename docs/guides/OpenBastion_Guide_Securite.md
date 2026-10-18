# OpenBastion — Guide Sécurité

**Version** 0.1 · **Statut** Draft de travail
**Public visé** RSSI, équipes sécurité, auditeurs, administrateurs de plateforme
**Portée** Ce guide consolide et détaille, sous l'angle sécurité, les décisions déjà prises dans la séquence architecture (`OpenBastion_00` à `OpenBastion_07`). Il ne redéfinit rien — il explique comment auditer et durcir ce qui a été conçu.

---

## 1. Modèle de menace

| Acteur / scénario | Considéré dans ce modèle | Contre-mesure principale |
|---|---|---|
| Opérateur privilégié malveillant ou compte compromis | Oui | Zero Standing Privilege : aucun credential statique connu de l'opérateur (doc 00 §2) |
| Compromission du control plane (Gateway, Broker, Workflow) | Oui | Invariant ADR-0003 : le control plane ne détient jamais de secret |
| Compromission d'un proxy protocolaire | Oui | Scope token à usage unique, purge mémoire immédiate, droits Vault strictement scopés par type de proxy |
| Interception réseau (MITM) inter-services | Oui | mTLS obligatoire sur tout trafic interne (§4) |
| Falsification rétroactive du journal d'audit | Oui | Chaînage par hash `prev_hash` → `hash` (doc 06 §4) |
| Compromission du KMS/HSM externe | Hors périmètre applicatif — traité comme dépendance externe critique, cf. §7 |
| Attaque physique sur l'infrastructure hôte | Hors périmètre de ce guide — relève de la sécurité de l'hébergeur/datacenter |

## 2. Rappel des trois invariants (doc 00, §2)

1. **Zero Standing Privilege** — aucun compte cible n'a de credential statique connu d'un humain.
2. **No Direct Access** — aucun client ne dialogue directement avec une cible ; tout passe par un proxy.
3. **Full Auditability** — chaque action produit un événement signé et chaîné.

Tout le reste de ce guide explique comment ces trois invariants sont concrètement appliqués et comment les vérifier.

## 3. Sécurité du transport

- **TLS externe** : terminaison chez Traefik, aucun trafic en clair au-delà de la bordure.
- **mTLS interne obligatoire** : chaque appel gRPC inter-services (`proto/`, doc 07) est authentifié dans les deux sens par certificat de service, jamais par simple confiance réseau (Zero Trust — doc 00 §2).
- **Identité de service** : chaque microservice porte une identité de type SPIFFE (`calling_service_id` propagé via `RequestContext`, doc 07 §2), vérifiable indépendamment du réseau d'origine.
- **Rotation automatique des certificats** : certificats internes à courte durée de vie, réémis en continu par une CA interne (Envoy comme data plane du mesh, doc 00 §10) — un certificat volé perd sa valeur rapidement.

**Point de vérification pour audit** : interroger un service au hasard sans certificat client valide doit systématiquement échouer, y compris depuis l'intérieur du cluster.

## 4. Sécurité de l'authentification

- **Émission de jetons** : Keycloak comme IdP de plateforme (ADR-0007), JWT à courte durée pour toute session opérateur.
- **Fédération externe** : LDAP, AD, Entra ID, OIDC, SAML délèguent l'authentification sans dupliquer de logique cryptographique par connecteur (ADR-0007).
- **MFA** (v1.0) : TOTP, WebAuthn/FIDO2, clés de sécurité, Passkeys, carte à puce/PKI — en MVP, le MFA est délégué au fournisseur OIDC externe (doc 04 §2), pas encore natif.
- **Protection anti brute-force** : verrouillage progressif après échecs répétés sur `/auth/login`, limité par IP et par compte, avec back-off exponentiel — à implémenter au niveau de l'Authentication Service, jamais laissé à la seule discrétion du proxy edge.

**Limite connue MVP** : sans MFA natif, la robustesse de l'authentification dépend entièrement du fournisseur OIDC configuré — à documenter explicitement dans le guide administrateur comme prérequis de déploiement.

## 5. Sécurité de l'autorisation

- **RBAC + ABAC combinés** (doc 00 §9) : le RBAC MVP (doc 04 §2) est complété par des attributs contextuels (heure, IP, score de risque) à partir de v1.0.
- **Principe du moindre privilège** : une politique (`policies`, doc 06 §3) lie un rôle à un `resource_pattern` précis (ex. `vault:account:prod-*`), jamais un accès global par défaut.
- **Décision centralisée** : toute vérification passe par `Authorization.CheckAccess` (doc 07 §8) — aucun service ne réimplémente sa propre logique d'autorisation.

**Point de vérification pour audit** : un rôle nouvellement créé sans politique associée ne doit donner accès à rien (deny-by-default).

## 6. Sécurité des secrets

- **Chiffrement à l'enveloppe** : `vault_secrets.encrypted_material` chiffré AES-256, la clé de déchiffrement référencée (`encryption_key_id`) et non stockée en base — dépendance à un KMS/HSM externe (doc 06 §3).
- **Enregistrements de session chiffrés au repos** (Command Recorder, implémenté) : chaque commande est scellée en AES-256-GCM sous une clé de données propre à la session ; cette clé n'existe en base que chiffrée par la KEK (`KMS_KEY_HEX` aujourd'hui, un KMS/HSM à terme — le Recorder refuse de démarrer sans elle dès que `DATABASE_URL` est défini). L'identifiant de session et l'horodatage sont liés au chiffrement : déplacer une ligne vers une autre session ou en modifier l'heure fait échouer la lecture au lieu de produire un faux replay. **Ce que cela ne couvre pas** : un attaquant qui contrôle la base peut supprimer ou réordonner des lignes intactes (elles ne sont pas chaînées entre elles, contrairement à l'audit, §9), et il suffit de la KEK *et* de la base pour tout lire — la KEK doit donc vivre hors de la base et de ses sauvegardes.
- **Argon2id** pour tout secret applicatif nécessitant un hash (ex. mots de passe des comptes locaux OpenBastion eux-mêmes, `users.password_hash`).
- **Le control plane ne voit jamais le secret** : seul `VaultCredentialIssuance.FetchCredential` (doc 07 §5) transporte un credential, et seul un proxy protocolaire authentifié par mTLS peut l'appeler.
- **Cycle de vie** : rotation manuelle, planifiée ou post-usage (doc 00, section Gestion des comptes) ; chaque rotation crée une nouvelle version dans `vault_secrets`, l'ancienne étant marquée `superseded_at` plutôt que supprimée — traçabilité complète.
- **Purge mémoire** : le `Credential Fetcher` de chaque proxy (doc 01 §4.2) purge le secret dès la fin de session ou en cas d'anomalie détectée — jamais persisté sur disque proxy, jamais journalisé.

**Point de vérification pour audit** : rechercher un credential en clair dans les logs de n'importe quel service doit systématiquement échouer — y compris en niveau de log `DEBUG`.

## 7. Sécurité applicative

| Menace | Contre-mesure |
|---|---|
| **CSRF** | Jetons CSRF sur toute action de mutation depuis l'Admin UI/User Portal, cookies de session en `SameSite=Strict` |
| **XSS** | Échappement systématique côté React (comportement par défaut), Content-Security-Policy stricte sur l'Admin UI et le User Portal, aucun rendu de HTML utilisateur non assaini (ex. `justification` de session affichée en texte brut) |
| **SSRF** | **Risque particulier sur le HTTP/HTTPS Web Proxy** (v2.0) : ce proxy relaie des requêtes vers des consoles web internes par construction — une politique d'allowlist stricte par cible déclarée dans `privileged_accounts` est obligatoire, aucune destination arbitraire ne doit être atteignable depuis une session |
| **Force brute** | Voir §4 — appliqué au niveau Authentication Service, pas uniquement en périphérie |

## 8. Sécurité de la couche proxy

C'est la zone de plus forte sensibilité du système — seul point où un secret existe en mémoire (doc 01 §4.2, ADR-0003).

- **Isolation réseau** : chaque famille de proxy ne doit avoir de connectivité sortante que vers les cibles de sa famille (ex. le Database Proxy ne doit pas pouvoir initier de connexion SSH).
- **Scoping Vault strict** : les droits d'un proxy auprès du Vault sont limités à son propre type de credential — vérifié par test de sécurité dédié (`test/security/`, doc 02 §9).
- **Scope token à usage unique** : `AuthorizeScope` (doc 07 §5) émet un jeton consommable une seule fois — un rejeu doit être rejeté par le Vault.
- **Enregistrer ou refuser** (ADR-0008) : par défaut (`RECORDING_POLICY=required`), une session que le Command Recorder ne peut pas enregistrer n'a pas lieu. Le proxy la refuse à l'admission si le recorder n'est pas prêt (injoignable, ou base en lecture seule), et ne transmet une commande à la cible qu'après que le recorder l'a acquittée : une commande non enregistrée n'est jamais exécutée, et la session s'arrête. Le mode `best-effort` n'est destiné qu'au développement ; il doit être demandé explicitement, le proxy l'annonce au démarrage, et il ne doit jamais être activé en production. Un proxy en mode `required` refuse de démarrer sans `RECORDER_URL`, et une valeur de politique inconnue est fatale — une faute de frappe ne doit pas sélectionner silencieusement le mode le plus faible.
- **Durcissement des conteneurs proxy** : exécution non-root, filesystem racine en lecture seule, capacités Linux réduites au strict nécessaire pour ouvrir les sockets réseau requis.

## 9. Sécurité de l'audit

- **Immutabilité** : chaînage par hash (doc 06 §4) — toute altération d'un événement passé casse la chaîne de tous les événements suivants, détectable par vérification périodique.
- **Signature** : chaque événement est signé par la clé de service de l'émetteur (`AuditIngestion.EmitEvent`, doc 07 §7), permettant de prouver *qui* a émis l'événement, indépendamment de la base de données elle-même.
- **Séparation des droits** : le service qui écrit dans `audit_events` ne doit pas être le même compte technique que celui qui peut modifier un rôle ou une politique — évite qu'un même compromis puisse à la fois agir et effacer ses traces.
- **Rétention** : partitionnement mensuel (doc 06 §3) permettant un archivage réglementaire par partition entière plutôt qu'une purge ligne à ligne, qui affaiblirait la chaîne de hash.

## 10. Durcissement du déploiement

- Images OCI minimales (distroless ou équivalent), sans shell ni outillage de débogage en production.
- `NetworkPolicy` Kubernetes restreignant chaque service aux flux strictement nécessaires (cohérent avec §8).
- Secrets de bootstrap de la plateforme elle-même (identifiants PostgreSQL, Keycloak admin, clés KMS) injectés via un mécanisme externe au dépôt (ex. Vault Agent Injector, External Secrets Operator) — jamais en clair dans les manifestes Helm versionnés.
- Scan de vulnérabilités des images et des dépendances en CI (`test/security/`, doc 02 §9), avant toute publication d'image.

## 11. Gestion des vulnérabilités et divulgation responsable

- **Cadence de scan** : SAST sur chaque merge request, DAST et scan de dépendances sur une cadence régulière, fuzzing ciblé sur les codecs de la couche proxy (surface d'analyse de protocole exposée à des cibles potentiellement compromises).
- **Signalement d'une vulnérabilité** : un fichier `SECURITY.md` à la racine du dépôt (à produire) doit préciser un canal de contact dédié, distinct des issues GitHub publiques, avec un délai d'embargo raisonnable avant divulgation publique — pratique standard pour un projet open source de sécurité.
- **Traitement** : toute vulnérabilité affectant la couche proxy ou le Vault est traitée en priorité maximale, compte tenu de leur sensibilité identifiée en §6 et §8.

## 12. Limites connues du périmètre MVP

À communiquer explicitement à toute organisation évaluant un déploiement MVP (doc 04 §2) :

| Limite | Compensée par | Résolue en |
|---|---|---|
| Pas de MFA natif | MFA délégué au fournisseur OIDC externe | v1.0 |
| Pas de validation multi-étapes | RBAC seul avant octroi | v1.0 (Workflow/Approval Engine) |
| Un seul protocole (SSH) | Périmètre volontairement restreint pour prouver l'invariant (doc 04 §1) | v1.0/v2.0 |
| Pas de détection d'anomalie/score de risque | Aucune | v2.0 |
| Le Command Recorder est une dépendance de disponibilité de **tous** les accès privilégiés (ADR-0008) : s'il est indisponible, aucune session ne s'ouvre et les sessions en cours s'arrêtent à leur prochaine commande | Déployer le recorder et sa base en haute disponibilité (guide HA), alerter sur `/readyz` | v1.0 (procédure d'urgence « break-glass » approuvée et auditée — non décidée) |
| Le recorder reçoit ses écritures sans authentification mutuelle : un appelant ayant accès au réseau interne pourrait y écrire de fausses entrées | `NetworkPolicy` restreignant l'accès au recorder aux seuls proxies | v1.0 (mTLS interne) |
| Un échec ambigu d'acquittement peut sur-enregistrer une commande qui n'a jamais été exécutée (le sens d'erreur inverse est exclu) | Lecture du replay à la lumière de l'audit de session | Non prévue — choix assumé (ADR-0008) |
| Un secret passé en argument d'une commande (`mysql -pXXXX`) est enregistré tel quel ; seul un secret saisi à un prompt est masqué | Chiffrement au repos + `recording:session:read` réservé aux auditeurs | À décider |

## 13. Prochaine étape

Les guides **Haute Disponibilité** et **PRA/PCA**, non encore rédigés, complètent ce guide sécurité — le premier traite de la résilience face à la panne, le second de la résilience face au désastre. Les deux s'appuient sur les mêmes composants ; ce guide se concentre volontairement sur la résilience face à l'attaque.

---
*Autres guides à venir : Guide Haute Disponibilité, Guide PRA/PCA.*
