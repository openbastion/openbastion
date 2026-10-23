# architecture — la structure technique d'OpenBastion

Lis ce fichier avant de toucher au code. Il te dit où se trouve quoi, comment un service est construit, et quelles propriétés du système tu ne dois jamais casser. Quand ce fichier et le code divergent, **le code fait foi** : corrige ce fichier dans le même commit.

---

## 1. Le produit en quelques lignes

OpenBastion est un PAM (Privileged Access Management) open source, cloud-native, en Go, sous licence Apache 2.0, entièrement original. Il centralise les accès privilégiés : l'opérateur n'a **jamais** le mot de passe de la cible, toutes les connexions passent par un proxy, toutes les sessions sont enregistrées, tout est audité.

Ce qui est implémenté aujourd'hui (MVP, un seul protocole : SSH) : Authentication, Authorization (RBAC), Session Broker, Password Vault, SSH Proxy, Audit Service (chaînage de hash), Command Recorder (replay texte chiffré au repos), API Gateway, mTLS interne. Le reste du périmètre (RDP, Workflow/Approval, UI, SDK…) est décrit dans `docs/architecture/OpenBastion_04_Roadmap.md` et **n'existe pas encore** : ne fais pas comme si.

## 2. Invariants — ne les affaiblis jamais

Chacun est tenu par du code et par des tests. Si une tâche semble exiger d'en affaiblir un, **arrête-toi et demande** (voir `policies.md` §2).

| ID | Invariant | Où il est tenu |
|---|---|---|
| ADR-0003 | Un secret ne traverse jamais le control plane (Gateway, Broker). Seul le proxy échange un scope à usage unique contre un credential, directement auprès du Vault. | Le port `VaultAuthorizer` du Broker n'a **aucune méthode** pour lire un credential ; `pkg/proxycore` purge le secret octet par octet. |
| ADR-0008 | Une session qui ne peut pas être enregistrée n'a pas lieu ; une commande non acquittée par le recorder n'est jamais exécutée. | `RECORDING_POLICY=required` par défaut (`pkg/proxycore`, ssh-proxy). |
| ADR-0009 | Le break-glass ne retire que l'enregistrement acquitté, sous six verrous cumulés, et jamais en silence. | Broker + `proxycore.Admission` (preuve à champs non exportés). |
| ADR-0011 | Une demande break-glass n'ouvre rien tant qu'une **autre** personne ne l'a pas approuvée : pas d'auto-approbation (par identifiant d'utilisateur), décideur et rôles tirés du jeton vérifié par la Gateway, décision auditée avant d'agir puis compare-and-swap, `connect` réservé au demandeur. | Session Broker (`decide`, `SaveIfStatus`) + liste blanche des routes `/sessions/...` du Gateway. |
| ADR-0012 | La liste des demandes break-glass en attente ne montre que ce que l'appelant peut décider (vide, jamais 403, sans autorité ; 503 plutôt qu'une liste partielle) ; la notification est au mieux et **n'est jamais un contrôle** (port sans valeur de retour, asynchrone, après coup) ; l'URL du webhook est un secret (jamais journalisée) ; ce que le demandeur écrit (`targetAccountId`) n'atteint jamais tel quel un message lu par des tiers. | Session Broker (`ListPendingApprovals`, `ApprovalNotifier`, `infrastructure/webhook_notifier.go`, `wellFormedAccountID`) + Gateway (`handleListPending` reconstruit la requête). |
| ADR-0013 | Un demandeur ne peut pas avoir plus de `BREAKGLASS_MAX_PENDING_PER_REQUESTER` demandes en attente (3 par défaut ; **par demandeur**, jamais global ni par compte : un plafond partagé serait une arme) ; le plafond est tenu **atomiquement**, entre réplicas aussi ; un décompte impossible est un 503, jamais une acceptation ; il n'est demandé qu'après l'autorité ; le webhook, si `BREAKGLASS_NOTIFY_SECRET` est fixé, est signé (`v1=` HMAC-SHA256 de `horodatage.corps`) et le secret n'apparaît jamais dans un journal ni une erreur. | Session Broker (`checkPendingQuota`, `SaveIfUnderPendingLimit` dans les deux magasins — verrou consultatif PostgreSQL —, `WebhookNotifier.WithSecret`) + relais du `429` par le Gateway. |
| ADR-0010 | L'identité de l'appelant vient du certificat, jamais du corps de la requête ; chaque route a sa liste d'appelants, refus par défaut. | `pkg/mtls`, un `internal/interfaces/callers.go` par service. |
| — | L'audit est fail-closed : un événement qui ne peut pas être écrit empêche l'action. | Broker, proxy. |
| — | Les défauts sont les plus stricts ; le comportement faible se demande **par son nom**, et une valeur inconnue est fatale. | `RECORDING_POLICY`, `INTERNAL_TLS`, `BREAKGLASS_*` (dont `BREAKGLASS_APPROVAL`) ; `BREAKGLASS_NOTIFY_URL` absente = pas de notification, annoncé au démarrage, et une valeur inutilisable est fatale ; `BREAKGLASS_MAX_PENDING_PER_REQUESTER` (1 à 100, pas d'« illimité ») et `BREAKGLASS_NOTIFY_SECRET` (32 octets au moins, sans URL = fatal) : hors bornes, fatal. |

## 3. Arborescence réelle

```
go.work                          workspace Go : un module par composant (ADR-0002)
Makefile                         build, vet, test, test-integration, test-postgres, pki, run-*
NOTES_SANDBOX.md                 journal des écarts, découvertes, limites, état des tests — à tenir à jour
README.md
.agents/  AGENTS.md              ce dossier
pkg/
  proxycore/                     pipeline proxy commun (listener, credential fetcher, tap, terminator) — ADR-0006
  mtls/                          identité par certificat, Guard, rechargement, PKI de dev — ADR-0010
    pki/  mtlstest/  cmd/openbastion-pki/
services/
  access/
    api-gateway/                 seul point d'entrée public ; écrase l'identité revendiquée par le client
    authentication/              Argon2id, JWT
    authorization/               RBAC deny-by-default, un deny explicite l'emporte
    session-broker/              orchestrateur ; ne voit jamais un secret
  proxy/ssh-proxy/               premier proxy réel (golang.org/x/crypto/ssh) ; sshcodec/
  vault/password-vault/          comptes, secrets (chiffrés), scopes à usage unique
  recording-audit/
    audit-service/               journal chaîné par hash, signé
    command-recorder/            replay texte, chiffrement enveloppe AES-256-GCM
proto/                           contrats Protobuf (doc 07) — la forme des messages
test/integration/                scénarios sur processus réels (binaires compilés, ports 18xxx)
docs/
  architecture/                  docs 00–07 numérotés ; les ADR sont consolidés dans le doc 03
  api/                           OpenAPI (doc 05)
  guides/                        administrateur, développeur, sécurité, HA, PRA/PCA, utilisateur
deploy/                          docker-compose, helm, k8s (squelettes)
```

`docs/adr/` est vide : tant que les ADR ne sont pas éclatés en fichiers, **ils vivent dans `docs/architecture/OpenBastion_03_ADR.md`**.

## 4. Le patron d'un service (Clean Architecture)

Chaque service a la même forme. Respecte-la ; ne mélange pas les couches.

```
services/<domaine>/<service>/
  go.mod                         module propre (+ replace locaux vers pkg/…, voir rules.md §8)
  cmd/<service>/main.go          composition : lit l'environnement, construit les adaptateurs, démarre
  internal/
    domain/                      entités + PORTS (interfaces de dépôt/clients). Aucune dépendance externe.
    application/                 cas d'usage. Dépend du domaine seulement. Toute la logique métier est ici.
    infrastructure/              adaptateurs : magasin mémoire, magasin PostgreSQL (InitSQL idempotent),
                                 clients HTTP vers les autres services (champ Client *http.Client + orDefault)
    interfaces/
      http.go                    handlers HTTP/JSON (remplaçant de gRPC, voir §6) ; aucune règle métier
      callers.go                 CallerRules() : qui peut appeler quelle route (mTLS)
```

Règles de dépendance : `interfaces → application → domain` ; `infrastructure → domain` (elle implémente ses ports). `domain` n'importe rien du projet. `main.go` est le seul endroit qui connaît tout le monde. Une règle métier dans un handler HTTP ou dans un adaptateur est un défaut.

## 5. Qui appelle qui (identités mTLS)

Les noms de service sont ceux des SAN URI `spiffe://<domaine>/<service>` : `api-gateway`, `authentication`, `authorization`, `session-broker`, `ssh-proxy`, `password-vault`, `audit-service`, `command-recorder`, plus `admin-cli` (outillage opérateur).

```
utilisateur ──HTTP──► api-gateway ──► authentication   (login, verify)
                          │──────► session-broker      (/sessions… : création, `GET /sessions?status=pending_approval` (seul statut servi), connect, approve, reject — liste blanche ; l'identité de l'appelant est celle du jeton, la requête de liste est reconstruite)
                          │──────► password-vault      (administration des comptes, rotation)
                          │──────► authorization       (création de politiques)
                          └──────► command-recorder    (lecture d'un replay)
session-broker ──► authorization (check-access) · password-vault (authorize-scope, métadonnées de compte)
               ──► audit-service (emit-event)   · ssh-proxy (establish-session)
               ──► webhook de notification (BREAKGLASS_NOTIFY_URL, HORS maillage mTLS, au mieux, jamais un contrôle — ADR-0012 ; signé si BREAKGLASS_NOTIFY_SECRET — ADR-0013)
ssh-proxy ──► password-vault (fetch-credential) · audit-service · command-recorder (écriture des commandes)
password-vault, command-recorder ──► authorization (check-access)
admin-cli ──► authentication (POST /auth/v1/users) · audit-service (GET /audit/v1/verify-chain)
```

Ports par défaut : gateway 8080, vault 8081, audit 8082, authorization 8083, broker 8084, ssh-proxy 8085 (API) + 2222 (SSH), authentication 8086, recorder 8087. La source de vérité des appelants autorisés est le `callers.go` de chaque service, pas ce schéma.

## 6. Transport, contrats, identité

- Le transport interne documenté est gRPC (doc 07). **Dans ce dépôt, c'est du HTTP/JSON** avec exactement les noms de champs des messages Protobuf, uniquement dans `internal/interfaces/`. Raison : réseau restreint du sandbox de build (`NOTES_SANDBOX.md`). Ne « répare » pas cet écart de ton propre chef.
- TLS 1.3 mutuel entre services, `INTERNAL_TLS=required` par défaut. Le listener public du Gateway reste en HTTP (le TLS se termine à l'arête).
- Un client HTTP interne n'est construit que pour des pairs déclarés (`mtls.Peer{URL, Service}`) : l'identité du pair est épinglée.
- Les contrats évoluent **de façon additive** uniquement (doc 07 §1) ; une rupture exige un package `v2`. Un numéro de champ Protobuf supprimé est `reserved`, jamais réutilisé.

## 7. Données

- PostgreSQL 15+ pour les services à état. Chaque magasin a une variante mémoire (développement/tests) et une variante PostgreSQL ; `DATABASE_URL` choisit. Le schéma est créé par un `InitSQL` **idempotent** (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN IF NOT EXISTS`) : une base créée avant un incrément doit se mettre à niveau sur place.
- Modèle de données de référence : `docs/architecture/OpenBastion_06_Modele_Donnees.md`.
- Secrets de bootstrap par variable d'environnement (`KMS_KEY_HEX`, `TOKEN_SIGNING_KEY_HEX`) : un service avec `DATABASE_URL` refuse de démarrer sans sa clé.

## 8. Où est la vérité

| Question | Fichier |
|---|---|
| Pourquoi cette décision ? | `docs/architecture/OpenBastion_03_ADR.md` |
| Quelle API publique ? | `docs/api/OpenBastion_05_OpenAPI.md` |
| Quel message entre services ? | `docs/architecture/OpenBastion_07_Interfaces_Inter_Services.md` + `proto/` |
| Quelle table ? | `docs/architecture/OpenBastion_06_Modele_Donnees.md` |
| Qu'est-ce qui est fait, quelles limites, quels écarts ? | `NOTES_SANDBOX.md` (le plus à jour) |
| Quelle feuille de route ? | `docs/architecture/OpenBastion_04_Roadmap.md` |
| Comment exploiter / sécuriser ? | `docs/guides/` |

## 9. Écarts connus entre la cible et l'implémenté

À ne pas « corriger » sans demande : transport HTTP/JSON au lieu de gRPC ; pas de Workflow/Approval Engine (seulement l'approbation à un décideur du break-glass, ADR-0011, dans le Broker) ni de MFA natif ; notification du break-glass sans nouvelle tentative, non signée, un seul canal ; `GET /sessions` ne sert que `pending_approval` ; un seul protocole (SSH) ; KEK locale (`LocalKMS`) au lieu d'un vrai KMS/HSM ; Vault chiffre en un seul niveau (pas d'enveloppe) ; lignes du recorder non chaînées ; événements d'audit non attribués par l'identité du certificat ; listes d'appelants dans le code. La liste à jour est dans `NOTES_SANDBOX.md` et dans le Guide Sécurité §12.
