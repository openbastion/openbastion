# OpenBastion — Documentation Administrateur

**Version** 0.1 · **Statut** Draft de travail
**Public visé** Administrateurs de la plateforme OpenBastion (déploiement, configuration, exploitation courante)
**Document précédent** `OpenBastion_Doc_Developpeur.md`
**Portée** Ce document ne couvre que le périmètre MVP (doc 04 §2) : authentification OIDC, RBAC simple, SSH Proxy, Password Vault, Audit. Les sections marquées *v1.0* anticipent des fonctionnalités pas encore livrées.

---

## 1. Prérequis de déploiement

| Composant | Rôle |
|---|---|
| Kubernetes / K3s / OpenShift, ou Docker Compose pour un petit site on-premise | Orchestration (doc 00 §10) |
| PostgreSQL 15+ | Métadonnées, politiques, comptes (doc 06) |
| Redis | Cache, état de session |
| MinIO | Stockage des enregistrements (v1.0 pour la vidéo) |
| NATS, Kafka | Bus temps réel / audit durable (ADR-0001) |
| Keycloak | IdP de plateforme (ADR-0007) |
| Un fournisseur OIDC accessible | Fédération d'identité en périmètre MVP (doc 04 §2) |
| Une autorité de certification interne (cert-manager, Vault PKI, SPIRE…), ou `openbastion-pki` pour un petit site | Identité de chaque service pour le mTLS interne (ADR-0010) — sans elle, aucun service ne démarre |

## 2. Installation

**Kubernetes (référence de production)** :

```sh
helm repo add openbastion https://charts.openbastion.io
helm install openbastion openbastion/openbastion \
  --namespace openbastion --create-namespace \
  -f values.yaml
```

Extrait `values.yaml` minimal pour un déploiement MVP :

```yaml
postgresql:
  external: true
  host: postgres.internal
oidc:
  issuerUrl: "https://idp.example.com/realms/company"
  clientId: "openbastion"
  clientSecretRef: "openbastion-oidc-secret"
sshProxy:
  replicas: 3
vault:
  kmsKeyRef: "arn:aws:kms:eu-west-3:xxx:key/xxx"   # ou équivalent HSM on-premise
```

**Docker Compose (petit site on-premise, développement)** : voir `deploy/docker-compose/docker-compose.yml` (doc 02 §6) — non recommandé pour un environnement de production au-delà d'un pilote.

## 3. Configuration initiale

1. **Donner une identité à chaque service** (mTLS interne, obligatoire) — voir « Identité des services » ci-dessous.
2. **Bootstrap du premier compte administrateur** — créé automatiquement à l'installation si `bootstrapAdmin` est renseigné dans `values.yaml` ; désactivé après première connexion.
3. **Vérifier la fédération OIDC** : `GET /api/v1/auth/me` après une connexion de test doit renvoyer `identitySource: "oidc"` et le mapping correct de `username`/`displayName` (doc 05 §2, schéma `User`).
4. **Créer les premiers rôles** (§5).
5. **Politique d'enregistrement des sessions** — voir ci-dessous.
6. **Décider du break-glass** (désactivé par défaut) — voir « Accès d'urgence (break-glass) » ci-dessous.

### Identité des services (mTLS interne)

Tous les appels entre services sont en TLS 1.3, avec certificat des deux côtés (ADR-0010). Chaque service lit son identité dans des fichiers PEM :

| Variable | Rôle |
|---|---|
| `INTERNAL_TLS` | `required` (défaut) ou `disabled`. **Un service sans certificat refuse de démarrer.** `disabled` supprime toute authentification entre services : développement uniquement, avertissement à chaque démarrage. Toute autre valeur est une erreur fatale. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Certificat (chaîne, feuille en premier) et clé privée **du service**. |
| `TLS_CA_FILE` | Autorités de confiance (un ou plusieurs certificats). |
| `TLS_TRUST_DOMAIN` | Domaine de confiance, `openbastion.local` par défaut. Le même pour tous les services. |
| `TLS_RELOAD_INTERVAL` | Fréquence maximale de relecture des fichiers, `5s` par défaut. |

**Forme de l'identité.** Le certificat de chaque service porte **un seul SAN URI**, `spiffe://<domaine>/<service>`, avec pour `<service>` l'un de : `api-gateway`, `authentication`, `authorization`, `session-broker`, `ssh-proxy`, `password-vault`, `audit-service`, `command-recorder`, et `admin-cli` pour l'outillage opérateur (qui n'a accès qu'à la création d'utilisateurs et à la vérification de la chaîne d'audit). Il doit servir et authentifier un client (`serverAuth` et `clientAuth`) et porter, comme noms DNS ou adresses IP, ceux sous lesquels les autres services le joignent : ils vérifient l'adresse qu'ils composent. **Un service refuse le certificat d'un autre service**, même valide. Avec SPIRE, enregistrer les identités sous cette forme (un seul segment de chemin).

**Petit site ou développement : `openbastion-pki`.**

```sh
make pki                                   # autorité + une identité par service, dans .pki/
# ou, sans make :
openbastion-pki all -dir /etc/openbastion/pki -trust-domain bastion.example.com -ttl 168h
openbastion-pki issue -dir … -service password-vault -dns vault.openbastion.svc -ip 10.0.0.12 -ttl 24h
```

Chaque service reçoit `<dir>/<service>/cert.pem` et `key.pem` (clé en 0600) et la même `<dir>/ca.pem`. La clé de l'autorité (`ca-key.pem`) **ne doit atteindre aucun service** : elle reste sur la machine qui émet. Les certificats durent 7 jours par défaut : relancer la commande les **renouvelle** sans redémarrage (voir ci-dessous) et conserve l'autorité.

**Renouveler un certificat.** Remplacer les fichiers du service (clé d'abord, puis certificat — `openbastion-pki issue` et cert-manager le font). Le service les reprend au plus tard après `TLS_RELOAD_INTERVAL`, sans redémarrage, et journalise `mtls: reloaded the identity of <service>`. Un fichier invalide (autre autorité, autre service, clé qui ne correspond pas) est **refusé** — `mtls: NOT reloading … keeping the current one` — et le service garde son identité actuelle : renouveler avec une erreur ne casse pas un service qui tourne, mais il faut lire le journal pour s'en apercevoir.

**Surveiller l'échéance.** Un certificat expiré est une panne : les pairs refusent le service. Le service journalise `mtls: the certificate of <service> expires at … — renew it` quand il reste 20 % de sa durée de vie, et `… EXPIRED …` à l'échéance. Alerter sur ces deux messages, **et** sur l'échéance des fichiers eux-mêmes (par exemple `openssl x509 -enddate -noout -in cert.pem`), car un service qui ne tourne plus ne journalise rien.

**Remplacer l'autorité** (compromission, ou fin de vie de l'autorité) — dans cet ordre, sans interruption :

1. Créer la nouvelle autorité ; mettre **les deux** certificats d'autorité dans le fichier `TLS_CA_FILE` de chaque service. Chaque service accepte immédiatement les certificats de l'une et de l'autre.
2. Réémettre l'identité de chaque service depuis la nouvelle autorité.
3. Retirer l'ancienne autorité du bundle. **Un service refuse de retirer l'autorité qui a signé son propre certificat** (`does not chain to the CA bundle`) : l'étape 2 doit être faite avant. À cet instant, tout certificat de l'ancienne autorité — y compris un certificat volé — cesse d'être accepté. C'est le remplacement de l'autorité, pas une liste de révocation, qui répond à une compromission.

**La Gateway** garde son listener public en HTTP (le TLS se termine chez Traefik) : elle a une identité pour ses appels vers les autres services, pas pour ceux qu'elle reçoit.

**Sondes Kubernetes.** Les sondes HTTP du kubelet ne présentent pas de certificat client : utiliser des sondes `tcpSocket` sur les ports internes (la santé applicative se vérifie par la supervision, avec une identité de service). Voir le guide HA.

### Politique d'enregistrement

Chaque proxy lit `RECORDING_POLICY` :

| Valeur | Comportement |
|---|---|
| `required` (défaut) | Une session qui ne peut pas être enregistrée n'a pas lieu : refusée si le Command Recorder n'est pas prêt, terminée si une commande n'a pas pu y être enregistrée (la commande n'est alors **pas** exécutée sur la cible). |
| `best-effort` | La session continue si l'enregistrement échoue ; des commandes sont perdues. **Développement uniquement.** Le proxy le signale par un avertissement au démarrage. |

En mode `required`, `RECORDER_URL` (adresse du Command Recorder) est obligatoire : sans elle, le proxy refuse de démarrer. Une valeur de `RECORDING_POLICY` inconnue est une erreur fatale, pas un repli. Le recorder expose `GET /healthz` (le processus tourne) et `GET /readyz` (il pourrait écrire : base joignable et inscriptible) ; c'est `/readyz` que doivent sonder l'orchestrateur et la supervision, car un recorder dont la base est passée en lecture seule est « vivant » mais bloque en pratique tous les accès privilégiés.

### Accès d'urgence (break-glass)

Quand le recorder est en panne et qu'un incident ne peut pas attendre, une session peut s'exécuter **sans enregistrement acquitté**. C'est une dérogation à l'enregistrement et rien d'autre (ADR-0009) : l'authentification, les droits `session:create`, le Vault et l'audit restent en vigueur. **Désactivé par défaut**, il se règle à deux endroits qui doivent tous deux être d'accord — et, une fois activé, **une demande attend l'approbation d'une seconde personne** (ADR-0011, voir plus bas) :

| Où | Variable | Effet |
|---|---|---|
| Session Broker | `BREAKGLASS_MAX_MINUTES` | Durée maximale d'une session break-glass, en minutes. Absente ou `0` : désactivé. Un texte ou un négatif est une erreur fatale au démarrage. Revenir à `0` coupe la possibilité **immédiatement**, y compris pour les sessions déjà accordées mais pas encore ouvertes. |
| SSH Proxy | `BREAKGLASS_ENABLED=true` | Autorise ce proxy à honorer une dérogation. Ignoré (avec un avertissement) hors `RECORDING_POLICY=required`. |
| Session Broker | `BREAKGLASS_APPROVAL` | `required` (**défaut**) : une demande break-glass attend l'approbation d'une autre personne. `disabled` : l'ancien comportement à une seule personne (ADR-0009), à demander **par son nom** — le Broker l'annonce au démarrage (« WITHOUT APPROVAL »). Toute autre valeur est une erreur fatale. |
| Session Broker | `BREAKGLASS_APPROVAL_WINDOW_MINUTES` | Délai laissé pour décider, de 1 à 1440 (défaut **15**). Passé ce délai la demande est `expired` et ne peut plus être décidée. Tout autre texte ou nombre est une erreur fatale. |

Aucun rôle n'en dispose par défaut — pas même un administrateur. Pour l'accorder, créez une politique sur la ressource **`breakglass:account:<id du compte>`**, distincte de `vault:account:…` :

```sh
curl -X POST https://bastion.example.com/api/v1/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "oncall-breakglass-prod-db-01",
    "role": "oncall-sre",
    "resourcePattern": "breakglass:account:<id-de-prod-db-01>",
    "effect": "allow"
  }'
```

Évitez les motifs génériques (`breakglass:account:*`) : ils accorderaient l'urgence sur **tous** les comptes.

**Qui approuve.** L'approbation a **sa propre ressource**, `breakglass-approve:account:<id du compte>` — le préfixe diffère exprès de `breakglass:` : la politique des demandeurs ne couvre pas l'approbation, et réciproquement. Accordez-la à un rôle différent (chef d'incident, astreinte N+1) :

```sh
curl -X POST https://bastion.example.com/api/v1/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "incident-lead-approves-prod-db-01", "role": "incident-lead",
       "resourcePattern": "breakglass-approve:account:<id-de-prod-db-01>", "effect": "allow"}'
```

Évitez `*` et `breakglass*` : ces motifs couvrent **à la fois** la demande et l'approbation, et annulent la double validation. Le moteur compare des rôles et des motifs, pas des personnes : veillez à ce que personne ne détienne les deux rôles sur un même compte — et, de toute façon, **personne n'approuve sa propre demande** (la comparaison porte sur l'identifiant d'utilisateur, pas sur le rôle).

Demande par l'opérateur (justification d'au moins 10 caractères, durée de 1 à `BREAKGLASS_MAX_MINUTES`) :

```sh
curl -X POST https://bastion.example.com/api/v1/sessions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"targetAccountId": "<id>", "justification": "INC-4821 : base de production saturée, recorder HS", "durationMinutes": 20, "breakGlass": true}'
```

La réponse est `201` avec `"status": "pending_approval"` : **ce n'est pas encore une session**, `connect` répond `409`. Il n'existe pas encore de liste ni de notification des demandes en attente : le demandeur transmet l'identifiant de la session (`id`) à la personne qui approuve — par l'astreinte, le canal d'incident. Cette personne relit la demande puis décide :

```sh
curl https://bastion.example.com/api/v1/sessions/<id> -H "Authorization: Bearer $APPROVER_TOKEN"   # qui, quel compte, pourquoi, échéance
curl -X POST https://bastion.example.com/api/v1/sessions/<id>/approve -H "Authorization: Bearer $APPROVER_TOKEN"
curl -X POST https://bastion.example.com/api/v1/sessions/<id>/reject  -H "Authorization: Bearer $APPROVER_TOKEN"
```

Après `approve`, la session est `active` et la durée demandée court **à partir de l'approbation**. **Seul le demandeur** peut ouvrir la session (`connect`) : l'approbateur reçoit `403`.

À relire après chaque usage : `session.breakglass_requested` (demande mise en attente, accordée ou refusée), `session.breakglass_approved` / `session.breakglass_rejected` (**qui** a décidé ; un `success=false` est un refus — auto-approbation, politique absente — à relire aussi), `session.breakglass` (la dérogation a **réellement** servi : le recorder n'était pas prêt) et `session.expire` (fin de session à l'échéance). Une session demandée en break-glass alors que le recorder était prêt reste enregistrée normalement et ne laisse pas de `session.breakglass`.

Ce que la double validation ne fait **pas** : elle ne détecte pas deux comptes tenus par la même personne, ne remplace pas la revue après l'incident (non implémentée), n'a qu'un approbateur (pas de quorum), et n'audite pas l'expiration d'une demande non décidée (le statut se lit `expired`).

## 4. Gestion des comptes privilégiés (Vault)

Onboarder un compte SSH cible :

```sh
curl -X POST https://bastion.example.com/api/v1/vault/accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-db-01-root",
    "targetHost": "10.0.4.12",
    "protocol": "ssh",
    "rotationPolicy": "post_use"
  }'
```

`rotationPolicy` accepte `manual`, `post_use` ou `scheduled` (doc 06 §3). Une rotation manuelle immédiate se déclenche via :

```sh
curl -X POST https://bastion.example.com/api/v1/vault/accounts/{accountId}/rotate \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Rappel** : l'API ne renvoie jamais le secret lui-même, à aucun moment, pour aucun rôle — cohérent avec ADR-0003. Un administrateur configure des comptes, il n'en consulte jamais les mots de passe.

## 5. Gestion des politiques RBAC

Une politique lie un rôle à un motif de ressource (doc 06 §3). Exemple : autoriser le rôle `dba` à ouvrir des sessions sur les comptes préfixés `prod-db-` :

```sh
curl -X POST https://bastion.example.com/api/v1/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dba-prod-db-access",
    "role": "dba",
    "resourcePattern": "vault:account:prod-db-*",
    "effect": "allow"
  }'
```

Le comportement est **deny-by-default** (Guide Sécurité §5) : un rôle sans politique associée n'ouvre l'accès à rien. Il n'existe pas de politique implicite « administrateur = accès total » — elle doit être créée explicitement si souhaitée.

## 6. Fédération d'identité

**Périmètre MVP — OIDC uniquement.** La connexion à un fournisseur OIDC se configure via `oidc.issuerUrl`, `oidc.clientId` et `oidc.clientSecretRef` (§2). Le mapping des claims vers `username`/`displayName` suit la convention standard OIDC (`preferred_username`, `name`) — personnalisable via `oidc.claimsMapping` si votre IdP diverge.

*v1.0* — LDAP, Active Directory, Entra ID, SAML et SCIM seront configurables via des sections dédiées de `values.yaml`, chacune correspondant à son connecteur (doc 00 §4.7). Ce document sera mis à jour à leur livraison.

## 7. Supervision et audit courant

- **Dashboards** : Grafana préconfiguré (doc 00 §10) expose l'activité par service, le taux d'échec d'authentification, le nombre de sessions actives.
- **Consultation de l'audit** :

```sh
curl "https://bastion.example.com/api/v1/audit/events?actor=jdupont&dateFrom=2026-08-01T00:00:00Z" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

- **Terminer une session active** en cas de doute :

```sh
curl -X DELETE https://bastion.example.com/api/v1/sessions/{sessionId} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Cette terminaison génère elle-même un événement d'audit (`action = "session.terminate"`, `actor` = l'administrateur qui a agi) — un arrêt forcé n'est jamais silencieux.

## 8. Sauvegardes

| Donnée | Où | Fréquence recommandée |
|---|---|---|
| PostgreSQL (comptes, politiques, sessions, audit) | Snapshot + WAL continu | Continu |
| MinIO (enregistrements, *v1.0*) | Réplication de bucket | Continu |
| Clé KMS/HSM | **Jamais dans la même sauvegarde que les données chiffrées** | Selon la politique du KMS externe |

La procédure complète de bascule en cas de sinistre, y compris la question de savoir si un site sauvegardé doit être traité comme potentiellement compromis, est couverte par `OpenBastion_Guide_PRA_PCA.md` (§4) — ce document ne couvre que la sauvegarde courante, pas la reprise.

## 9. Mise à jour de la plateforme

- Les contrats REST (`/api/v1`) et gRPC (`proto/`) évoluent de façon additive uniquement (doc 07 §1) — une mise à jour mineure n'exige jamais de migration cliente.
- Procéder par `helm upgrade`, service par service si un déploiement fin est souhaité (les charts sont indépendants, doc 02 §6).
- Toujours mettre à jour PostgreSQL (migrations de schéma) avant les services applicatifs qui en dépendent, jamais l'inverse.

## 10. Dépannage courant

| Symptôme | Cause probable | Action |
|---|---|---|
| Session en `pending_approval` | Normal pour une demande `breakGlass` : elle attend une seconde personne (ADR-0011). Une session **ordinaire** n'est jamais en attente | Faire approuver (`POST /sessions/<id>/approve`) par un utilisateur autre que le demandeur, porteur d'une politique `breakglass-approve:account:<id>`, avant l'échéance |
| `approve` renvoie `403` « cannot be approved by the person who made it » | Le demandeur essaie d'approuver sa propre demande | Une autre personne doit approuver |
| `approve` renvoie `403` « no approval policy allows this » | L'approbateur n'a pas de politique sur `breakglass-approve:account:<id>` (la politique `breakglass:…` des demandeurs ne suffit pas) | Créer la politique pour le rôle de l'approbateur (voir « Qui approuve ») |
| `approve` renvoie `409` | La demande est déjà décidée, périmée (`expired`, délai `BREAKGLASS_APPROVAL_WINDOW_MINUTES`) ou n'est pas une demande break-glass | Relire la demande (`GET /sessions/<id>`) ; en cas de péremption, le demandeur en refait une |
| `approve` renvoie `503` | L'Authorization Service, l'audit ou la base ne répond pas : la décision n'est **pas** prise (fail-closed) | Rétablir la dépendance et renouveler ; la cause est dans le journal du Broker |
| `connect` renvoie `403` sur une session accordée | L'appelant n'est pas le demandeur de la session (l'approbateur, par exemple) | Le demandeur se connecte lui-même |
| `POST /sessions` renvoie `403` de façon inattendue | Politique manquante ou `resourcePattern` mal formé (§5) | Lister les politiques du rôle concerné via `GET /policies` |
| `POST /sessions/{id}/connect` renvoie `503` (« recording unavailable ») | Le Command Recorder n'est pas prêt : injoignable, ou base de données en lecture seule (basculement de réplica, disque plein). La session n'a pas été établie et aucun secret n'a été consommé | Sonder `GET /readyz` du recorder, rétablir la base, puis renouveler la même requête ; l'événement `session.recording_unavailable` figure dans l'audit |
| Une session s'arrête en cours de route avec le message « session ended because recording is unavailable » | Le recorder a cessé d'acquitter : la commande en cours n'a **pas** été envoyée à la cible (ADR-0008) | Rechercher `session.recording_lost` dans l'audit pour la session concernée ; rétablir le recorder ; l'opérateur ouvre une nouvelle session |
| `POST /sessions` avec `breakGlass: true` renvoie `403` | L'une des conditions n'est pas remplie ; le corps de la réponse dit laquelle : désactivé (`BREAKGLASS_MAX_MINUTES` absent ou à 0), justification trop courte, durée hors limite, ou aucune politique sur `breakglass:account:<id>` | Corriger la demande, ou créer la politique si l'accès d'urgence est légitime — ne pas la généraliser. La tentative figure dans l'audit (`session.breakglass_requested`, échec) |
| Une session break-glass est accordée mais `connect` renvoie `503` (« recording unavailable ») | Le proxy n'a pas `BREAKGLASS_ENABLED=true`, ou tourne en `best-effort` (donc ignore la dérogation) | Activer `BREAKGLASS_ENABLED` sur ce proxy ; ne pas passer en `best-effort` |
| Une session ordinaire s'arrête avec « session ended because its time limit was reached » | Fin normale : le proxy coupe toute session à son échéance (`session.expire`) | Redemander une session si le besoin persiste |
| Un proxy ne démarre pas : « refusing to start » | `RECORDING_POLICY=required` (défaut) sans `RECORDER_URL` | Renseigner `RECORDER_URL` — ne pas passer en `best-effort` pour contourner |
| Un service ne démarre pas : « INTERNAL_TLS is "required" … TLS_CERT_FILE, … not set — refusing to start » | Le mTLS interne est le défaut ; il manque le certificat, la clé ou la CA | Fournir les trois fichiers (guide §3, « Identité des services »). `INTERNAL_TLS=disabled` n'est pas un remède : il supprime l'authentification entre services |
| Un service ne démarre pas : « holds the certificate of "X", not of "Y" » ou « expired at » | Mauvais fichiers montés dans ce service, ou certificat périmé | Monter le certificat **de ce service**, renouvelé |
| `remote error: tls: bad certificate`, ou `tls: failed to verify certificate` entre deux services | Un des deux n'a pas la bonne autorité dans `TLS_CA_FILE`, ou un certificat est expiré, ou l'adresse composée n'est pas dans les noms du certificat | Comparer les `TLS_CA_FILE` ; `openssl x509 -in cert.pem -noout -dates -ext subjectAltName` ; réémettre avec `-dns`/`-ip` corrects |
| `403` avec le corps `forbidden` sur un appel interne ; le journal du service appelé dit `mtls: refused POST /… from "X" — not an allowed caller` | Le service X n'est pas autorisé à appeler cette route (table `internal/interfaces/callers.go` du service appelé) | Cela signale en général une mauvaise configuration d'URL (un service pointé vers le mauvais pair) ou un appel inattendu ; ne pas chercher à élargir la table avant d'avoir compris pourquoi X appelle cette route |
| `mtls: <adresse> answered as "X", expected "Y"` | Une URL de service (`VAULT_URL`…) mène à un autre service que prévu | Corriger l'URL. Si ce n'est pas une erreur de configuration, c'est un service qui se fait passer pour un autre : à traiter comme un incident |
| `mtls: NOT reloading … keeping the current one` | Un renouvellement a déposé des fichiers invalides ; le service garde l'ancien certificat | Corriger les fichiers avant l'échéance de l'ancien ; le message dit pourquoi |
| `mtls: the certificate of … EXPIRED` | Le certificat n'a pas été renouvelé à temps ; les pairs refusent ce service | Renouveler immédiatement (la reprise est automatique) ; revoir l'alerte d'échéance |
| Rotation d'un compte reste indéfiniment en cours | KMS/HSM externe indisponible (Guide Sécurité §6) | Vérifier la connectivité du Password Vault vers le KMS configuré en `values.yaml` |

## 11. Prochaine étape

Le **guide utilisateur** s'adresse à l'opérateur final — celui qui demande et utilise une session — sans les concepts d'administration de ce document.

---
*Document suivant : `OpenBastion_Guide_Utilisateur.md`*
