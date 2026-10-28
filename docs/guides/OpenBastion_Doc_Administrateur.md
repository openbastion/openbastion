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
| Session Broker | `BREAKGLASS_NOTIFY_URL` | URL d'un webhook (Slack, Teams, Mattermost, récepteur générique) prévenu quand une demande break-glass est déposée, approuvée ou rejetée (ADR-0012). Absente : aucune notification, les approbateurs consultent la liste. **https exigé** (http seulement vers une adresse de boucle locale) ; une URL avec identifiants, sans hôte, d'un autre schéma ou illisible est une erreur fatale au démarrage, dont le message ne la répète pas. **L'URL est un secret** (celles de Slack et de Teams en contiennent un) : traitez-la comme tel dans vos manifestes — Secret Kubernetes, pas ConfigMap. Le Broker ne journalise que son schéma et son hôte. |
| Session Broker | `BREAKGLASS_MAX_PENDING_PER_REQUESTER` | Nombre maximal de demandes break-glass qu'**un même demandeur** peut avoir en attente, de 1 à 100 (défaut **3**) ; au-delà, `429`. Il n'existe pas de valeur « illimité » ; un texte, `0`, un négatif ou plus de 100 est une erreur fatale au démarrage. Ne s'applique qu'avec `BREAKGLASS_APPROVAL=required` (sans approbation, rien n'attend). Une place se libère quand une demande est décidée ou échue (ADR-0013). |
| Session Broker | `BREAKGLASS_NOTIFY_SECRET` | Secret qui signe le webhook : 32 octets au moins, utilisé tel quel, sans suppression d'espaces (`openssl rand -hex 32`). Fixé, chaque envoi porte `X-OpenBastion-Timestamp` et `X-OpenBastion-Signature`. Fixé sans `BREAKGLASS_NOTIFY_URL`, ou trop court : erreur fatale au démarrage. Jamais journalisé, jamais répété dans une erreur (ADR-0013). |

**Plafond et signature (ADR-0013).** Un demandeur ne peut pas avoir plus de `BREAKGLASS_MAX_PENDING_PER_REQUESTER` demandes en attente (3 par défaut). Le plafond est **par demandeur** : celui d'une personne n'ôte rien à une autre. Une demande refusée pour cette raison est un `429`, laisse un événement `session.breakglass_requested` avec `success=false`, ne prévient pas le canal et n'apparaît pas dans la liste. Un demandeur au plafond ne peut plus rien demander tant qu'une de ses demandes n'est pas décidée ou échue (15 minutes par défaut) : c'est le prix de la protection, et c'est pourquoi on ne le règle pas à 1 sans y penser.

Quand `BREAKGLASS_NOTIFY_SECRET` est fixé, le récepteur du webhook peut **vérifier** ce qu'il reçoit. La signature est `HMAC-SHA256(secret, timestamp + "." + corps exact)`, écrite `v1=<hex>` ; il faut la calculer sur les octets reçus, pas sur du JSON ré-encodé :

```python
import hashlib, hmac, time

def verify(secret: bytes, ts: str, sig: str, body: bytes, tolerance: int = 300) -> bool:
    try:
        if abs(time.time() - int(ts)) > tolerance:   # horodatage (X-OpenBastion-Timestamp) hors tolérance
            return False
    except ValueError:
        return False
    want = "v1=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)            # sig = X-OpenBastion-Signature
```

Cela prouve l'origine, l'intégrité et la fraîcheur du message. Cela **ne** protège **pas** contre un rejeu à l'intérieur de la tolérance, ne chiffre rien, et Slack, Teams ou Mattermost ignorent ces en-têtes : avec eux, l'URL reste le seul secret.

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

La réponse est `201` avec `"status": "pending_approval"` : **ce n'est pas encore une session**, `connect` répond `409`. L'approbateur n'a pas besoin qu'on lui transmette l'identifiant : il liste ce qu'il peut décider (ADR-0012) et, si `BREAKGLASS_NOTIFY_URL` est fixée, le canal l'a prévenu :

```sh
curl "https://bastion.example.com/api/v1/sessions?status=pending_approval" -H "Authorization: Bearer $APPROVER_TOKEN"
# {"items":[{"id":"…","status":"pending_approval","requestedBy":"…","privilegedAccountId":"…","justification":"…","breakGlass":true,"expiresAt":"…"}],"page":1,"pageSize":20,"totalItems":1}
```

La liste ne montre **que ce que l'appelant peut approuver maintenant** : pas ses propres demandes, pas les comptes que sa politique `breakglass-approve:` ne couvre pas. Elle est **vide**, jamais en erreur, pour qui n'a aucune autorité : un utilisateur ne peut pas s'en servir pour apprendre quels comptes sont sensibles. Les demandes les plus proches de leur échéance viennent d'abord ; au-delà de 100 demandes en attente la réponse porte `"truncated": true`. Seul `status=pending_approval` est servi (autre chose : `400`). Une dépendance qui ne répond pas donne `503`, jamais une liste partielle : si vous obtenez `503`, ne concluez pas qu'il n'y a rien à décider. L'approbateur relit alors la demande puis décide :

```sh
curl https://bastion.example.com/api/v1/sessions/<id> -H "Authorization: Bearer $APPROVER_TOKEN"   # qui, quel compte, pourquoi, échéance
curl -X POST https://bastion.example.com/api/v1/sessions/<id>/approve -H "Authorization: Bearer $APPROVER_TOKEN"
curl -X POST https://bastion.example.com/api/v1/sessions/<id>/reject  -H "Authorization: Bearer $APPROVER_TOKEN"
```

Après `approve`, la session est `active` et la durée demandée court **à partir de l'approbation**. **Seul le demandeur** peut ouvrir la session (`connect`) : l'approbateur reçoit `403`.

À relire après chaque usage : `session.breakglass_requested` (demande mise en attente, accordée ou refusée), `session.breakglass_approved` / `session.breakglass_rejected` (**qui** a décidé ; un `success=false` est un refus — auto-approbation, politique absente — à relire aussi), `session.breakglass` (la dérogation a **réellement** servi : le recorder n'était pas prêt) et `session.expire` (fin de session à l'échéance). Une session demandée en break-glass alors que le recorder était prêt reste enregistrée normalement et ne laisse pas de `session.breakglass`.

**La notification est une courtoisie, pas un contrôle.** Elle part après coup, en arrière-plan, sans nouvelle tentative (5 s, 16 envois simultanés au plus) : un canal en panne, lent ou hostile ne retarde ni ne bloque aucune demande ni aucune décision, il laisse une ligne dans le journal du Broker (`notification … not delivered`). La liste est le filet. Le message nomme la session, le compte, le demandeur, la durée et l'échéance ; il **ne contient ni la justification ni rien de la cible** — le détail s'obtient en s'authentifiant, par la liste. Au démarrage le Broker dit où il notifie, ou qu'il n'a « no notification channel ». Le message n'est pas signé ; l'URL est le seul secret que le destinataire ait pour croire qu'il vient du Broker.

Ce que la double validation ne fait **pas** : elle ne détecte pas deux comptes tenus par la même personne, ne remplace pas la revue après l'incident (non implémentée), n'a qu'un approbateur (pas de quorum), et n'audite pas l'expiration d'une demande non décidée (le statut se lit `expired`).

### Limitation de débit du Gateway (ADR-0014, ADR-0016)

Le Gateway applique quatre limites, de natures différentes. **Aucune n'a de valeur « illimité ».**

| Quoi | Clé | Réglage | Comportement |
|---|---|---|---|
| `POST /sessions` | l'**utilisateur** vérifié (jamais l'adresse, jamais le corps) | `SESSION_REQUEST_BURST` : rafale, de 1 à 1000 (défaut **10**) ; `SESSION_REQUEST_RATE_PER_MINUTE` : débit soutenu, de 1 à 600 (défaut **6**) | Chaque tentative coûte un jeton, acceptée ou non, avant la lecture du corps. Une demande refusée ici **n'atteint pas le Broker** : ni ligne `sessions`, ni événement d'audit. |
| `approve`, `reject`, `connect` (ADR-0016) et `DELETE /sessions/{id}` (ADR-0017) | l'**utilisateur** vérifié (jamais l'adresse, jamais le corps) — **un seul seau pour les quatre routes**, distinct de celui de `POST /sessions` | `SESSION_ACTION_BURST` : rafale, de 1 à 1000 (défaut **10**) ; `SESSION_ACTION_RATE_PER_MINUTE` : débit soutenu, de 1 à 600 (défaut **6**) | Chaque appel de l'une des quatre coûte un jeton **avant** que le Broker soit appelé. Ce sont les routes qui **écrivent à chaque appel** : un refus d'approbation, de rejet ou de terminaison écrit un événement d'audit, un `connect` crée un scope du Vault, un ticket du proxy et un événement d'audit. Une action refusée ici n'atteint ni le Broker, ni le Vault, ni le proxy, et n'écrit rien. Une méthode non permise (`405`) et la lecture d'une session (`GET`) ne coûtent rien. |
| Requêtes authentifiées | l'**adresse du client** (voir plus bas) | `CLIENT_REQUEST_BURST` : rafale, de 1 à 10000 (défaut **60**) ; `CLIENT_REQUEST_RATE_PER_MINUTE` : de 1 à 6000 (défaut **60**) | Comptée avant même que le jeton soit regardé. Les défauts sont ce que le Gateway faisait déjà. |
| `/auth/login` | l'**adresse du client** (voir plus bas) | `CLIENT_LOGIN_BURST` : rafale, de 1 à 100 (défaut **5**) ; `CLIENT_LOGIN_RATE_PER_MINUTE` : de 1 à 60 (défaut **1**) | Protection contre la force brute ; volontairement stricte. Les défauts sont ce que le Gateway faisait déjà : rien n'est relâché tant que vous ne le demandez pas **par son nom**. |

Une valeur invalide de l'une de ces huit variables (texte, `0`, négatif, hors bornes) est une erreur fatale au démarrage qui **nomme la variable**. Au démarrage, le Gateway écrit ce qu'il applique réellement, une ligne par budget (« POST /sessions: at most 10 at once per user, then 6 per minute … » et « approve, reject, connect, terminate: at most 10 at once per user, then 6 per minute, one budget for the four … ») : ce sont les lignes à relire après un changement de configuration. Les deux budgets par utilisateur se règlent **séparément** : relever `SESSION_REQUEST_BURST` ne change rien au budget d'actions, et inversement.

Les quatre limites répondent `429` avec un `Retry-After` **vrai** : le nombre de secondes (arrondi au-dessus, au moins 1) qui manque pour qu'un jeton se reforme. Le message de la limite de `POST /sessions` — « too many session requests from this user … retry in N s » — et celui du budget d'actions — « too many session actions from this user … retry in N s » — sont distincts l'un de l'autre, et de celui du plafond de demandes break-glass en attente du Broker (ADR-0013, « too many break-glass requests are waiting … ») : les deux premiers se résolvent en attendant quelques secondes, le troisième en faisant décider une demande.

**Où lire un refus.** Le Gateway écrit **une** ligne de journal par utilisateur et par épisode de refus (« the session requests of user "…" are refused: more than 10 at once, then one every 10s » ; « the session actions of user "…" are refused: … » pour le budget d'actions), jamais une par requête refusée, et jamais le jeton. Rien dans l'audit : le Gateway n'en est pas un émetteur autorisé (ADR-0010) et un événement par refus recréerait le flux d'écritures que la limite borne. Pour savoir **qui** sature son budget, cherchez cette ligne.

**Ce qui reste faux, et que vous devez savoir.**

- **Par processus.** Le seau vit dans la mémoire du Gateway : *N* réplicas accordent *N* fois le budget.
- **Seuls `POST /sessions`, `approve`, `reject`, `connect` et `DELETE /sessions/{id}` sont limités par identité.** Les lectures — `GET /sessions/{id}`, l'enregistrement, la liste des demandes en attente — ne dépendent que de la limite par adresse ; la liste peut coûter à l'Authorization Service un appel par compte distinct en attente.
- **Terminer une session coupe ce qui est déjà ouvert (ADR-0018), mais pas tout, et pas partout.** `DELETE` fait d'abord révoquer la session au SSH Proxy — connexions ouvertes fermées, tickets non consommés jetés, rien d'établi ensuite — puis change l'état dans le Broker. Ce que la révocation **ne** fait **pas** : elle ne révoque pas les octrois de portée du Vault (le jeton est à usage unique, réservé à l'identité du proxy, et abandonné avec le ticket), et elle n'atteint qu'**une** instance du proxy — ne déployez pas plusieurs réplicas du proxy SSH tant que le registre des proxys n'existe pas (voir le guide HA). Si le proxy ne répond pas, `DELETE` renvoie `503` et **la session reste active** : voyez « Terminer une session » plus bas.
- **Terminer en masse est ralenti.** Un responsable qui doit terminer vingt sessions d'un coup épuise son budget d'actions (rafale 10 par défaut, puis 6 par minute) : relevez `SESSION_ACTION_BURST` pour la durée de l'incident, par son nom, ou terminez par lots.
- **`GET /sessions/{id}` reste ouvert à tout utilisateur authentifié** : il montre le demandeur, le compte et la justification d'une session à qui en connaît l'identifiant. Ce n'est pas corrigé par ADR-0017 (qui protège l'écriture, pas la lecture).
- **Le budget d'actions est celui de l'utilisateur, pas celui d'une session** : un script qui décide ou se connecte à vingt sessions d'un coup est ralenti. Les valeurs par défaut sont choisies, non mesurées sur un usage réel : relevez-les par leur nom si un usage légitime les dépasse.
- **En urgence, un jeton volé pèse plus.** Qui détient le jeton d'un approbateur ou d'un demandeur peut épuiser son budget d'actions pendant l'incident ; le remède est de révoquer le jeton.
- **La limite par adresse est celle de l'adresse que le Gateway sait lire.** Tant que `TRUSTED_PROXY_CIDRS` n'est pas réglé, c'est celle du pair TCP — **celle de Traefik pour tout le monde** : un seul seau pour toute la plateforme, et une rafale de login qu'un seul utilisateur peut épuiser pour tous. Voir la sous-section suivante.
- **Un jeton volé peut priver son titulaire de son budget** (un jeton se reforme toutes les 10 secondes avec les défauts ; il va à qui arrive le premier). Le remède est de **révoquer le jeton**, pas de relever la limite.
- **K identités compromises, K budgets.**
- Les limites du login et des requêtes authentifiées n'étaient pas ce que le code annonçait (le login faisait déjà « 5 puis une par minute », pas « 5 par minute » ; les requêtes authentifiées se vidaient en 60 puis une par minute). Le login **n'a pas été relâché** ; les requêtes authentifiées font désormais réellement 60 par minute.

### Derrière Traefik : déclarer le proxy (ADR-0015)

Les limites **par adresse** (login et requêtes authentifiées) ont besoin de l'adresse du **vrai client**. Le listener du Gateway est en HTTP derrière Traefik : sans réglage, l'adresse du pair est celle de Traefik, la même pour tous, et tous les utilisateurs partagent un seau.

| Variable | Effet |
|---|---|
| `TRUSTED_PROXY_CIDRS` | Adresses ou réseaux CIDR (séparés par des virgules) des proxys inverses qui précèdent le Gateway, par exemple `10.42.0.0/16` ou `172.18.0.5, 172.18.0.6`. **Absente : personne n'est de confiance** et l'adresse du client est celle du pair (le comportement d'avant). |

**Ce que fait le Gateway.** L'en-tête `X-Forwarded-For` n'est lu que si le **pair TCP immédiat** est dans cette liste ; venant de tout autre pair, il est ignoré. Il est lu **de droite à gauche** : une adresse de la liste est un proxy de plus à franchir, et la **première adresse qui n'y est pas est le client**. Ce que le client a écrit à gauche n'est jamais lu tant que l'adresse ajoutée par votre proxy est à sa droite. Au moindre doute (en-tête absent d'un proxy, élément illisible, plus de 32 sauts, tout est proxy), la clé est l'adresse du pair — jamais une valeur choisie par le client. Une adresse IPv4 écrite en IPv6 est ramenée à l'IPv4, une adresse IPv6 à son **/64** (un abonné en possède 2⁶⁴) ; le port et la zone sont retirés.

**Une valeur douteuse empêche le Gateway de démarrer**, en nommant la variable et l'entrée : entrée vide (`a,,b`), ni adresse ni CIDR, bits d'hôte non nuls (`192.168.1.5/24` : écrivez `192.168.1.0/24` ou l'adresse seule), et tout réseau de longueur 0 (`0.0.0.0/0`, `::/0` : faire confiance à tout pair revient à laisser chacun choisir sa clé). Il n'existe pas de valeur « tout le monde ». Au démarrage, le Gateway écrit ce qu'il fait : « client address: X-Forwarded-For is believed only from … » ou « the address of the peer (TRUSTED_PROXY_CIDRS is not set) ». **Relisez cette ligne après chaque changement.**

**Ce que vous devez faire de votre côté.**

1. **Déclarer l'adresse de Traefik** telle que **le Gateway la voit** (l'adresse source de la connexion : adresse du pod ou du conteneur de Traefik, ou réseau qui les contient). Ce n'est pas l'adresse publique. Prenez le réseau **le plus étroit** qui convient : un réseau trop large (tout un VPC) laisse n'importe quel hôte qu'il contient choisir sa clé.
2. **Faire en sorte que Traefik n'ajoute que ce qu'il a vu.** Le proxy doit **ajouter l'adresse dont il a reçu la connexion** à `X-Forwarded-For`, comme font les proxys usuels, et ne pas croire les `X-Forwarded-*` d'un client qui n'est pas de confiance (réglage `forwardedHeaders` de l'entrypoint Traefik : voir la documentation de **votre** version). Un proxy qui transmet l'en-tête du client sans rien ajouter rend la valeur forgeable à travers lui. **Ce réglage de Traefik n'a pas été essayé ici** : les tests tiennent le rôle du proxy.
3. **Vérifier.** Depuis une machine, envoyez à la suite plus de tentatives de login que la rafale (6 avec les défauts) avec à chaque fois un `X-Forwarded-For` différent (`curl -H 'X-Forwarded-For: 6.6.6.N' …`) : la **sixième doit être refusée** (`429`). Si elle ne l'est pas, le proxy n'ajoute pas l'adresse qu'il voit, ou la liste est trop large : **ne mettez pas en production**.
4. **Ne pas exposer le listener du Gateway autrement que par le proxy** : un client qui l'atteint directement n'est pas de confiance et son en-tête est ignoré, mais il n'a alors aucune raison d'y avoir accès.

**Ce qui reste faux.**

- **Une adresse n'est pas une personne.** Derrière un NAT d'entreprise ou d'opérateur, de nombreux utilisateurs partagent une adresse et un seau, même bien résolue ; à l'inverse, qui possède beaucoup d'adresses a beaucoup de seaux : la limite par adresse **ne borne pas une force brute distribuée**. Aucune limite par compte n'est ajoutée ici.
- **Le /64 IPv6 est un choix, non réglable** : les utilisateurs d'un même /64 (un réseau local) partagent un seau.
- **Par processus** : *N* réplicas, *N* fois le budget.
- **Les refus par adresse ne sont ni dans l'audit ni dans le journal du Gateway** (une ligne par refus serait une ligne par requête pour qui change d'adresse) ; ils sont dans le **journal d'accès de Traefik**, qui connaît l'adresse.

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
  -H "Authorization: Bearer $RESPONDER_TOKEN"
```

**Qui peut terminer une session (ADR-0017).** Deux catégories de personnes, et rien d'autre :

1. **Le demandeur** de la session, sans aucune politique : on peut toujours mettre fin à ce qu'on a ouvert.
2. **Quiconque détient une politique sur la ressource `session-terminate:account:<id du compte>`**. Elle est refusée par défaut, et son préfixe est distinct de `vault:`, `breakglass:` et `breakglass-approve:` : *pouvoir approuver une urgence, ou demander l'accès, n'est pas pouvoir terminer la session de quelqu'un d'autre*. Le rôle `platform-admin` ne l'accorde pas à lui seul : sans politique, un administrateur reçoit `403` comme tout le monde.

Pour donner ce pouvoir à une astreinte, sur un compte :

```sh
curl -X POST https://bastion.example.com/api/v1/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "oncall-can-end-prod-db-01-sessions", "role": "oncall",
       "resourcePattern": "session-terminate:account:<id-de-prod-db-01>", "effect": "allow"}'
```

Un `*` final est un préfixe : `session-terminate:account:*` couvre **tous** les comptes — réservez-le à un rôle d'urgence réellement transverse, et gardez à l'esprit que `*` seul, ou `session*`, couvrent aussi cette ressource. Un refus explicite (`effect: deny`) l'emporte toujours.

Ce que l'on voit dans l'audit : la terminaison (`session.terminate`) est écrite **sous le nom de celui qui l'a demandée** — pas du demandeur de la session ; un refus l'est aussi (échec), sous le nom de l'appelant refusé. Une session inconnue (`404`) ou qui n'est pas active (`409`) n'écrit rien. L'ordre des vérifications est : la session existe, l'appelant en a le droit, la session est active — un appelant sans droit reçoit donc le même `403` pour une session active ou terminée, et n'apprend rien de son état. Si l'Authorization Service ne répond pas, la réponse est `503` et **rien n'est terminé** (le demandeur, lui, n'a pas besoin du service pour mettre fin à sa propre session).

**Ce qui se passe quand on termine (ADR-0018).** Terminer, c'est couper : le Broker dit d'abord au SSH Proxy de révoquer la session, et ne la marque terminée qu'après sa confirmation.

- L'opérateur connecté lit « `openbastion: session ended because it was terminated.` » (sans savoir qui l'a décidé), et sa connexion se ferme. Un ticket de connexion pas encore utilisé ne sert plus ; un `connect` en cours au même instant ne laisse pas de ticket. La session ne peut plus être établie, jusqu'à l'heure où elle aurait expiré de toute façon.
- Dans l'audit : `session.terminate` du Broker (au nom de celui qui a terminé), puis, pour **chaque connexion coupée**, `session.revoked` et `session.terminate` du proxy (le credential est purgé). Un arrêt du proxy, lui, **n'est pas** une révocation et n'écrit pas `session.revoked`.
- **Si le proxy est injoignable** (ou ne confirme pas dans les 5 secondes) : `503`, **la session reste `active`**, et un événement `session.terminate` en **échec** est écrit sous le nom de l'appelant — la tentative est tracée. Renouvelez le même appel quand le proxy est revenu : il aboutit. Tant que ce n'est pas fait, la session est ouverte ; si c'est urgent, coupez la connexion au niveau réseau ou arrêtez le proxy, puis terminez.
- Une terminaison **refusée** (`403`), d'une session inconnue (`404`) ou qui n'est pas active (`409`) ne contacte pas le proxy.
- Le proxy se souvient de la révocation pendant le temps qu'il restait à la session (plus une minute, au plus 7 jours), **en mémoire** : s'il redémarre, il oublie — sans conséquence, puisque le Broker n'émet plus de ticket pour une session terminée.

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
| `GET /sessions?status=pending_approval` renvoie une liste vide alors qu'une demande attend | Normal pour qui n'a pas de politique `breakglass-approve:account:<id>` sur ce compte, pour l'auteur de la demande, ou si la demande est périmée ou la dérogation coupée : la liste ne montre que ce que **cet appelant** peut décider maintenant | Vérifier la politique de l'approbateur (voir « Qui approuve ») ; le demandeur relit sa propre demande par `GET /sessions/<id>` |
| `GET /sessions` renvoie `400` | `status` absent, ou autre que `pending_approval` : seul ce statut est servi | Ajouter `?status=pending_approval` |
| `GET /sessions?status=pending_approval` renvoie `503` | L'Authorization Service ou la base ne répond pas ; le Broker ne renvoie jamais de liste partielle | Rétablir la dépendance et renouveler ; la cause est dans le journal du Broker (« listing the pending requests failed ») |
| `POST /sessions` avec `breakGlass: true` renvoie `403` « … is not a valid account identifier » | L'identifiant de compte n'est pas de la forme `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` (ADR-0012) | Corriger l'identifiant ; un identifiant qui contiendrait une mention ou un lien n'a rien à faire dans le canal d'astreinte |
| Le journal du Broker dit « notification … not delivered » ou « refused » | Le webhook est injoignable, lent, ou répond autre chose que 2xx (une redirection compte comme un refus : elle n'est pas suivie) | Vérifier l'URL et le récepteur ; rien n'est perdu côté demande, la liste reste à jour |
| Le Broker s'arrête avec « BREAKGLASS_NOTIFY_URL cannot be used » | L'URL n'est pas https (hors boucle locale), porte des identifiants, n'a pas d'hôte ou est illisible. Le message ne la répète pas | Corriger la variable ; mieux vaut un démarrage refusé que des approbateurs qui croient être prévenus |
| Le Broker s'arrête avec « BREAKGLASS_NOTIFY_SECRET is set but BREAKGLASS_NOTIFY_URL is not » | Un secret de signature est fixé alors qu'il n'y a pas de canal : il n'y a rien à signer, et c'est probablement une variable oubliée | Fixer `BREAKGLASS_NOTIFY_URL`, ou retirer le secret |
| Le Broker s'arrête avec « BREAKGLASS_NOTIFY_SECRET cannot be used » | Le secret fait moins de 32 octets. Le message ne le répète pas | Générer un secret : `openssl rand -hex 32` ; le fixer des deux côtés |
| Le Broker s'arrête avec « BREAKGLASS_MAX_PENDING_PER_REQUESTER must be a number between 1 and 100 » | Valeur non numérique, `0`, négative ou supérieure à 100 : il n'existe pas de « illimité » | Corriger la variable |
| Le récepteur du webhook refuse la signature | Corps modifié ou ré-encodé par un intermédiaire (la signature porte sur les octets exacts), horloge décalée au-delà de la tolérance, secret différent des deux côtés | Vérifier sur le corps brut ; synchroniser l'horloge (NTP) ; comparer les secrets |
| `POST /sessions` avec `breakGlass: true` renvoie `429` « too many break-glass requests are waiting for a decision » | Le demandeur a déjà `BREAKGLASS_MAX_PENDING_PER_REQUESTER` demandes en attente ; la tentative est enregistrée `denied` et auditée (`success=false`) | Faire décider une de ses demandes, ou attendre qu'elle échoie (15 minutes par défaut) ; relever le plafond seulement si le besoin est réel |
| `POST /sessions` avec `breakGlass: true` renvoie `503` | Les demandes en attente du demandeur n'ont pas pu être comptées (base ou dépendance) : par défaut la demande n'est **pas** acceptée | Rétablir la dépendance et renouveler ; la cause est dans le journal du Broker (« a break-glass request was not accepted ») |
| `POST /sessions` renvoie `429` « too many session requests from this user … retry in N s » | L'utilisateur a épuisé son budget de demandes (`SESSION_REQUEST_BURST`, puis `SESSION_REQUEST_RATE_PER_MINUTE`) ; la requête n'est **pas** parvenue au Broker (aucune ligne, aucun événement d'audit) | Attendre le `Retry-After` ; si c'est un client qui boucle, le corriger ; si la ligne de journal du Gateway revient pour un utilisateur qui n'a pas dû agir, **révoquer son jeton** (ADR-0014) |
| `DELETE /sessions/{id}` renvoie `403` « only the requester of a session, or somebody with a policy to terminate on this account, can end it » | L'appelant n'est pas le demandeur et n'a pas de politique sur `session-terminate:account:<id>` — **y compris un `platform-admin`** : le rôle n'accorde rien tout seul. Le refus est dans l'audit (`session.terminate`, échec) sous son nom | Créer la politique pour le rôle du responsable (voir §7, « Qui peut terminer une session ») ; ne pas lui prêter `breakglass-approve:*`, qui n'est pas cette ressource |
| `DELETE /sessions/{id}` renvoie `409` | La session n'est pas active (déjà terminée, expirée, refusée ou en attente d'approbation), ou quelqu'un l'a terminée une seconde plus tôt. Rien n'est écrit | Relire la session (`GET /sessions/<id>`) ; rien à refaire |
| `DELETE /sessions/{id}` renvoie `503` | L'Authorization Service, la base **ou le SSH Proxy** ne répond pas (ou une connexion ne s'est pas fermée dans les 5 s) : **rien n'a été terminé**, la session reste active, et si c'est le proxy qui n'a pas confirmé, un `session.terminate` en échec est dans l'audit sous le nom de l'appelant | Rétablir la dépendance et renouveler ; la cause est dans le journal du Broker (« termination of … not made », « revoking at the proxy ») et, côté proxy, « revocation of session … still closing ». Le demandeur peut terminer sa propre session sans l'Authorization Service, **mais pas sans le proxy** |
| Un opérateur reste connecté après un `DELETE` `200` | Plusieurs instances du SSH Proxy : la révocation n'a atteint que celle que le Broker connaît (ADR-0018) | N'exécuter qu'**une** instance du proxy SSH ; arrêter les autres |
| `connect` renvoie `409` « session revoked … » après une terminaison | Normal : le proxy refuse d'établir une session que le Broker lui a fait révoquer | Ouvrir une nouvelle session |
| `connect`, `approve`, `reject` ou `DELETE /sessions/{id}` renvoie `429` « too many session actions from this user … retry in N s » | L'utilisateur a épuisé son budget d'actions (`SESSION_ACTION_BURST`, puis `SESSION_ACTION_RATE_PER_MINUTE`), **partagé** entre les quatre routes et toutes ses sessions ; l'action n'est **pas** parvenue au Broker (rien dans l'audit). Ce n'est pas le budget de `POST /sessions` : se connecter reste possible après avoir trop demandé | Attendre le `Retry-After` ; si c'est un client qui boucle, le corriger ; si la ligne « the session actions of user … are refused » revient pour un utilisateur qui n'a pas dû agir, **révoquer son jeton** (ADR-0016) |
| Le Gateway s'arrête avec « SESSION_ACTION_BURST must be a number between 1 and 1000 » (ou `SESSION_ACTION_RATE_PER_MINUTE … between 1 and 600`) | Valeur non numérique, `0`, négative ou hors bornes : il n'existe pas de « illimité » | Corriger la variable |
| Le Gateway s'arrête avec « SESSION_REQUEST_BURST must be a number between 1 and 1000 » (ou `SESSION_REQUEST_RATE_PER_MINUTE … between 1 and 600`) | Valeur non numérique, `0`, négative ou hors bornes : il n'existe pas de « illimité » | Corriger la variable |
| Tous les utilisateurs reçoivent `429` en même temps (login ou requêtes authentifiées) | Ils partagent un seau : `TRUSTED_PROXY_CIDRS` n'est pas réglé (le Gateway annonce « the address of the peer »), ou ne contient pas l'adresse que Traefik présente au Gateway, ou l'en-tête n'arrive pas | Régler `TRUSTED_PROXY_CIDRS` (sous-section ci-dessus) et relire la ligne d'annonce ; ne pas relâcher le login pour compenser |
| Le Gateway s'arrête avec « TRUSTED_PROXY_CIDRS cannot be used: … » | Une entrée est vide, illisible, a des bits d'hôte non nuls, ou est un réseau de longueur 0 (« trusts every address ») ; le message nomme l'entrée | Corriger la variable ; il n'existe pas de valeur « tout le monde » |
| Le Gateway s'arrête avec « CLIENT_LOGIN_BURST must be a number between 1 and 100 » (ou `CLIENT_LOGIN_RATE_PER_MINUTE … 1 and 60`, `CLIENT_REQUEST_BURST … 1 and 10000`, `CLIENT_REQUEST_RATE_PER_MINUTE … 1 and 6000`) | Valeur non numérique, `0`, négative ou hors bornes : il n'existe pas de « illimité » | Corriger la variable |
| Les tentatives de login avec un `X-Forwarded-For` différent à chaque fois ne sont **pas** refusées après la rafale | Le proxy n'ajoute pas l'adresse qu'il voit, ou `TRUSTED_PROXY_CIDRS` est trop large (le client est « de confiance ») | Réduire le réseau déclaré ; régler Traefik pour qu'il ajoute le pair et ignore l'en-tête d'un client non fiable ; refaire la vérification |
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
