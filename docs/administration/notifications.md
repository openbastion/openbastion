# Notifications

OpenBastion pousse deux sortes de messages vers l'extérieur, chacun par un webhook `POST` JSON que vous déclarez : les étapes d'une demande break-glass (Session Broker, ADR-0012 et ADR-0013) et les **alertes** écrites à l'audit (Audit Service, ADR-0045). Les deux utilisent la même signature, et leur URL n'est jamais écrite dans un journal. Une notification est un rappel, pas le registre : ce qui fait foi est la chaîne d'audit.

## Slack et Teams

Chaque canal a un format (ADR-0074) : `ALERT_NOTIFY_FORMAT` pour les alertes, `BREAKGLASS_NOTIFY_FORMAT` pour les demandes d'accès et de break-glass.

| Valeur | Corps envoyé | Pour |
|---|---|---|
| `generic` (défaut) | Le JSON décrit plus bas | Un récepteur à vous, qui peut vérifier la signature |
| `slack` | `{"text": "<phrase>"}` | Un webhook entrant Slack, ou un récepteur compatible |
| `teams` | La phrase dans une carte adaptative, sans bouton ni action | Un flux Teams **Workflows**, « Post to a channel when a webhook request is received » |

Une autre valeur, ou un format sans URL : le service refuse de démarrer.

- **Teams.** Microsoft indique avoir retiré ses connecteurs Office 365 en mai 2026. Créez un flux Workflows : une ancienne URL de connecteur ne fonctionne plus.
- **Seule la phrase part.** Elle n'est faite que de textes fixes, de nombres et d'identifiants filtrés : une mention ou un lien fabriqués n'y survivent pas. Ni justification, ni rien de la cible. Identifiants de compte et de demandeur, et ticket, partent bien chez Slack ou Microsoft : c'est votre décision en déclarant le canal.
- **Slack et Teams ne vérifient pas la signature.** Pour eux, seule l'URL fait foi : qui la détient peut écrire un faux message dans le canal. Il ne peut rien décider : approuver passe toujours par l'API authentifiée. Traitez l'URL en secret, et remplacez-la si elle fuit.
- **Un canal par service.** Pas de routage par équipe. La livraison ne change pas avec le format : le Broker n'essaie qu'une fois, sans jamais retarder une session.

**Essayer un vrai canal**, sans écrire l'URL dans l'historique du shell :

```sh
read -rs NOTIFY_INTEROP_SLACK_URL; export NOTIFY_INTEROP_SLACK_URL   # ou NOTIFY_INTEROP_TEAMS_URL
go test ./pkg/webhook/ -run TestRealChannel -v -count=1
```

Le message de test s'affiche dans le canal : regardez-le, le test ne prouve que le `2xx`.

## Alertes (Audit Service)

Une alerte est un événement d'audit, poussé **après** avoir été écrit dans la chaîne, et seulement si le service qui l'écrit est celui qui a le droit de la dire. L'émetteur est lu dans son certificat mTLS (ADR-0027), jamais dans la requête.

| Action poussée | Écrite par | Ce qu'elle dit |
|---|---|---|
| `vault.rotation_overdue` | `password-vault` | La rotation planifiée d'un compte échoue depuis `ROTATION_ALERT_AFTER_FAILURES` tentatives de suite : son secret vieillit contre sa politique (ADR-0041). Elle se répète tous les N échecs tant que la rotation échoue. |

Le même `vault.rotation_overdue` écrit par un autre service (Broker, proxy, Recorder) est enregistré dans la chaîne comme toute écriture, et **n'est pas poussé** : un service compromis ne peut ni vous réveiller pour rien, ni noyer une vraie alerte. Ajouter une alerte est un changement de l'Audit Service, pas un réglage.

### Configuration

| Variable | Rôle |
|---|---|
| `ALERT_NOTIFY_URL` | URL du récepteur : `https`, ou `http` vers une adresse de bouclage (développement). C'est un **secret** (Slack et Teams mettent le leur dans le chemin) : il n'est jamais écrit ; le journal n'en dit que le schéma et l'hôte. Une URL avec identifiants (`user:pass@`), sans hôte ou d'un autre schéma arrête le service. |
| `ALERT_NOTIFY_SECRET` | Clé de signature, **obligatoire avec l'URL**, 32 octets au moins (`openssl rand -hex 32`). Utilisée telle quelle : un saut de ligne final en fait partie. |
| `ALERT_NOTIFY_FORMAT` | `generic` (défaut), `slack` ou `teams` (ADR-0074, ci-dessus). |
| `ALERT_NOTIFY_RETRY_SECONDS` | Attente avant le premier renvoi, de 1 à 600 (30 par défaut) ; elle double à chaque renvoi. |

L'une sans l'autre, une valeur hors bornes ou un secret trop court : l'Audit Service refuse de démarrer, avec un message qui ne répète ni l'URL ni le secret. Sans aucune des trois, il démarre et l'annonce : « no alert channel ». Au démarrage, il dit ce qu'il pousse, vers quel hôte, et combien de fois il essaie.

**Sans TLS interne** (`INTERNAL_TLS=disabled`, développement seulement), aucun émetteur n'est nommé : une alerte est poussée quel que soit le service qui l'écrit, et le journal le dit au démarrage.

### Le message

```json
{
  "event": "vault.rotation_overdue",
  "eventId": "evt_1761901200000000000_42",
  "emitter": "password-vault",
  "resourceType": "account",
  "resourceId": "acc_db",
  "success": false,
  "at": "2026-10-31T09:00:00.000123Z",
  "text": "OpenBastion alert: the scheduled rotation of account acc_db keeps failing; its secret is older than its rotation policy (audit event evt_1761901200000000000_42)."
}
```

Rien d'autre que ce que la chaîne contient déjà : pas d'acteur (une alerte est une action du système), rien de la cible. `text` est lu par les webhooks entrants de type Slack ; les identifiants y sont filtrés (lettres, chiffres, `. _ : -`, 64 caractères au plus) pour qu'un nom de compte ne devienne ni une mention, ni un lien, ni un saut de ligne. Les champs, eux, portent la valeur exacte.

### Renvois

| Réponse du récepteur | Ce que fait l'Audit Service |
|---|---|
| `2xx` | Livré. |
| Erreur de transport (refus de connexion, délai de 5 s dépassé), `408`, `429`, `5xx` | Renvoie, jusqu'à **5 tentatives** en tout, après 30 s, 60 s, 120 s, 240 s (avec la valeur par défaut). |
| Tout autre statut (`4xx`, redirection) | Abandon immédiat. Une redirection n'est jamais suivie. |

Chaque échec et chaque abandon sont une ligne du journal, avec l'identifiant de l'événement. Au plus **256 alertes** sont en cours (en file ou en attente d'un renvoi) ; au-delà, une alerte n'est pas poussée, et le journal le dit. L'écriture dans la chaîne n'attend jamais le canal.

**Où attendent les alertes** (ADR-0057) : avec `DATABASE_URL`, dans la table `alert_outbox` — une alerte en attente d'un renvoi survit à un redémarrage de l'Audit Service, et le suivant la livre à l'heure prévue, à la tentative atteinte ; le journal du démarrage le dit (« kept in alert_outbox »). Sans base, en mémoire : elle est perdue à l'arrêt ; elle reste dans la chaîne, et le Vault la réécrit `ROTATION_ALERT_AFTER_FAILURES` échecs plus tard. Dans les deux cas, une alerte n'est gardée qu'une fois par événement, et elle est gardée **après** l'écriture de l'événement : un arrêt entre les deux perd la poussée, pas l'événement. Un renvoi porte le même corps : écartez les doublons par `eventId`.

## Break-glass (Session Broker)

`BREAKGLASS_NOTIFY_URL` et `BREAKGLASS_NOTIFY_SECRET` (optionnel pour le break-glass), le message et ses limites sont décrits dans [`approval-workflows.md`](approval-workflows.md). Pas de renvoi : la demande reste visible par `GET /sessions?status=pending_approval`.

## Vérifier la signature côté récepteur

Les deux canaux envoient `X-OpenBastion-Timestamp` (secondes Unix, à l'envoi) et `X-OpenBastion-Signature: v1=<hex>`, où `<hex>` est `HMAC-SHA256(secret, timestamp + "." + corps exact)`. Le récepteur :

1. recalcule la signature sur les **octets reçus**, avant tout décodage JSON ;
2. la compare en temps constant ;
3. refuse un horodatage trop loin de sa propre horloge (quelques minutes) ;
4. écarte un `eventId` (alerte) déjà traité.

```python
import hashlib, hmac, time
def verify(secret: bytes, headers, body: bytes, tolerance=300) -> bool:
    ts = headers["X-OpenBastion-Timestamp"]
    want = "v1=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers["X-OpenBastion-Signature"]) and abs(time.time() - int(ts)) <= tolerance
```

La signature prouve l'origine et l'intégrité, et l'horodatage la fraîcheur. Elle ne chiffre rien : le contenu n'est pas secret, mais l'URL l'est.
