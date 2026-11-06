# Workflows d'approbation

## Approbation d'une session ordinaire (ADR-0067)

Un compte peut exiger une approbation indépendante avant qu'une session ordinaire s'ouvre. Le réglage appartient au compte : il se pose à sa création ou par `PUT /vault/accounts/{id}/approval` avec `{"approvalRequired":true|false}`. Seul un appelant autorisé à administrer le compte peut le modifier ; le Vault audite le changement avant de l'appliquer. Un changement ne modifie pas les demandes déjà en attente.

Quand le réglage est actif, `POST /sessions` exige un `ticket` qui respecte `APPROVAL_TICKET_PATTERN`. Sans cette variable, le format par défaut autorise de 1 à 64 lettres, chiffres et caractères `-`, `_`, `.`, `:`, `/`. Le motif configuré est une expression RE2, ancrée automatiquement au début et à la fin ; par exemple `(INC|CHG)[0-9]{7}`. La valeur est toujours limitée à 128 octets. Un ticket est une référence, non un secret ; OpenBastion ne vérifie pas son existence dans un ITSM.

La demande reste `pending_approval` jusqu'à décision ou expiration. L'approbateur doit détenir `session-approve:account:<id>` et être une autre personne que le demandeur. Le droit `breakglass-approve` ne suffit pas. Le ticket est affiché avec la demande et inclus dans les événements d'audit de demande et de décision, dans les détails protégés par le hash v4 (ADR-0068). Un ticket invalide est refusé et sa valeur n'est ni conservée ni recopiée dans l'audit. Sans écriture d'audit, aucune demande ni décision n'est acceptée.

La fenêtre de décision et le plafond des demandes en attente partagent les réglages du break-glass (`BREAKGLASS_APPROVAL_WINDOW_MINUTES` et `BREAKGLASS_MAX_PENDING_PER_REQUESTER`). Voir [la configuration du déploiement](../deployment/configuration.md) pour le motif de ticket et les limites associées.

## Accès d'urgence (break-glass)

Quand le recorder est en panne et qu'un incident ne peut pas attendre, une session peut s'exécuter **sans enregistrement acquitté**. C'est une dérogation à l'enregistrement et rien d'autre (ADR-0009) : l'authentification, les droits `session:create`, le Vault et l'audit restent en vigueur. **Désactivé par défaut**, il se règle à deux endroits qui doivent tous deux être d'accord — et, une fois activé, **une demande attend l'approbation d'une seconde personne** (ADR-0011, voir plus bas) :

| Où | Variable | Effet |
|---|---|---|
| Session Broker | `BREAKGLASS_MAX_MINUTES` | Durée maximale d'une session break-glass, en minutes. Absente ou `0` : désactivé. Un texte ou un négatif est une erreur fatale au démarrage. Revenir à `0` coupe la possibilité **immédiatement**, y compris pour les sessions déjà accordées mais pas encore ouvertes. |
| SSH Proxy | `BREAKGLASS_ENABLED=true` | Autorise ce proxy à honorer une dérogation. Ignoré (avec un avertissement) hors `RECORDING_POLICY=required`. |
| Session Broker | `BREAKGLASS_APPROVAL` | `required` (**défaut**) : une demande break-glass attend l'approbation d'une autre personne. `disabled` : l'ancien comportement à une seule personne (ADR-0009), à demander **par son nom** — le Broker l'annonce au démarrage (« WITHOUT APPROVAL »). Toute autre valeur est une erreur fatale. |
| Session Broker | `BREAKGLASS_APPROVAL_WINDOW_MINUTES` | Délai laissé pour décider, de 1 à 1440 (défaut **15**). Passé ce délai la demande est `expired` et ne peut plus être décidée. Tout autre texte ou nombre est une erreur fatale. |
| Session Broker | `BREAKGLASS_NOTIFY_URL` | URL d'un webhook (récepteur générique, Slack, Teams, selon `BREAKGLASS_NOTIFY_FORMAT`) prévenu quand une demande break-glass est déposée, approuvée ou rejetée (ADR-0012). Absente : aucune notification, les approbateurs consultent la liste. **https exigé** (http seulement vers une adresse de boucle locale) ; une URL avec identifiants, sans hôte, d'un autre schéma ou illisible est une erreur fatale au démarrage, dont le message ne la répète pas. **L'URL est un secret** (celles de Slack et de Teams en contiennent un) : traitez-la comme tel dans vos manifestes — Secret Kubernetes, pas ConfigMap. Le Broker ne journalise que son schéma et son hôte. |
| Session Broker | `BREAKGLASS_NOTIFY_FORMAT` | Forme des envois : `generic` (défaut), `slack` ou `teams` (ADR-0074, [`notifications.md`](notifications.md)). Teams exige `teams` et un flux Workflows. Sans URL, ou une autre valeur : le Broker refuse de démarrer. |
| Session Broker | `BREAKGLASS_MAX_PENDING_PER_REQUESTER` | Nombre maximal de demandes break-glass qu'**un même demandeur** peut avoir en attente, de 1 à 100 (défaut **3**) ; au-delà, `429`. Il n'existe pas de valeur « illimité » ; un texte, `0`, un négatif ou plus de 100 est une erreur fatale au démarrage. Ne s'applique qu'avec `BREAKGLASS_APPROVAL=required` (sans approbation, rien n'attend). Une place se libère quand une demande est décidée ou échue (ADR-0013). |
| Session Broker | `BREAKGLASS_NOTIFY_SECRET` | Secret qui signe le webhook : 32 octets au moins, utilisé tel quel, sans suppression d'espaces (`openssl rand -hex 32`). Fixé, chaque envoi porte `X-OpenBastion-Timestamp` et `X-OpenBastion-Signature`. Fixé sans `BREAKGLASS_NOTIFY_URL`, ou trop court : erreur fatale au démarrage. Jamais journalisé, jamais répété dans une erreur (ADR-0013). |
| Session Broker | `SESSION_READ_AUDIT_BURST` | Combien de **refus de lecture** d'une session (`GET /sessions/{id}` refusé à un tiers) **d'une même identité** s'écrivent à l'audit d'un coup, de 1 à 1000 (défaut **10**) ; voir « Qui peut lire une session » dans `docs/administration/audit-and-compliance.md` (ADR-0020). Ce n'est **pas** une limite de débit : le refus reste le même, seule son écriture à l'audit est bornée. Il n'existe pas de valeur « illimité » ni « désactivé » ; un texte, `0`, un négatif ou plus de 1000 est une erreur fatale au démarrage. **Par processus** : avec *N* répliques du Broker, *N* fois le budget. |
| Session Broker | `SESSION_READ_AUDIT_RATE_PER_MINUTE` | Combien de refus de lecture s'écrivent ensuite **par minute** pour une même identité, de 1 à 600 (défaut **6**). Mêmes règles que ci-dessus. |
| Session Broker | `SESSION_EXPIRY_SWEEP_SECONDS` | Période du balayage des expirations (ADR-0034), de 1 à 3600 secondes (défaut **30**) : chaque session ou demande break-glass passée son échéance est marquée `expired` en base, une fois quel que soit le nombre de répliques, et `session.expire` est écrit à l'audit (sans acteur). Il n'existe pas de valeur « désactivé » ; un texte, `0`, un négatif ou plus de 3600 est une erreur fatale au démarrage. |
| Password Vault | `ROTATION_SWEEP_SECONDS` | Période du balayage des rotations planifiées (ADR-0040), de 1 à 86 400 secondes (défaut **300**) : chaque compte `scheduled` échu est pris par un seul Vault et tourné sur sa cible (au plus 20 par passage ; un échec attend une heure). Il n'existe pas de valeur « désactivé » ; un texte, `0`, un négatif ou plus de 86 400 est une erreur fatale au démarrage. |
| Password Vault | `ROTATION_WINDOW_UTC` | Fenêtre horaire des rotations planifiées (ADR-0041), `HH:MM-HH:MM` en **UTC**, qui peut passer minuit (`22:30-03:00`). Hors de la fenêtre, aucun compte n'est pris ; un compte échu attend la fenêtre suivante. Absente : à toute heure. Mal formée ou de durée nulle : erreur fatale au démarrage. Une rotation demandée par un administrateur n'est pas tenue par la fenêtre. |
| Password Vault | `ROTATION_ALERT_AFTER_FAILURES` | Après combien d'échecs consécutifs de la rotation planifiée d'un compte le Vault écrit `vault.rotation_overdue` à l'audit, puis de nouveau tous les autant d'échecs (ADR-0041) ; de 1 à 100, défaut **3**. Hors bornes : erreur fatale au démarrage. |

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
