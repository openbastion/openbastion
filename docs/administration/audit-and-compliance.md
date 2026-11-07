# Supervision et audit courant

- **Dashboards** : Grafana préconfiguré (`docs/architecture/system-overview.md`) expose l'activité par service, le taux d'échec d'authentification, le nombre de sessions actives.
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

**Qui peut lire une session (ADR-0019).** Trois catégories de personnes, et rien d'autre :

1. **Le demandeur** de la session, sans aucune politique et sans que l'Authorization Service soit consulté.
2. **La personne qui l'a décidée** (approbation ou rejet d'une demande break-glass), pour **cette** session seulement.
3. **Quiconque détient une politique sur la ressource `session-read:account:<id du compte>`** (action `session:read`). Elle est refusée par défaut, et son préfixe est distinct de `vault:`, `breakglass:`, `breakglass-approve:` et `session-terminate:` : *pouvoir approuver une urgence, ou terminer une session, n'est pas pouvoir lire celle de quelqu'un d'autre*. Un approbateur qui n'est ni le demandeur ni le décideur reçoit `403` : il voit ce qu'il peut décider par la liste `GET /sessions?status=pending_approval`.

**Changement de comportement à l'installation de cette version :** avant, tout utilisateur authentifié lisait toute session ; maintenant, un auditeur ou une équipe de sécurité qui lisait les sessions des autres reçoit `403` tant que vous ne lui avez pas écrit de politique. Aucune n'est créée par défaut.

```sh
curl -X POST https://bastion.example.com/api/v1/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "secops-can-read-prod-db-01-sessions", "role": "secops",
       "resourcePattern": "session-read:account:<id-de-prod-db-01>", "effect": "allow"}'
```

Un `*` final est un préfixe : `session-read:account:*` couvre **tous** les comptes — et donc les **justifications d'urgence** de toutes les demandes ; réservez-le à un rôle réellement transverse, et gardez à l'esprit que `*` seul, ou `session*`, couvrent aussi cette ressource. Un refus explicite (`effect: deny`) l'emporte toujours. **Lire une session n'est pas lire ce qui s'y est tapé** : les commandes enregistrées restent derrière le rôle auditeur du Command Recorder.

Ce qui se passe : si l'Authorization Service ne répond pas, un tiers reçoit `503` (jamais une lecture faute de réponse) ; le demandeur et le décideur ne dépendent pas de lui. Le refus (`403`) est le même pour tous et ne dit rien de la session — ni le compte, ni le demandeur, ni la justification, ni l'état. **Une lecture servie à un titulaire de politique est un événement** `session.read` en succès (auteur = celui qui a lu, ressource = `session` et l'identifiant lu), écrit avant d'être servi et sans budget (ADR-0021) : c'est ce que vous relisez pour savoir **qui a lu quoi**. Celle du demandeur et celle du décideur n'écrivent rien. Un **refus** (`403`) en écrit un aussi, en échec, borné par identité (ADR-0020) : `session.read`, `success=false`, auteur = l'appelant refusé, ressource = `session` et l'identifiant sondé — c'est ce que vous relisez pour repérer une sonde. Un `404` (identifiant inconnu), un `503` ou un appelant sans nom n'écrivent rien ; **si l'audit ne répond pas, la lecture d'un titulaire de politique est un `503`** (rien n'est servi). Au-delà du budget (`SESSION_READ_AUDIT_BURST`, puis `SESSION_READ_AUDIT_RATE_PER_MINUTE`, voir `docs/administration/approval-workflows.md`), le refus reste identique mais n'est plus écrit un par un : cherchez la ligne « refused reads by user … are no longer written to the audit one by one » dans le journal du Broker, qui nomme l'identité (limites : `docs/deployment/configuration.md`, « Ce qui reste faux »).

**Ce qui se passe quand on termine (ADR-0018).** Terminer, c'est couper : le Broker dit d'abord au SSH Proxy de révoquer la session, et ne la marque terminée qu'après sa confirmation.

- L'opérateur connecté lit « `openbastion: session ended because it was terminated.` » (sans savoir qui l'a décidé), et sa connexion se ferme. Un ticket de connexion pas encore utilisé ne sert plus ; un `connect` en cours au même instant ne laisse pas de ticket. La session ne peut plus être établie, jusqu'à l'heure où elle aurait expiré de toute façon.
- Dans l'audit : `session.terminate` du Broker (au nom de celui qui a terminé), puis, pour **chaque connexion coupée**, `session.revoked` et `session.terminate` du proxy (le credential est purgé). Un arrêt du proxy, lui, **n'est pas** une révocation et n'écrit pas `session.revoked`.
- **Si le proxy est injoignable** (ou ne confirme pas dans les 5 secondes) : `503`, **la session reste `active`**, et un événement `session.terminate` en **échec** est écrit sous le nom de l'appelant — la tentative est tracée. Renouvelez le même appel quand le proxy est revenu : il aboutit. Tant que ce n'est pas fait, la session est ouverte ; si c'est urgent, coupez la connexion au niveau réseau ou arrêtez le proxy, puis terminez.
- Une terminaison **refusée** (`403`), d'une session inconnue (`404`) ou qui n'est pas active (`409`) ne contacte pas le proxy.
- Le proxy se souvient de la révocation pendant le temps qu'il restait à la session (plus une minute, au plus 7 jours), **en mémoire** : s'il redémarre, il oublie — sans conséquence, puisque le Broker n'émet plus de ticket pour une session terminée.

## Clé de la chaîne d'audit (ADR-0027)

Chaque événement d'audit est signé (HMAC-SHA256) avec la **clé de chaîne** de l'Audit Service : sans elle, personne ne peut réécrire la chaîne en base de façon qu'elle se vérifie encore.

- **`AUDIT_CHAIN_KEY_HEX`** — 64 chiffres hexadécimaux (32 octets ; `openssl rand -hex 32`). **Obligatoire avec `DATABASE_URL`** : sans elle, ou avec une valeur qui n'est pas une clé, l'Audit Service refuse de démarrer en nommant la variable (jamais la valeur). En mémoire (sans base), une clé aléatoire est tirée au démarrage et l'annonce le dit.
- **`AUDIT_CHAIN_PREVIOUS_KEYS_HEX`** — clés précédentes, séparées par des virgules, gardées **pour vérifier** ce qu'elles ont signé, jamais pour signer. **Rotation** : mettre la nouvelle clé dans `AUDIT_CHAIN_KEY_HEX`, l'ancienne dans `AUDIT_CHAIN_PREVIOUS_KEYS_HEX`, redémarrer ; la ligne de démarrage dit l'identifiant de la clé courante et le nombre de clés tenues (« signed with key b6e8…, 2 key(s) held »). Chaque événement porte l'identifiant (`chain_key_id`) de la clé qui l'a signé, jamais la clé.
- **Une clé perdue rend l'histoire qu'elle a signée invérifiable, définitivement** : `verify-chain` répond `409` « signed with chain key …, which this service does not hold ». Sauvegarder chaque clé **hors de la base et hors des sauvegardes de la base** (`docs/deployment/backup-restore.md`), pour toute la durée de rétention de l'audit.
- Chaque événement porte aussi **le service qui l'a écrit** (`emitter`), tiré de son certificat mTLS — jamais du corps de la requête ; vide quand `INTERNAL_TLS=disabled`.

## Ancrage de la chaîne hors de la base (ADR-0028)

L'Audit Service écrit périodiquement une **ancre** — l'identifiant et le hash du dernier événement qu'il a écrit, sous un HMAC avec la clé de chaîne — dans un fichier en ajout seul, **hors de la base**. `verify-chain` vérifie chaque ancre et exige que l'événement ancré soit encore dans la chaîne, avec le même hash : une chaîne réécrite (même entièrement, dans un format sans clé) ou tronquée avant la dernière ancre est un `409`.

- **`AUDIT_ANCHOR_FILE`** — chemin **absolu** du fichier d'ancres, **obligatoire avec `DATABASE_URL`** (refus de démarrer sans lui, ou si son répertoire n'existe pas). Il doit être **là où la base n'a aucun pouvoir** : un autre volume, idéalement un montage en ajout seul (WORM) ou une destination répliquée hors de l'hôte de la base ; quelqu'un qui peut écrire à la fois dans la base et dans ce fichier peut tout réécrire. Le fichier est créé au démarrage (droits 0600) puis seulement complété ; **un fichier qui a disparu n'est jamais recréé** : `verify-chain` répond `503` (la chaîne ne peut pas être garantie).
- **`AUDIT_ANCHOR_INTERVAL_SECONDS`** — période d'ancrage, **60** par défaut, de 1 à 3600 (hors bornes : refus de démarrer). Une ancre n'est écrite que si la tête a avancé. **Ce qui a été écrit depuis la dernière ancre** peut encore être tronqué sans être vu : la période est la fenêtre d'exposition.
- Un échec d'écriture d'une ancre n'arrête pas l'audit (les événements restent signés) : une ligne de journal par épisode (« anchoring the head of the chain failed »), puis « works again ».

## Rétention : archiver les vieux mois hors de la base (ADR-0032)

**Désactivée par défaut** : sans les deux variables suivantes, rien ne quitte jamais `audit_events`. Activée, l'Audit Service archive, au démarrage puis toutes les heures, les **mois civils entiers** plus vieux que la rétention, le plus ancien d'abord, un à la fois. Pour chaque mois, il **vérifie toute la chaîne** (événements et ancres), écrit l'archive, la **relit**, ajoute un **point de contrôle** sous la clé de chaîne au fichier d'ancres, écrit l'événement `audit.archived` dans la chaîne, puis seulement supprime le mois de la base. `verify-chain` repart ensuite du dernier point de contrôle.

- **`AUDIT_ARCHIVE_DIR`** — répertoire **absolu**, existant, où sont écrites les archives `audit-AAAA-MM.jsonl` (un événement par ligne, tous les champs, droits 0600, jamais écrasées). Comme le fichier d'ancres, **hors de la portée de la base** : un autre volume, idéalement un stockage objet ou un montage en ajout seul (WORM) avec la durée de conservation légale.
- **`AUDIT_RETENTION_MONTHS`** — nombre de mois gardés en base, **de 1 à 120** (hors bornes : refus de démarrer). Avec 12 au 15 mars 2027, les mois jusqu'à février 2026 inclus sont archivés.
- Les deux vont ensemble (l'une sans l'autre : refus de démarrer), et demandent `AUDIT_ANCHOR_FILE` (les points de contrôle y sont gardés).
- **Si la chaîne ne se vérifie pas, rien n'est archivé ni supprimé** : une ligne de journal par épisode (« archiving stopped, nothing more leaves the database »), réessai à l'heure suivante.
- **Détruire une archive** à la fin de la durée légale se fait par le stockage (cycle de vie, rétention WORM), jamais par le service. La chaîne en base reste vérifiable sans elle ; ce qu'elle contenait n'est plus consultable.
- **Un retour à un binaire d'avant ADR-0032** sur un fichier d'ancres qui contient des points de contrôle fait répondre `verify-chain` en `409` (« not an anchor ») : ce binaire ne connaît pas ces lignes.

## Les connexions (ADR-0064)

Chaque jeton émis est un événement `auth.login` ou `auth.login_mfa` de la chaîne, écrit avant l'émission ; les gestes du second facteur (`auth.mfa_enrollment_code_issued`, `auth.mfa_enrolled`, `auth.mfa_reset`) avant d'être faits ; les refus (`auth.login_refused`) au mieux, dans un budget par nom de connexion. Chaque connexion et chaque refus disent dans leurs détails qui répond du compte : `identity_source` (`local`, `oidc`, `ldap`) et, pour un fournisseur ou un annuaire, `identity_provider` (son `id`, ou `(variables)` pour celui des variables `OIDC_*`/`LDAP_*` ; ADR-0076). **Sans Audit Service, personne ne se connecte.** Le détail est dans [`../deployment/configuration.md`](../deployment/configuration.md).
