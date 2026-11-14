# Contrat de confirmation MFA pour l'injection d'un secret

**Statut :** implémentation partielle en cours — parcours A câblé pour SSH en interne, sans route Gateway ni UI  
**Décision de référence :** ADR-0097 (accepté)  
**Périmètre :** injection d'un secret issu du Vault (parcours A). Le parcours B (secret saisi par l'opérateur) reste bloqué tant que le transport navigateur → proxy ne garantit pas que la Gateway ne voit jamais le clair.

## 1. Invariants

1. Le navigateur ne reçoit jamais un secret du Vault.
2. La Gateway ne reçoit jamais de credential ni de scope Vault. Le Session Broker ne reçoit jamais le credential cible ; il manipule transitoirement en mémoire le scope Vault (capacité bearer de contrôle, pas le credential), uniquement pour le transmettre au proxy choisi. Il ne le persiste, ne le journalise et ne le retourne jamais au client.
3. Seul le proxy de la session échange un scope Vault à usage unique contre le credential.
4. Chaque injection exige une preuve MFA fraîche et une autorisation « secret:inject:<account_id> ».
5. Une autorisation d'injection est liée à un utilisateur, une session, un compte Vault, un protocole et l'action exacte. Elle n'est ni transférable ni réutilisable.
6. Audit et marqueur d'enregistrement sont acquittés avant toute frappe dans la cible. Toute panne refuse l'action.
7. L'expiration de la session, sa révocation, son changement d'état ou le changement d'instance proxy invalide l'opération.
8. Aucun fallback vers presse-papiers, terminal ordinaire ou saisie non masquée n'est permis.

## 2. Responsabilités et flux

| Étape | Composant | Responsabilité |
|---|---|---|
| 1 | Admin UI → Gateway | Demande une injection sur la session courante, avec l'identifiant du compte Vault (pas de valeur secrète). |
| 2 | Gateway → Session Broker | Transmet l'identité vérifiée issue du bearer token ; le corps client ne peut pas choisir l'acteur ou ses rôles. |
| 3 | Session Broker | Charge la session, vérifie qu'elle est active, non expirée, non révoquée, que l'appelant en est le demandeur et que le protocole correspond. Vérifie « secret:inject:<account_id> » / « secret:inject ». |
| 4 | Session Broker → Authentication | Demande un challenge MFA lié à l'acteur, la session, le compte, le protocole et l'action. Appel mTLS authentifié comme « session-broker ». |
| 5 | Gateway → Admin UI | Retourne uniquement l'identifiant opaque du challenge, son expiration et les options WebAuthn/TOTP nécessaires. |
| 6 | Admin UI → Gateway → Session Broker → Authentication | Transmet la preuve TOTP ou WebAuthn. Le Broker réévalue la session et les droits avant la confirmation. |
| 7 | Authentication | Vérifie la preuve selon les politiques existantes (TOTP à usage unique ; WebAuthn avec vérification origin/RP ID/compteur ; WebAuthn obligatoire pour les rôles stricts). Consomme le challenge atomiquement et crée un grant opaque aléatoire à usage unique. |
| 8 | Session Broker | Réévalue l'autorisation et l'état de la session après le retour MFA. |
| 9 | Session Broker → Authentication | Consomme immédiatement le grant. Le stockage ne conserve que SHA-256 du grant et son contexte. Une seule consommation concurrente réussit. |
| 10 | Session Broker → Vault | Demande un scope à usage unique lié à la session, au compte et à l'identité exacte du proxy. |
| 11 | Session Broker → Proxy | Transmet uniquement session, compte et scope Vault par mTLS. Le scope ne retourne jamais au client. |
| 12 | Proxy → Vault | Échange le scope une fois, reçoit le credential, le purge après saisie. |
| 13 | Proxy | Sous verrou exclusif d'entrée : audit préalable, marqueur d'enregistrement acquitté, frappe dans la cible, purge du buffer. |

Le grant MFA est consommé par le Broker avant l'émission du scope Vault. Une erreur après consommation exige une nouvelle confirmation MFA ; aucun grant ne peut être rejoué pour « réessayer ». Si la frappe a pu atteindre la cible mais que l'audit final échoue, le résultat est ambigu : l'événement préalable et le marqueur « injection requested » restent la preuve de tentative ; l'opérateur doit vérifier la cible avant une nouvelle tentative.

## 3. Contrats internes

### 3.1 Authentication — créer un challenge d'action

POST /auth/v1/actions/challenge — mTLS, appelant autorisé : session-broker uniquement.

Requête : actorUserId (identité vérifiée par la Gateway et transmise par le Broker), sessionId, accountId, protocol (ssh, vnc ou rdp), action (valeur constante secret:inject).

Réponse : challenge (32 octets aléatoires encodés base64url ; seule son empreinte SHA-256 est persistée), expiresAt (UTC, durée cible 120 secondes), factors (facteurs réellement enrôlés et acceptables), webAuthn (options de cérémonie si une clé est utilisable).

Refus si MFA désactivé, aucun facteur enrôlé, rôle strict sans WebAuthn, utilisateur inconnu/inactif ou stockage indisponible. Pas de challenge générique convertible en jeton de connexion.

### 3.2 Authentication — vérifier et émettre un grant

POST /auth/v1/actions/verify — mTLS, appelant autorisé : session-broker uniquement.

Requête : challenge, factor (totp ou webauthn), proof (code TOTP ou assertion WebAuthn ; jamais journalisé).

Réponse interne uniquement : grant (32 octets aléatoires base64url), expiresAt (UTC, durée cible 30 secondes).

Le grant est une capacité opaque, pas un JWT d'accès. Il n'est jamais renvoyé par la Gateway à l'Admin UI. La ligne persistée contient uniquement SHA-256(grant), actor_user_id, session_id, account_id, protocol, action, expires_at, consumed_at. Aucune preuve MFA ni secret Vault n'est stocké.

### 3.3 Authentication — consommer le grant

POST /auth/v1/actions/consume — mTLS, appelant autorisé : session-broker uniquement.

Requête : grant et contexte attendu complet (actorUserId, sessionId, accountId, protocol, action). Réponse : succès sans donnée sensible, ou refus générique.

La consommation est atomique :

    UPDATE mfa_action_grants
       SET consumed_at = now()
     WHERE grant_hash = $1
       AND consumed_at IS NULL
       AND expires_at > now()
       AND actor_user_id = $2
       AND session_id = $3
       AND account_id = $4
       AND protocol = $5
       AND action = $6
    RETURNING grant_hash;

Une seule ligne retournée signifie succès. Zéro ligne signifie refus. Les détails de cause ne sont pas exposés.

## 4. Contrats Gateway et Session Broker

Routes publiques proposées :
- POST /sessions/{sessionId}/secrets/{accountId}/challenge : crée le challenge et renvoie uniquement les informations MFA.
- POST /sessions/{sessionId}/secrets/{accountId}/inject : reçoit la preuve MFA, puis orchestre la consommation du grant et l'injection.

La Gateway authentifie le bearer token et reconstruit les champs d'acteur à partir du contexte vérifié. Elle ne relaie jamais un champ client actorUserId, actorRoles ou requestedBy comme autorité.

Le Broker :
- ne possède aucune méthode de lecture de credential ;
- vérifie le demandeur, le statut, la durée de vie, le compte et le protocole de la session à chaque route ;
- demande Authorization pour secret:inject:<account_id> avec l'action secret:inject ; refus par défaut ;
- consomme le grant auprès d'Authentication avant de demander le scope Vault ;
- n'écrit jamais le grant, le scope ni la preuve MFA dans l'audit ;
- lie le scope Vault au proxy exact qui détient la session ;
- refuse si le proxy n'est pas joignable ou si le type de session n'implémente pas SecretTyper.

Les chemins et noms définitifs des routes restent à synchroniser avec le routeur Gateway existant et le schéma OpenAPI avant leur implémentation.

## 5. Persistance et concurrence

La migration additive 008_mfa_action_grants.sql a été ajoutée au module Authentication, sans modifier les migrations déjà appliquées :
- table mfa_action_grants, empreinte de grant comme clé primaire ;
- colonnes de liaison non nulles : acteur, session, compte, protocole, action ;
- expires_at, consumed_at, created_at ;
- index d'expiration pour le nettoyage ;
- contrainte de domaine sur protocol/action, validation stricte dans le domaine également.

Le challenge d'action doit être distinct du challenge de connexion : il ne doit jamais passer par finish() ni appeler TokenIssuer.Issue. La vérification doit retourner un grant d'action, jamais un bearer token.

Le magasin en mémoire doit implémenter les mêmes garanties atomiques que PostgreSQL sous mutex, afin que les tests unitaires n'aient pas une sémantique plus faible.

## 6. Sécurité et tests obligatoires

| Test | Résultat attendu |
|---|---|
| Grant expiré | Refus ; aucun scope Vault ni appel proxy |
| Grant consommé une première fois puis rejoué | Deuxième consommation refusée |
| Deux consommations concurrentes | Une seule réussit |
| Autre utilisateur | Refus |
| Autre session | Refus |
| Autre compte | Refus |
| Autre protocole | Refus |
| Autre action (secret:paste) | Refus |
| Challenge expiré | Refus ; aucun grant |
| Challenge déjà consommé | Refus ; aucun grant |
| TOTP réutilisé dans la même fenêtre | Refus via l'état totp_last_step existant |
| Rôle strict avec TOTP seulement | Refus |
| Assertion WebAuthn d'une autre origine/RP ID | Refus |
| Compteur WebAuthn régressif | Refus |
| MFA non enrôlé / MFA indisponible | Refus |
| Authorization refuse ou indisponible | Refus ; aucun challenge utilisable pour injecter |
| Session terminée/expirée/révoquée entre challenge et confirmation | Refus |
| Compte non épinglé ou compte différent de la session | Refus |
| Proxy différent de celui de la session | Refus |
| Audit indisponible | Refus avant la frappe |
| Recorder indisponible | Refus avant la frappe |
| Erreur Vault / scope déjà consommé | Refus ; buffers purgés |
| Valeur du grant, scope ou preuve dans logs/audit/recording | Test de non-divulgation |

Chaque garantie doit avoir une contre-épreuve : retirer temporairement le contrôle correspondant doit faire échouer le test. Ajouter des tests de concurrence sous -race et des tests PostgreSQL réels sur une base de test dédiée.

## 7. Parcours B — secret fourni par l'opérateur : bloqué séparément

ADR-0097 accepte le parcours B, mais le secret provient du navigateur. Le relayer en clair via une route JSON Gateway → Broker violerait l'invariant « secret jamais dans le control plane » (ADR-0003 et policy secrets-management). Il est donc interdit d'implémenter B de cette façon.

Avant B, concevoir un canal client → proxy où la Gateway ne voit que du ciphertext (par exemple un mécanisme standard de chiffrement de bout en bout, avec clé éphémère liée à la session et à l'instance proxy, anti-rejeu et authentification de contexte). Le choix cryptographique et le contrat de transport nécessitent un ADR dédié et une dépendance ne sera ajoutée qu'après décision. Aucun fallback clipboard n'est permis.

## 8. Ordre d'implémentation

1. ~~Migration additive, domaine du grant et magasins mémoire/PostgreSQL avec consommation atomique~~ (incrément 1).
2. ~~Défis TOTP/WebAuthn liés au contexte, émission de grant sans jeton de connexion, consommation atomique et routes internes Authentication réservées au Session Broker~~ (incrément 2 ; tests unitaires en place).
3. ~~Client mTLS Broker → Authentication et tests de transport~~ (incrément 3).
4. ~~Broker : vérifier session + Authorization ; appeler start/verify/consume ; ensuite seulement obtenir le scope Vault et commander le proxy~~ (incréments 4–5).
5. ~~Canal de commande proxy ciblé vers l'instance qui détient la session ; jamais de scope dans le client~~ (incrément 5, SSH seulement ; affinité déterministe ADR-0046).
6. ~~Tests PostgreSQL réels des migrations, bindings et consommations atomiques~~ (incrément 2, base dédiée PostgreSQL 16) ; restent les tests d'intégration multi-services.
7. Contrat OpenAPI public, documentation opérateur et UI ; seulement après les tests des étapes précédentes.
8. VNC et RDP : implémenter SecretTyper avec événements clavier Unicode, sans presse-papiers ; tests contre les vraies cibles prévues par ADR-0097.

**État actuel :** les étapes 1 à 6 sont réalisées pour le parcours A SSH interne ; voir §9 pour les détails et les limites. Les routes Gateway/Broker et l'UI, les tests multi-services, VNC/RDP et le parcours B restent à faire.


## 9. État d'implémentation — 14 novembre 2026, incrément 5 (SSH A)

- Le Session Broker orchestre désormais, dans un seul use case applicatif, `verify MFA → revalidation session/Authorization → consume grant → authorize scope Vault (15 s) → commande proxy`. Le grant n'est jamais renvoyé par ce use case. Une perte d'autorisation après la vérification MFA stoppe le flux avant consommation et avant Vault.
- Le Broker reçoit transitoirement le scope Vault à usage unique puis transmet au proxy seulement `session_id`, `account_id` et `vault_scope_token`, via le client mTLS épinglé à `ssh-proxy`. Le scope n'est ni persisté, ni journalisé, ni retourné à la Gateway/UI ; le secret cible ne passe jamais par le Broker.
- Le pool proxy utilise maintenant un rendezvous hashing déterministe sur le session ID et le nom stable d'instance, amendement ADR-0046 : toutes les répliques Broker ciblent la même instance ; aucune bascule vers un autre proxy n'est permise pour une action privilégiée. Si le propriétaire est indisponible, l'action échoue fermée.
- SSH Proxy expose `POST /internal/v1/inject-vault-secret`, autorisé au seul certificat mTLS `session-broker`. Il exige un shell interactif enregistré, refuse une session inactive ou ambiguë (plusieurs shells), lie le contexte de l'injection au contexte d'annulation du relay, puis échange le scope auprès du Vault avec sa propre identité mTLS.
- Le proxy compare le `TargetHost` et `TargetUser` reçus du Vault à ceux du shell actif. Il exige un credential de type `password`, UTF-8 valide, mono-ligne, sans contrôle et limité à 4 Kio, puis appelle `proxycore.InjectSecret` : audit préalable `session.secret_injection_started`, marqueur Command Recorder « injection requested » strictement acquitté, frappe SSH hors du flux enregistré, événement de résultat `session.secret_injected`/`session.secret_injection_failed`, purge des buffers. Aucun presse-papiers n'est utilisé.
- Tests ciblés couvrent le routage identique entre deux répliques Broker, l'absence de failover, le recontrôle Authorization après MFA, l'absence d'appel Vault/proxy si la consommation MFA échoue, le refus d'un protocole sans typer, l'absence de fetch pour une session inactive/annulée/ambiguë, la correspondance de cible, l'ordre audit → recording → typing et la purge.
- **Limites** : ce parcours est actuellement implémenté uniquement pour SSH interactif. Aucun endpoint Session Broker/Gateway ni UI n'est exposé ; VNC/RDP ne disposent pas encore de `SecretTyper` intégré ; le parcours B reste interdit jusqu'au canal E2E navigateur → proxy. Le flux A n'est donc pas encore activable par un utilisateur.
