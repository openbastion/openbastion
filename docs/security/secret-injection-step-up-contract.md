# Contrat de confirmation MFA pour l'injection d'un secret

**État actualisé au 21 novembre 2026 :** parcours A câblé Gateway → Broker → proxy pour SSH, VNC et RDP ; MFA TOTP/WebAuthn et routes API disponibles ; Admin UI raccordée (ADR-0097 §12) ; E2E multi-processus SSH/VNC/RDP validés ; VNC éprouvé contre TigerVNC réel ; test Chromium de l’UI avec API simulée passé dans la CI de la PR #220. Restent la réception Unicode RDP sur Windows en CI, le parcours navigateur contre une cible réelle et les risques P1 de la revue STRIDE.
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
| 1 | Admin UI → Gateway | Demande un challenge pour l'identifiant de session uniquement ; le compte Vault n'est jamais choisi ni transmis par l'UI, il est dérivé du stockage côté Broker. |
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

Routes publiques implémentées :
- `POST /sessions/{sessionId}/secret-injection-step-up` : corps vide ; crée le challenge et renvoie uniquement les informations MFA.
- `POST /sessions/{sessionId}/secret-injection` : reçoit la preuve MFA, puis orchestre la consommation du grant et l'injection.

La Gateway authentifie le bearer token, applique le seau de débit des actions de session, impose `Cache-Control: no-store`, rejette les champs inconnus et reconstruit les champs d'acteur à partir du contexte vérifié. Le premier endpoint refuse tout corps non vide. Elle ne relaie jamais un champ client `callerId`, `actorRoles`, `requestedBy`, `accountId`, `grant` ou `vault_scope_token` comme autorité.

Le Broker :
- ne possède aucune méthode de lecture de credential ;
- vérifie le demandeur, le statut, la durée de vie, le compte et le protocole de la session à chaque route ;
- demande Authorization pour secret:inject:<account_id> avec l'action secret:inject ; refus par défaut ;
- consomme le grant auprès d'Authentication avant de demander le scope Vault ;
- n'écrit jamais le grant, le scope ni la preuve MFA dans l'audit ;
- lie le scope Vault au proxy exact qui détient la session ;
- refuse si le proxy n'est pas joignable ou si le type de session n'implémente pas SecretTyper.
- expose les handlers de step-up et d'injection seulement sur les routes Session Broker autorisées au certificat mTLS `api-gateway` ; les routes Authentication restent exclusivement appelables par `session-broker`.

Les routes sont inscrites dans `docs/api/rest/openapi.yaml`. Le schéma OpenAPI décrit les preuves MFA autorisées et interdit les propriétés supplémentaires. L'Admin UI déclenche le challenge depuis le détail d'une session active SSH/VNC/RDP et ne transmet que la preuve TOTP ou l'assertion WebAuthn ; le compte est toujours celui de la session persistée.

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
7. ~~Contrat OpenAPI public et routes Gateway/Broker, avec tests HTTP et contrat Protobuf~~ (incrément 6) ; ~~interface Admin UI TOTP/WebAuthn du parcours A~~ (incrément UI, §12).
8. ~~VNC et RDP : implémenter SecretTyper avec événements clavier Unicode, sans presse-papiers~~ (incrément 7 : implémentation et tests unitaires/protocole) ; ~~parcours MFA/Broker/Vault/proxy/Recorder/Audit multi-processus VNC et RDP~~ (incrément 8 : VNC sur cible RFB de test avec séquence Unicode exacte ; RDP sur FreeRDP 3 avec scope, audit, marqueur durable et rejeu). Restent TigerVNC réel, preuve de réception Unicode sur Windows dans la CI et vérification navigateur contre les cibles.

**État au 15 novembre 2026 :** les routes Gateway/Broker, le contrat OpenAPI, l'orchestration MFA et l'interface Admin UI du parcours A sont réalisés. SSH est testé de bout en bout sur de vrais processus. VNC et RDP passent maintenant par un parcours multi-processus MFA → Broker → Vault → proxy → Video Recorder → Audit ; VNC vérifie les keysyms Unicode reçus par la cible RFB, RDP vérifie le scope, l'audit, le marqueur vidéo et le rejeu avec FreeRDP 3. FreeRDP Shadow ne fournit pas une preuve fiable de réception des événements Unicode ; cette preuve reste au test Windows `TestRDPWindows_SecretTyperUnicode` de la CI, non exécuté localement. TigerVNC réel et vérification navigateur restent à confirmer. Le parcours B reste interdit jusqu'à l'ADR et au canal E2E dédié.


## 9. État d'implémentation — 14 novembre 2026, incrément 5 (SSH A)

- Le Session Broker orchestre désormais, dans un seul use case applicatif, `verify MFA → revalidation session/Authorization → consume grant → authorize scope Vault (15 s) → commande proxy`. Le grant n'est jamais renvoyé par ce use case. Une perte d'autorisation après la vérification MFA stoppe le flux avant consommation et avant Vault.
- Le Broker reçoit transitoirement le scope Vault à usage unique puis transmet au proxy seulement `session_id`, `account_id` et `vault_scope_token`, via le client mTLS épinglé à `ssh-proxy`. Le scope n'est ni persisté, ni journalisé, ni retourné à la Gateway/UI ; le secret cible ne passe jamais par le Broker.
- Le pool proxy utilise maintenant un rendezvous hashing déterministe sur le session ID et le nom stable d'instance, amendement ADR-0046 : toutes les répliques Broker ciblent la même instance ; aucune bascule vers un autre proxy n'est permise pour une action privilégiée. Si le propriétaire est indisponible, l'action échoue fermée.
- SSH Proxy expose `POST /internal/v1/inject-vault-secret`, autorisé au seul certificat mTLS `session-broker`. Il exige un shell interactif enregistré, refuse une session inactive ou ambiguë (plusieurs shells), lie le contexte de l'injection au contexte d'annulation du relay, puis échange le scope auprès du Vault avec sa propre identité mTLS.
- Le proxy compare le `TargetHost` et `TargetUser` reçus du Vault à ceux du shell actif. Il exige un credential de type `password`, UTF-8 valide, mono-ligne, sans contrôle et limité à 4 Kio, puis appelle `proxycore.InjectSecret` : audit préalable `session.secret_injection_started`, marqueur Command Recorder « injection requested » strictement acquitté, frappe SSH hors du flux enregistré, événement de résultat `session.secret_injected`/`session.secret_injection_failed`, purge des buffers. Aucun presse-papiers n'est utilisé.
- Tests ciblés couvrent le routage identique entre deux répliques Broker, l'absence de failover, le recontrôle Authorization après MFA, l'absence d'appel Vault/proxy si la consommation MFA échoue, le refus d'un protocole sans typer, l'absence de fetch pour une session inactive/annulée/ambiguë, la correspondance de cible, l'ordre audit → recording → typing et la purge.
- **Limites à la date de cet incrément (14 novembre 2026)** : le parcours était implémenté uniquement pour SSH interactif ; VNC/RDP et l'interface opérateur restaient à construire. Cet état historique est supersédé par l'incrément 7 (§11), qui câble le `SecretTyper` VNC/RDP et la route mTLS. Restent l'UI, les essais d'interopérabilité sur vraies cibles et le parcours B.


## 10. État d'implémentation — 14 novembre 2026, incrément 6 (routes HTTP)

- `POST /sessions/{sessionId}/secret-injection-step-up` est exposé par la Gateway et le Session Broker. La requête est sans corps ; le Gateway construit l'acteur/rôles à partir du bearer token. Le Broker dérive le compte et le protocole du stockage et fixe l'action à `secret:inject`.
- `POST /sessions/{sessionId}/secret-injection` n'accepte que `challenge`, `factor`, `totp_code` ou `webauthn_response`. La Gateway refuse les champs inconnus, y compris toute tentative de forger l'identité, les rôles, le compte, le credential, le grant ou le scope. Elle reconstruit le corps interne à partir de la preuve et de l'identité vérifiée.
- Les deux endpoints sont soumis au seau `SESSION_ACTION_*` ; toutes les réponses (y compris les erreurs) sont `Cache-Control: no-store`. Le Broker limite les corps à 64 Kio, refuse les JSON supplémentaires et retourne `204` sans donnée sensible après confirmation proxy.
- Les tests couvrent l'identité vérifiée, les rôles, l'absence de corps pour le challenge, l'allowlist de preuve, TOTP/WebAuthn, l'absence de grant/scope dans les réponses, MFA refusé, demandeur non propriétaire, authentification manquante, routes inconnues et débit partagé. Le test de contrat relie les DTO HTTP aux messages Protobuf et documente les champs volontairement dérivés ou aplatis.
- Le test multi-processus `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses` enrôle TOTP, crée et connecte une session SSH, effectue le step-up via Gateway, injecte le credential du Vault et vérifie le marqueur Command Recorder, l'absence de credential dans les journaux et la chaîne d'audit.
- **Limites** : aucun écran UI ; seul SSH interactif ; pas de VNC/RDP ; parcours B toujours bloqué jusqu'au canal E2E.


## 11. État d'implémentation — 15 novembre 2026, incrément 7 (VNC/RDP)

- Le RDP/VNC Proxy implémente désormais la même route interne `InjectVaultSecret` que le SSH Proxy, autorisée exclusivement à `session-broker` par mTLS. Le routeur du Broker conserve son affinité déterministe et envoie VNC/RDP au pool screen existant.
- Le relay écran expose un `SecretTyper` uniquement tant que la session est vivante. L'enregistrement est lié au protocole et à l'hôte/utilisateur de la cible authentifiée ; une session inactive, ambiguë, annulée ou un credential Vault destiné à une autre cible est refusé.
- VNC utilise des keysyms Unicode RFB ; RDP utilise `TS_UNICODE_KEYBOARD_EVENT` UTF-16 avec paires press/release. L'entrée opérateur est sérialisée par le même verrou ; le presse-papiers n'est pas touché.
- L'ordre commun est audit préalable → marqueur vidéo Vault durable → frappe → audit du résultat. Les tests couvrent les métadonnées d'audit, la purge, l'allowlist mTLS, le registre et les formats clavier. Tests ciblés, `-race`, `go vet`, `buf lint` et `make build` : PASS.
- **Avant production** : essais réels TigerVNC et cinq cibles Windows de CI, puis test multi-processus MFA → Broker → VNC/RDP Proxy → Vault → Video Recorder → cible → Audit. L'interface Admin UI n'est pas raccordée ; B reste bloqué en attente du canal E2E dédié.


## 12. État d'implémentation — 15 novembre 2026, incrément UI ADR-0097

- L'Admin UI affiche l'action uniquement pour une session active SSH, VNC ou RDP. Le compte est affiché comme information et ne peut pas être changé côté navigateur : le Broker continue de le dériver depuis la session persistée.
- Une confirmation préalable rappelle que le relay doit être ouvert, que le focus doit être sur un champ masqué et que la saisie dans un champ non masqué peut apparaître dans l'enregistrement. Aucun mécanisme ne prétend détecter le focus de la cible.
- L'UI appelle le challenge sans corps, puis accepte uniquement un code TOTP ou une assertion WebAuthn via `navigator.credentials.get`. Les rôles stricts n'affichent pas de TOTP si le serveur ne le propose pas.
- Le code TOTP est effacé du champ avant l'envoi ; l'assertion WebAuthn et le challenge restent en mémoire seulement. L'UI ne reçoit ni credential Vault, ni grant MFA, ni scope Vault. Les réponses API sont `no-store`.
- Une annulation avant le challenge n'émet aucune requête ; une expiration, un facteur inutilisable ou un refus API n'entraîne aucun fallback vers clipboard ou saisie libre.
- Le contrat OpenAPI a été corrigé : les routes prennent en charge SSH, VNC et RDP, sous réserve d'un relay actif implémentant `SecretTyper`.
- **Non validé dans cet incrément** : parcours complet MFA → Broker → proxy écran → Vault → frappe → Video Recorder → Audit sur processus réels VNC/RDP, vérification UI dans un navigateur contre TigerVNC et les cinq cibles Windows. Les tests Windows restent exécutés uniquement en CI. Le parcours B reste interdit jusqu'à la conception et à l'épreuve d'un canal navigateur → proxy chiffré de bout en bout.


## 13. État d'implémentation — 15 novembre 2026, incrément 8 (E2E multi-processus VNC/RDP)

- Le test d'intégration VNC **TestScreenFlow_VNCFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses/Vault_secret_injection_across_real_VNC_processes** démarre les services séparément sous mTLS, utilise PostgreSQL dédié et une cible RFB de test. Il enrôle TOTP, crée une session VNC détenue par l'acteur, refuse le step-up d'un autre utilisateur et un code TOTP invalide, puis vérifie la séquence de keysyms Unicode exacte reçue par la cible. L'audit session.secret_injected, le marqueur secret_injection_started, l'absence du secret dans les journaux et le stockage objet sont vérifiés.
- Le test d'intégration RDP **TestScreenFlow_RDPFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses** démarre les services séparément sous mTLS avec PostgreSQL dédié et FreeRDP 3. Il exerce le step-up TOTP, le refus d'un autre acteur et d'une preuve invalide, le routage Broker → Vault → proxy RDP, l'événement d'audit, le marqueur vidéo durable, l'absence du secret dans le marqueur et le stockage objet, ainsi que le rejeu. FreeRDP Shadow ne fournit pas de receipt oracle fiable pour la frappe Unicode ; la réception exacte par Windows reste à vérifier par TestRDPWindows_SecretTyperUnicode dans la CI Windows.
- Le test de routage **TestInjectVaultSecretWithStepUp_RoutesEverySupportedProtocolToItsProxyFamily** couvre explicitement ssh → ssh-proxy, vnc → rdp-vnc-proxy et rdp → rdp-vnc-proxy. Cette couverture a révélé puis corrigé une garde authorizedSecretAction qui n'autorisait encore que SSH malgré l'implémentation des typers écran.
- Résultats locaux : go test -race ./services/access/session-broker/... PASS ; compilation de tous les tests d'intégration PASS ; parcours VNC complet PASS (115,64 s, incluant l'expiration de session) ; parcours RDP FreeRDP 3 PASS. Aucun test Windows n'a été lancé localement.
- Limites restantes : smoke test TigerVNC réel, confirmation CI du test Windows de réception Unicode, test navigateur Admin UI contre une cible réelle, revue de menace ciblée et parcours B interdit jusqu'à un canal navigateur → proxy chiffré de bout en bout.


## 13. État d’implémentation — 15 novembre 2026, incrément 8 (E2E multi-processus VNC/RDP)

- Le test VNC TestScreenFlow_VNCFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses démarre les services séparément sous mTLS, utilise PostgreSQL dédié et une cible RFB de test. Il enrôle TOTP, crée une session VNC détenue par l’acteur, refuse le step-up d’un autre utilisateur et un code TOTP invalide, puis vérifie la séquence de keysyms Unicode exacte reçue par la cible. Audit session.secret_injected, marqueur secret_injection_started, absence du secret dans les journaux et le stockage objet sont vérifiés.
- Le test RDP TestScreenFlow_RDPFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses démarre les services séparément sous mTLS avec PostgreSQL dédié et FreeRDP 3. Il exerce le step-up TOTP, le refus d’un autre acteur et d’une preuve invalide, le routage Broker → Vault → proxy RDP, l’événement d’audit, le marqueur vidéo durable, l’absence du secret dans le marqueur et le stockage objet, ainsi que le rejeu. FreeRDP Shadow ne fournit pas de receipt oracle fiable pour la frappe Unicode ; la réception exacte par Windows reste à vérifier par TestRDPWindows_SecretTyperUnicode dans la CI Windows.
- TestInjectVaultSecretWithStepUp_RoutesEverySupportedProtocolToItsProxyFamily couvre explicitement ssh → ssh-proxy, vnc → rdp-vnc-proxy et rdp → rdp-vnc-proxy. Cette couverture a révélé puis corrigé une garde authorizedSecretAction qui n’autorisait encore que SSH malgré l’implémentation des typers écran.
- Résultats locaux : go test -race ./services/access/session-broker/... PASS ; compilation de tous les tests d’intégration PASS ; parcours VNC complet PASS (115,64 s, incluant l’expiration de session) ; parcours RDP FreeRDP 3 PASS (73,65 s). Aucun test Windows lancé localement.
- Limites restantes : smoke test TigerVNC réel, confirmation CI du test Windows de réception Unicode, test navigateur Admin UI contre une cible réelle, revue de menace ciblée et parcours B interdit jusqu’à un canal navigateur → proxy chiffré de bout en bout.
