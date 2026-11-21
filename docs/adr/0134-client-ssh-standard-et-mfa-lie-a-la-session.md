# ADR-0134 — Le client SSH standard ouvre une session à ticket ; le step-up MFA reste lié à l'action dans l'Admin UI

**Statut** `Accepté` · 21 novembre 2026, décision du propriétaire du projet (« Oui », après la recette) · catégorie : Proxy SSH · recette faite le 21 novembre 2026 (§4 et §4 bis) : 57 critères sur 59 prouvés. A06 relève du déploiement. H08 : les risques P1 d'ADR-0097 restent ouverts et suivis (`docs/security/known-limitations.md`) ; l'acceptation de l'ADR ne les déclare pas acceptés comme définitifs.
**Remplace** aucun ADR. Cette décision complète ADR-0097 sans en modifier ni remplacer les invariants.

## Contexte

OpenBastion permet à un opérateur d'utiliser un client SSH classique (OpenSSH, PuTTY ou équivalent) sans lui communiquer le mot de passe ni la clé privée du compte cible. Le client SSH se connecte au SSH Proxy avec un ticket de connexion à usage unique. Le proxy ouvre une seconde connexion SSH vers la cible, après avoir obtenu le credential du Vault et vérifié l'identité de la cible (ADR-0003, ADR-0039).

L'injection ultérieure du credential Vault dans un shell SSH interactif exige une confirmation MFA d'action (ADR-0097). Cette confirmation est distincte du MFA de connexion : elle porte sur l'action précise `secret:inject`, et ne transforme pas le challenge en jeton de connexion. L'opérateur garde son terminal SSH habituel ; il effectue la cérémonie MFA dans l'Admin UI, qui dispose des API publiques et des API WebAuthn du navigateur.

Une lecture littérale de « chiffrement de bout en bout » serait trompeuse. Le SSH Proxy termine la connexion SSH du client, puis agit comme client SSH indépendant vers la cible. Il s'agit de deux transports SSH chiffrés, avec le proxy comme frontière de confiance. Le secret Vault n'est jamais livré au client, au navigateur, à la Gateway ou au Session Broker ; il est récupéré par le proxy propriétaire et transmis à la cible dans le transport SSH proxy-cible.

Les documents d'ADR-0097 et le code ont désormais un parcours Admin UI pour SSH, VNC et RDP. Toutefois, `docs/api/grpc/README.md` conserve des phrases historiques affirmant que l'interface n'existe pas. Cet ADR fixe le parcours SSH, les responsabilités des canaux et les preuves minimales attendues ; il corrige ces descriptions obsolètes sans réécrire ADR-0097.

## Décision

### 1. Parcours opérateur, étape par étape

1. **S'authentifier à OpenBastion.** L'opérateur se connecte à l'Admin UI avec son identité et son facteur de connexion requis. Le bearer token est conservé par l'interface et transmis à la Gateway sur HTTPS ; le client SSH n'utilise pas ce bearer token.
2. **Créer une session SSH.** Depuis l'Admin UI ou l'API publique, l'opérateur demande une session avec le compte privilégié, le protocole `ssh`, une justification et une durée. La Gateway vérifie le bearer token ; le Broker dérive l'acteur de cette identité vérifiée. Une approbation préalable, si le compte l'exige, doit être terminée avant la connexion.
3. **Préparer la connexion.** L'opérateur appelle `POST /sessions/{sessionId}/connect`. Pour SSH, la réponse contient `proxyEndpoint`, `ticket`, `protocol` et `expiresAt`. Le Broker obtient un scope Vault pour le proxy propriétaire et lui demande d'enregistrer un ticket. Le ticket n'est pas le scope Vault ni le credential cible ; il est à usage unique et expire au plus tard avec la durée restante de la session.
4. **Ouvrir le terminal SSH classique.** L'opérateur utilise l'adresse exacte renvoyée par `proxyEndpoint`, et non l'adresse directe de la cible. Exemple OpenSSH, après extraction de l'hôte et du port :

   ```sh
   ssh -p <port> operator@<hote-du-proxy>
   ```

   Au prompt de mot de passe SSH, il colle/saisit le `ticket` retourné par `connect`. Le ticket ne doit pas être placé dans la ligne de commande, une variable exportée, un fichier, ni un argument d'outil susceptible d'être journalisé. Le ticket est consommé atomiquement pendant l'authentification SSH ; un second usage ou un ticket expiré est refusé. L'utilisateur SSH présenté au proxy est un identifiant de transport, pas l'identité humaine OpenBastion : celle-ci vient du jeton vérifié par la Gateway.
5. **Attendre le shell distant.** Le proxy n'ouvre la connexion cible qu'après la négociation SSH du client et la demande d'un canal interactif (shell). Il vérifie la clé d'hôte de la cible par rapport à l'ancre épinglée au Vault (ADR-0039). Une cible non reconnue est refusée avant l'envoi du credential. Le Command Recorder doit être disponible ; sinon la session est refusée ou coupée selon ADR-0008.
6. **Positionner le terminal sur une invite de secret masquée.** Dans le terminal SSH, l'opérateur déclenche sur la cible l'action qui attend le mot de passe (par exemple une invite `sudo` ou une invite applicative). Il ne doit pas laisser le curseur dans une commande ou un champ visible. OpenBastion ne peut pas prouver que le terminal distant masque effectivement la saisie.
7. **Demander l'injection dans l'Admin UI.** Dans le détail de cette session active, l'opérateur déclenche « Injecter le secret Vault ». L'interface affiche une confirmation rappelant que le shell doit être ouvert et que la cible doit attendre une invite masquée. Elle ne permet pas de choisir un autre compte : le Broker le relit depuis la session persistée.
8. **Obtenir un challenge d'action.** Après confirmation, l'Admin UI appelle `POST /sessions/{sessionId}/secret-injection-step-up` avec un corps vide. La Gateway transmet l'identité et les rôles du bearer token vérifié. Le Broker vérifie le demandeur, l'état et l'échéance de la session, le protocole SSH, puis l'autorisation `secret:inject` sur le compte lié. Il demande à Authentication un challenge lié au tuple complet `(actor_user_id, session_id, account_id, protocol, action)`, avec `action=secret:inject`.
9. **Vérifier TOTP ou WebAuthn dans le navigateur.**
   - **TOTP :** l'opérateur saisit son code à usage unique dans l'Admin UI. Le code est effacé du champ avant l'envoi. La Gateway transmet uniquement la preuve MFA autorisée ; Authentication vérifie le code, sa fenêtre temporelle et l'absence de réutilisation.
   - **WebAuthn / FIDO2 / passkey :** l'opérateur lance la cérémonie du navigateur (`navigator.credentials.get`) et valide sur sa clé ou son authentificateur. L'assertion signée est envoyée à Authentication via l'Admin UI et la Gateway. Authentication vérifie le challenge, l'origine, le RP ID, la signature et le compteur lorsque celui-ci est applicable. La clé privée ne quitte jamais l'authentificateur. Un client SSH en ligne de commande ne peut pas réaliser cette cérémonie WebAuthn ; le navigateur est donc requis pour cette étape. Pour les rôles stricts, WebAuthn est obligatoire et TOTP n'est pas proposé comme repli.
10. **Consommer l'autorisation d'action.** Authentication consomme le challenge et émet un grant opaque aléatoire à usage unique, lié au même tuple. Le challenge a une durée de 120 secondes et au plus cinq essais ; le grant a une durée de 30 secondes. Seule l'empreinte SHA-256 du challenge/grant est persistée selon le contrat ADR-0097. Le grant reste entre Authentication et le Broker : il n'est jamais envoyé au navigateur ni au proxy.
11. **Récupérer et injecter le credential.** Le Broker revalide la session et Authorization, consomme atomiquement le grant, puis demande au Vault un scope à usage unique, lié à la session, au compte et à l'identité mTLS du SSH Proxy propriétaire (durée prévue : 15 secondes). Le Broker transmet uniquement session, compte et scope au proxy par mTLS. Le proxy échange le scope directement auprès du Vault, vérifie que le compte cible (hôte et utilisateur) correspond au shell vivant, puis frappe le credential dans le flux SSH cible. Le credential n'est pas retourné à l'Admin UI, au client SSH, à la Gateway ou au Broker.
12. **Contrôler le résultat.** Avant toute frappe, le proxy attend l'acquittement de l'événement d'audit préalable et du marqueur Command Recorder. Il écrit ensuite le résultat dans la chaîne d'audit et purge les buffers qu'il contrôle. En cas de résultat `outcome_unknown`, l'opérateur ne rejoue pas l'injection : il vérifie l'état de la cible et rapproche l'identifiant `injection_id` avec les preuves d'audit. Une nouvelle tentative nécessite un nouveau challenge et une nouvelle preuve MFA.

### 2. Frontières de chiffrement et modèle de confiance

~~~mermaid
sequenceDiagram
    participant O as Opérateur / OpenSSH
    participant UI as Admin UI
    participant G as API Gateway
    participant B as Session Broker
    participant A as Authentication
    participant V as Password Vault
    participant P as SSH Proxy
    participant T as Cible SSH

    O->>P: SSH client-proxy (ticket à usage unique)
    P->>T: SSH proxy-cible (credential du Vault)
    UI->>G: HTTPS : challenge et preuve MFA
    G->>B: mTLS interne : identité vérifiée + preuve
    B->>A: mTLS : challenge / verify / consume
    B->>V: mTLS : scope lié au proxy propriétaire
    B->>P: mTLS : session + compte + scope
    P->>V: mTLS : échange scope contre credential
    P->>T: frappe dans le canal SSH cible
~~~

1. **Client → SSH Proxy :** protocole SSH chiffré, authentification par ticket éphémère. Ce flux ne transporte pas le mot de passe cible.
2. **SSH Proxy → cible :** seconde connexion SSH indépendante ; la clé d'hôte cible est vérifiée par rapport au Vault. Le proxy termine le premier SSH et initie le second : aucun tunnel cryptographique opaque client-cible n'est revendiqué.
3. **Admin UI → Gateway :** HTTPS en production ; le point de terminaison TLS est celui du déploiement. Le navigateur transporte le challenge et la preuve MFA, jamais le secret cible, le scope Vault ou le grant MFA.
4. **Communications internes :** TLS 1.3 mutuel, certificats et identités de service vérifiés. Les routes Authentication sont appelables par le seul Session Broker ; les routes d'injection du proxy sont réservées au certificat mTLS `session-broker`.
5. **Vault → proxy :** le credential est délivré au proxy propriétaire sur le canal mTLS. Le proxy l'utilise dans le flux SSH chiffré vers la cible. Le proxy est donc une frontière de confiance qui voit le credential en mémoire.
6. **Au repos :** les secrets du Vault et les enregistrements suivent leurs ADR dédiés ; le grant et le challenge ne sont conservés qu'empreintés. Cet ADR n'introduit aucun nouveau format cryptographique ni algorithme.

### 3. Règles normatives proposées

| ID | Règle |
|---|---|
| SSH-MFA-001 | Un client SSH classique se connecte exclusivement au `proxyEndpoint` renvoyé par `connect`, jamais directement à l'hôte cible. |
| SSH-MFA-002 | Le client SSH présente le ticket de connexion comme mot de passe de transport ; le ticket est à usage unique et n'est jamais un credential cible. |
| SSH-MFA-003 | Le ticket, le scope Vault et le credential ne doivent jamais apparaître dans les journaux, l'audit, les traces, les enregistrements ou les arguments de commande. |
| SSH-MFA-004 | L'identité humaine est exclusivement celle du bearer token vérifié par la Gateway ; le nom d'utilisateur SSH de transport ne constitue pas une preuve d'identité OpenBastion. |
| SSH-MFA-005 | Une injection n'est permise que dans une session SSH active, appartenant au demandeur, non expirée, non révoquée et possédant un shell interactif non ambigu. |
| SSH-MFA-006 | Le compte, l'hôte, l'utilisateur cible et le protocole sont dérivés de la session persistée et du Vault ; le client ne peut pas les substituer. |
| SSH-MFA-007 | Chaque injection exige un challenge MFA frais lié à l'acteur, la session, le compte, le protocole et l'action exacte `secret:inject`. |
| SSH-MFA-008 | Le challenge expire après 120 secondes, est à usage unique et est détruit après cinq échecs au plus ; un challenge de connexion ne peut pas être converti en challenge d'action. |
| SSH-MFA-009 | TOTP est vérifié par Authentication, à usage unique dans sa fenêtre ; une preuve déjà utilisée est refusée. |
| SSH-MFA-010 | WebAuthn est vérifié par Authentication avec challenge, origine, RP ID, signature et compteur applicable ; la clé privée ne quitte jamais l'authentificateur. |
| SSH-MFA-011 | L'Admin UI est le client de cérémonie WebAuthn. Le client SSH en ligne de commande ne reçoit ni ne fabrique d'assertion WebAuthn. |
| SSH-MFA-012 | Un rôle strict ne peut pas rétrograder vers TOTP lorsque WebAuthn est requis. Aucun fallback vers un facteur moins fort n'est permis. |
| SSH-MFA-013 | Le grant MFA est opaque, lié au même tuple, à usage unique, valable 30 secondes ; seule son empreinte SHA-256 est persistée. |
| SSH-MFA-014 | Le grant est consommé atomiquement avant la création du scope Vault ; il n'est jamais exposé au navigateur, au client SSH ou au proxy. |
| SSH-MFA-015 | Le scope Vault est lié à la session, au compte et au certificat du proxy propriétaire ; le proxy l'échange directement avec le Vault, une fois. |
| SSH-MFA-016 | Le Broker ne lit jamais le credential cible. Le proxy est le seul composant qui le récupère et le frappe dans le flux cible. |
| SSH-MFA-017 | La clé d'hôte de la cible est vérifiée selon ADR-0039 avant toute remise du secret. Aucun mode `InsecureIgnoreHostKey` n'est admis en production. |
| SSH-MFA-018 | L'audit préalable et l'acquittement du marqueur Command Recorder précèdent toute frappe ; indisponibilité ou résultat non fiable = refus fermé. |
| SSH-MFA-019 | L'injection n'utilise jamais le presse-papiers, un canal de commande parallèle ou une saisie opérateur non masquée comme solution de repli. |
| SSH-MFA-020 | Le proxy vérifie que le credential du Vault correspond au `TargetHost` et au `TargetUser` du shell interactif vivant ; toute ambiguïté est refusée. |
| SSH-MFA-021 | Un grant, un scope, un ticket expiré, consommé, rejoué ou lié à un autre contexte est refusé sans tentative de bascule vers un autre proxy. |
| SSH-MFA-022 | Une révocation empêche toute nouvelle frappe après son acquittement. Une frappe déjà transmise à la cible ne peut pas être annulée rétroactivement. |
| SSH-MFA-023 | En cas de perte de l'acquittement terminal après une frappe possible, le résultat est `outcome_unknown` ; aucun retry automatique ni réutilisation du grant/scope n'est permis. |
| SSH-MFA-024 | Les réponses API MFA/injection portent `Cache-Control: no-store`, ne retournent ni credential, ni grant, ni scope, et rejettent les champs inconnus. |
| SSH-MFA-025 | Les buffers contrôlés du credential sont purgés au plus tôt ; aucun effacement total de toutes les copies internes Go/TLS/GC n'est promis (ADR-0115). |
| SSH-MFA-026 | Le secret n'est injecté que lorsque l'opérateur a placé la cible sur une invite masquée. L'interface avertit du risque ; le proxy ne prétend pas détecter le focus ni le masquage de l'invite. |
| SSH-MFA-027 | Le chiffrement est décrit par segments (SSH client-proxy, SSH proxy-cible, HTTPS et mTLS internes). Le produit ne revendique pas de chiffrement cryptographique opaque de bout en bout client-cible. |
| SSH-MFA-028 | Le parcours B reste distinct du parcours Vault A et n'est pas activé par cet ADR SSH. Sa conception pour les sessions écran RDP/VNC est définie par ADR-0133 ; elle ne constitue pas une implémentation éprouvée ni un canal SSH. |

### 4. Checklist de recette OpenBastion

Les cases sont des critères à prouver, pas une déclaration de réussite. Une case ne passe qu'avec un test reproductible, son résultat conservé en CI ou dans le rapport de validation, et une contre-épreuve lorsque le critère protège une frontière de sécurité.

#### A — Connexion depuis un client SSH standard

- [x] A01 — Créer une session SSH par l'API publique avec un bearer token valide ; l'acteur est issu du jeton, jamais du corps client.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` (corps forgé `requestedBy`, l'acteur reste celui du jeton) ; `TestSecretInjectionStepUp_GatewayInjectsVerifiedIdentityAndDoesNotRelayClientBody`.
- [x] A02 — Connecter le demandeur uniquement ; un autre utilisateur et un approbateur non demandeur sont refusés.
  **Preuve** : `TestConnect_OnlyTheRequesterMayConnect`, `TestConnectOverHTTP_OnlyTheRequesterMayConnect`.
- [x] A03 — `connect` renvoie l'endpoint du proxy et un ticket ; aucun secret cible ni scope Vault n'est renvoyé.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : `connect` donne l'adresse du proxy et un ticket, qui ne contient pas le credential.
- [x] A04 — OpenSSH se connecte au proxy avec le ticket au prompt de mot de passe ; le shell cible interactif s'ouvre.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : OpenSSH 9.6 (`ssh -tt`), ticket au prompt par `SSH_ASKPASS` lisant un fichier 0600, shell cible ouvert ; clé d'hôte du proxy épinglée (`StrictHostKeyChecking=yes`).
- [x] A05 — Le ticket est consommé une seule fois ; le rejeu, l'expiration et la révocation avant connexion sont refusés.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : second `ssh` avec le même ticket, puis ticket d'une session terminée avant connexion, refusés à l'authentification (« Permission denied ») ; expiration : `TestPendingSessions_ConsumeRejectsExpiredTicket`. Contre-épreuve : ticket non consommé dans `PendingSessions.Consume` → le test échoue.
- [ ] A06 — L'accès réseau direct à la cible depuis le poste opérateur est absent ou bloqué par le déploiement ; le chemin autorisé est le proxy.
  **Non prouvable par le produit** : c'est une propriété du réseau de chaque déploiement (`docs/security/session-security.md`, « Isolation réseau »). À vérifier à l'installation.
- [x] A07 — Le proxy vérifie la clé d'hôte épinglée de la cible ; une clé différente entraîne un refus avant livraison du credential.
  **Preuve** : `TestRelay_AnImpostorWithAnotherHostKeyIsSentNoSecret`, `TestRelay_NoPinnedHostKeyMeansNoSecret`.
- [x] A08 — Une session non enregistrable ne s'ouvre pas ; le Command Recorder est requis selon ADR-0008.
  **Preuve** : `TestStrictRecording_ASessionIsRefusedBeforeTheCredentialIsFetched`, `TestStrictRecording_AnUnconfiguredProxyRefusesEverySession`.

#### B — Challenge lié à l'action et à la session

- [x] B01 — Le challenge est demandé avec un corps vide et l'identifiant de session seulement.
  **Preuve** : `TestSecretInjectionStepUp_GatewayInjectsVerifiedIdentityAndDoesNotRelayClientBody` ; le test navigateur à API simulée refuse un corps non vide.
- [x] B02 — Le Broker dérive acteur, compte et protocole de la Gateway et de la session persistée.
  **Preuve** : `TestSecretInjectionStepUp_ReturnsOnlyChallengeAndIsNoStore`, `TestInjectVaultSecretWithStepUp_RoutesEverySupportedProtocolToItsProxyFamily`.
- [x] B03 — Vérifier séparément les permutations acteur, session, compte, protocole et action ; chaque permutation est refusée.
  **Preuve** : `TestMFAActionStepUp_EachFieldOfTheTupleIsBound` (acteur, session, compte, protocole, action, chacun seul, challenge neuf à chaque fois ; contre-épreuve : protocole retiré de la comparaison → échec) ; grant : `TestMFAActionGrant_BindsEveryFieldExpiresAndCanBeConsumedOnce`.
- [x] B04 — Le challenge est lié à `secret:inject`, et non à une autorisation générique ou à un jeton de connexion.
  **Preuve** : `TestMFAActionStepUp_TOTPProducesOnlyBoundSingleUseActionGrant` (un grant d'action n'est pas un jeton de connexion).
- [x] B05 — Challenge expiré, consommé ou après cinq échecs : refus sans grant, scope ni frappe.
  **Preuve** : `TestMFAActionChallenge_ExpiryAndAttemptLimit`, `TestMFAActionChallenge_ConcurrentConsumptionHasOneWinner`.
- [x] B06 — Session terminée, expirée, révoquée ou demandeur non propriétaire entre challenge et preuve : refus.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : session terminée entre le challenge et la clé → `409`, rien n'est tapé, l'OpenSSH de l'opérateur est coupé.
- [x] B07 — Authorization refusé ou indisponible : refus fermé, sans scope Vault ni appel proxy.
  **Preuve** : `TestInjectVaultSecretWithStepUp_RechecksAuthorizationAfterMFA`.

#### C — TOTP

- [x] C01 — Enrôler un facteur TOTP et obtenir un challenge step-up pour une session SSH active.
  **Preuve** : `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses`.
- [x] C02 — Un code valide produit une seule opération d'injection confirmée.
  **Preuve** : `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses` : un code, une frappe, observée par la cible.
- [x] C03 — Un code invalide, mal formé, expiré ou réutilisé est refusé.
  **Preuve** : `TestMFAActionStepUp_ExpiredChallengeAndWrongFactorAreRefused`, `TestMFAActionStepUp_TOTPProducesOnlyBoundSingleUseActionGrant` (rejeu).
- [x] C04 — Le code est effacé du champ UI avant l'envoi et absent des journaux, traces, événements d'audit et enregistrements.
  **Preuve** : `TestAdminUI_SecretInjectionStepUpInAHeadlessBrowser` (champ vidé avant l'envoi) ; `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses` : ni le credential, ni un code du step-up, ni le champ `totp_code` dans les journaux des sept services (sans contre-épreuve : aucun service ne journalise le code à retirer).
- [x] C05 — TOTP non enrôlé ou MFA désactivé : aucune injection n'est possible.
  **Preuve** : `TestMFAActionStepUp_RequiresEnrolledFactorAndRejectsInvalidContext`.

#### D — WebAuthn / FIDO2 / passkeys

- [x] D01 — Réaliser la cérémonie réelle avec `navigator.credentials.get` dans un navigateur compatible et un authentificateur disponible.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : Chrome sans interface, `navigator.credentials.create` à l'enrôlement et `navigator.credentials.get` au step-up, répondus par l'authentificateur virtuel de Chrome (domaine CDP `WebAuthn`) ; ce n'est pas une clé matérielle.
- [x] D02 — Vérifier challenge, origine, RP ID, signature et compteur de l'authentificateur selon la politique WebAuthn.
  **Preuve** : `TestWebAuthnFlow_AStrictRoleLogsInOnlyWithItsKey_AndWhatPhishingWouldSendIsRefused` (origine, RP ID, compteur) ; le step-up passe par la même vérification (`FinishLogin`). `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : origine `http://localhost:<port>`, RP ID `localhost`.
- [x] D03 — Assertion d'une autre origine, d'un autre RP ID, d'un challenge différent ou rejoué : refus.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : assertion rejouée → `403`, rien n'est tapé ; signature altérée par l'authentificateur (`isBogusSignature`) → refus, rien n'est tapé. Deux verrous indépendants arrêtent le rejeu (challenge consommé, compteur) : chacun retiré seul, le rejeu reste refusé ; les deux retirés, il passe (`204`) et le test échoue.
- [x] D04 — La clé privée ne quitte jamais l'authentificateur ; seule l'assertion publique est transmise à Authentication.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : la preuve envoyée est une assertion `webauthn_response` ; la clé privée reste dans l'authentificateur virtuel.
- [x] D05 — Pour un rôle strict, TOTP n'est pas proposé et aucune rétrogradation n'est possible.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : rôle strict, aucun champ TOTP ni à l'enrôlement ni au step-up ; `TestMFAActionStepUp_StrictRoleRequiresWebAuthn`.
- [x] D06 — Annulation de la cérémonie ou authentificateur indisponible : aucune injection et aucun fallback presse-papiers.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : cérémonie annulée (« Annuler ») → rien n'est tapé ; le presse-papiers n'est jamais touché par la page (compteur d'appels à zéro).
- [x] D07 — Les tests unitaires/mocks sont complétés par un test navigateur réel ; ne pas les présenter comme preuve d'une cérémonie réelle.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` (cette preuve, sur processus réels et navigateur réel, s'ajoute aux tests Vitest).

#### E — Grant et scope Vault

- [x] E01 — Challenge et grant sont générés avec `crypto/rand` ; seule leur empreinte SHA-256 est persistée.
  **Preuve** : `crypto/rand` et SHA-256 : `services/access/authentication/internal/application/mfa_action.go`, magasins `*_action_*_store.go` ; `TestMFAActionStepUp_TOTPProducesOnlyBoundSingleUseActionGrant` (grant opaque de 32 octets).
- [x] E02 — Grant limité à 30 secondes, lié au tuple complet et consommé atomiquement.
  **Preuve** : `TestMFAActionGrant_BindsEveryFieldExpiresAndCanBeConsumedOnce`, `TestMFAActionGrant_ExpiredGrantIsRefused` (mémoire et PostgreSQL).
- [x] E03 — Deux consommations concurrentes du même grant : une seule réussit.
  **Preuve** : `TestMFAActionGrant_ConcurrentConsumptionHasOneWinner` (mémoire et PostgreSQL).
- [x] E04 — Grant rejoué, expiré ou altéré : aucun scope Vault et aucun appel proxy.
  **Preuve** : `TestInjectVaultSecretWithStepUp_FailsClosedBeforeProxyWhenMFAConsumptionFails`, `TestSecretInjection_MFAFailureDoesNotReachProxy`.
- [x] E05 — Scope Vault lié au proxy propriétaire, au compte et à la session, à usage unique et limité à 15 secondes.
  **Preuve** : `SecretInjectionScopeTTL = 15 * time.Second` ; scope à usage unique et lié au proxy : `TestSSHFlow_EndToEnd_AcrossRealSeparateProcesses` (rejeu, mauvaise identité de proxy).
- [x] E06 — Un proxy différent, indisponible ou non joignable ne déclenche aucun failover privilégié.
  **Preuve** : affinité sans repli (ADR-0046) : `TestInjectVaultSecretWithStepUp_RoutesEverySupportedProtocolToItsProxyFamily`.
- [x] E07 — Le Broker ne reçoit jamais le credential ; le proxy l'obtient directement du Vault.
  **Preuve** : `TestInjectVaultSecretWithStepUp_KeepsGrantAndSecretOutOfGatewayAndBrokerProxyPayload`.
- [x] E08 — Hôte/utilisateur du credential différents du shell actif : refus avant frappe.
  **Preuve** : `TestSecretInputRegistry_RejectsCredentialForDifferentTargetAndPurges`.

#### F — Injection, audit et enregistrement

- [x] F01 — L'ordre observé est audit préalable acquitté → marqueur Command Recorder acquitté → frappe → résultat d'audit.
  **Preuve** : `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses` (événement préalable, marqueur, frappe, événement terminal) ; `TestSSHCodec_InjectsSecretOutsideOperatorRecording`.
- [x] F02 — Audit ou Recorder indisponible : aucune frappe.
  **Preuve** : `TestMFAActionStepUp_AuditFailureNeverReturnsChallengeOrGrant`, `TestStrictRecording_*`.
- [x] F03 — Le credential exact atteint l'oracle de la cible dans le test multi-processus SSH.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` (invite masquée de la cible) et `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses`.
- [x] F04 — Le credential est absent des réponses HTTP, logs Gateway/Broker/proxy/Vault/Recorder/Audit, traces et données enregistrées.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` (Gateway, Broker, proxy, Vault, Authentication, recorder, audit) et `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses`.
- [x] F05 — Le marqueur prouve la demande d'injection, sans contenir le secret, sa longueur, son empreinte ou un extrait.
  **Preuve** : `TestAuditSecretInputSendsOnlySafeEvidence`.
- [x] F06 — Le credential n'apparaît pas dans l'historique du client SSH ni dans les arguments de processus.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : ni le ticket ni le credential dans `/proc/<pid>/cmdline` de `ssh` ; rien du credential dans ce que reçoit OpenSSH (contre-épreuve : une cible qui renvoie la saisie → le test échoue).
- [x] F07 — Le presse-papiers n'est jamais consulté ni modifié par l'injection.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` : aucun appel à `navigator.clipboard` pendant tout le parcours.
- [x] F08 — Les buffers contrôlés sont purgés après usage et les erreurs n'exposent pas le secret.
  **Preuve** : `TestSSHCodec_PurgesCredentialAfterTargetAuthenticationWhileSessionRemainsActive`, `TestSecretInputRegistry_RejectsCredentialForDifferentTargetAndPurges`.
- [x] F09 — Perte de l'acquittement final après frappe possible : `outcome_unknown`, identifiant rapprochable, aucune seconde frappe automatique.
  **Preuve** : `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses` (accusé perdu → `outcome_unknown`, aucune seconde frappe).
- [x] F10 — Les erreurs d'injection sont distinguées de l'échec de connexion SSH ; une réponse ambiguë exige une vérification manuelle de la cible.
  **Preuve** : codes distincts : `409` (session non active), `403` (MFA refusée), `outcome_unknown` ; `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser`.

#### G — Chiffrement et frontières de confiance

- [x] G01 — SSH client-proxy et SSH proxy-cible sont deux sessions distinctes ; la documentation et les captures de trafic ne les décrivent pas comme un tunnel opaque.
  **Preuve** : §2 de cet ADR ; deux transports SSH distincts dans le code (`sshcodec`).
- [x] G02 — HTTPS protège le navigateur vers la Gateway ; mTLS TLS 1.3 protège les appels interservices.
  **Preuve** : `TestMTLS_TheWholeProductOverMutualTLS_AndItsAttackers_AcrossEightRealProcesses`.
- [x] G03 — Les identités de certificats mTLS sont vérifiées et les routes internes ont une allowlist stricte.
  **Preuve** : `TestCallerRules`, `TestEveryRegisteredRouteHasACaller` (proxy SSH), règles d'appelant d'Authentication.
- [x] G04 — Le secret Vault n'est jamais transmis à la Gateway, au navigateur, au client SSH ou au Session Broker.
  **Preuve** : `TestInjectVaultSecretWithStepUp_KeepsGrantAndSecretOutOfGatewayAndBrokerProxyPayload` ; `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` (réponses et journaux).
- [x] G05 — Le secret n'est transmis qu'au proxy propriétaire, puis dans le transport SSH chiffré vers la cible.
  **Preuve** : `TestSecretInputRegistry_FetchesFromVaultAndTypesOnlyIntoLiveTarget`.
- [x] G06 — Aucun secret, grant, scope ou preuve MFA n'apparaît dans les métriques, les traces ou les messages d'erreur.
  **Preuve** : journaux et réponses : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser`, `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses`. Le produit n'exporte ni métriques ni traces de ces flux aujourd'hui.

#### H — Révocation, concurrence et résilience

- [x] H01 — Révoquer la session avant le challenge : refus.
  **Preuve** : même contrôle d'état que H02 (`409 secret injection requires an active session`) ; `TestInjectVaultSecret_InactiveSessionDoesNotBurnVaultScope`.
- [x] H02 — Révoquer la session entre challenge et preuve : refus.
  **Preuve** : `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser`.
- [x] H03 — Révoquer pendant une frappe concurrente : établir les états permis, sans nouvelle frappe après acquittement de révocation.
  **Preuve** : `TestSecretInputRegistry_CancelsInFlightInjectionWhenSessionIsRevoked`, `TestSecretInputRegistry_DoesNotFetchAfterSessionContextIsCanceled` ; la course reste un risque P1 (H08).
- [x] H04 — Un proxy propriétaire indisponible n'entraîne pas de routage vers un autre proxy.
  **Preuve** : voir E06.
- [x] H05 — Une session ambiguë (plusieurs shells) est refusée.
  **Preuve** : `TestSecretInputRegistry_RefusesAmbiguousSessionWithMultipleShells`.
- [x] H06 — Les tests de concurrence sont répétés sous `-race` ; les tests d'intégration utilisent de vrais processus et PostgreSQL 16 dédié.
  **Preuve** : CI « Go / unit tests under -race » ; magasins de challenges et de grants éprouvés sous PostgreSQL 16 dans le job PostgreSQL.
- [x] H07 — Les tests Windows restent en CI uniquement ; aucun test Windows lourd n'est lancé localement.
  **Preuve** : aucun test Windows dans ce parcours.
- [ ] H08 — Les risques P1 de la revue STRIDE ADR-0097 sont soit traités avec preuve, soit explicitement acceptés par le propriétaire ; cet ADR ne les accepte pas par défaut.
  **Décision du propriétaire attendue** : course révocation/frappe (H03), copies mémoire Go/TLS/GC (ADR-0115), métadonnées de session si PostgreSQL est compromis (ADR-0116, non mis en œuvre). Aucun n'est accepté ici.

### 4 bis. État de la recette au 21 novembre 2026

- **Nouvelle preuve de bout en bout** : `test/integration/adr0134_openssh_webauthn_browser_test.go`, dans le job « Integration » (étape navigateur). Le parcours :
  - huit services en processus réels ;
  - un OpenSSH réel, dont la clé d'hôte du proxy est épinglée ;
  - l'Admin UI dans Chrome sans interface, avec l'enrôlement d'une clé puis le step-up par `navigator.credentials` et l'authentificateur virtuel de Chrome ;
  - une cible à invite masquée.

  Il vérifie la frappe, puis les refus (ticket rejoué, ticket d'une session terminée, assertion rejouée, signature altérée, cérémonie annulée, session terminée entre challenge et clé), et l'absence du ticket et du credential dans les arguments de `ssh`, dans ce qu'il reçoit et dans les journaux des sept services.
- **Contre-épreuves tuées** :
  - ticket non consommé ;
  - cible qui renvoie la saisie ;
  - les deux verrous anti-rejeu retirés ensemble (un seul retiré ne suffit pas : défense en profondeur) ;
  - signature non altérée ;
  - protocole retiré du lien du challenge (B03).
- **Ce que la preuve n'est pas** : la clé est l'authentificateur virtuel de Chrome, pas une clé matérielle. La cible est un serveur SSH de test, pas sudo sur un vrai système.
- **Défaut d'interface relevé, sans effet de sécurité** : après une fin de session, le détail ouvert dans l'Admin UI montre encore « Active » jusqu'à une nouvelle recherche. La saisie y est refusée (`409`), et le message le dit.
- **Restent** :
  - A06, une propriété de chaque déploiement ;
  - H08, les risques P1 d'ADR-0097, qui sont la décision du propriétaire ;
  - ~~le passage au statut `Accepté` (§5)~~ : décidé par le propriétaire le 21 novembre 2026.

### 5. Critères de sortie

L'ADR ne pourra passer à `Accepté` qu'après décision explicite du propriétaire. L'implémentation ne pourra être déclarée conforme à ce parcours qu'après :

1. validation de tous les critères applicables A à H, avec rapports et preuves reproductibles ;
2. test multi-processus OpenSSH → Gateway/Broker → SSH Proxy → Vault → cible → Command Recorder/Audit ;
3. preuve de TOTP et cérémonie WebAuthn réelle dans un navigateur, avec refus des attaques de rejeu et de substitution de contexte ;
4. tests négatifs et contre-épreuves pour chaque invariant de sécurité ;
5. tests `-race`, PostgreSQL 16 et CI complète, sans lancer les tests Windows localement ;
6. mise à jour des risques résiduels et des limites connues.

### 6. Conséquences

**(+) Éléments observés sur `main` au 21 novembre 2026**

- `POST /sessions/{sessionId}/connect` renvoie pour SSH un `proxyEndpoint` et un ticket à usage unique ; le ticket est consommé par le callback d'authentification SSH du proxy.
- Le test `TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses` démarre Gateway, Broker, Authentication, Authorization, Vault, SSH Proxy, Command Recorder et Audit comme processus distincts. Il crée une cible SSH de test, enrôle TOTP, crée et connecte une session, vérifie le challenge MFA, injecte le credential, observe la frappe côté cible, vérifie le marqueur, l'absence du credential dans les journaux et l'intégrité de la chaîne d'audit.
- Ce même test simule la perte d'un acquittement d'audit après commit : l'API retourne `outcome_unknown`, la cible ne reçoit pas une seconde frappe et le client doit s'abstenir de rejouer.
- L'Admin UI contient `SecretInjection` dans le détail d'une session active SSH/VNC/RDP ; le composant propose TOTP et WebAuthn selon les facteurs renvoyés, utilise `navigator.credentials.get` et n'expose ni credential, ni scope, ni grant.
- L'OpenAPI documente les deux routes publiques step-up et injection ; les contrats internes Authentication et proxy sont décrits dans `docs/api/grpc/README.md`.

**(−) Limites et risques qui restent ouverts**

- Les tests Vitest et le code UI ne constituaient pas à eux seuls une preuve de cérémonie WebAuthn réelle. Depuis le 21 novembre 2026, `TestADR0134_OpenSSHAndAWebAuthnStepUpInARealBrowser` en est une, avec l'authentificateur virtuel de Chrome. Aucune clé matérielle n'est éprouvée en CI.
- Le test SSH multi-processus utilise une cible SSH de test ; il ne prouve pas l'interopérabilité avec toutes les implémentations SSH, les invites applicatives ou tous les comportements de terminal.
- Le proxy ne sait pas si la cible attend une invite réellement masquée. Une saisie dans un champ visible peut apparaître dans le terminal ou l'enregistrement ; l'opérateur doit vérifier le focus et le masquage.
- Une frappe partielle peut avoir atteint la cible avant un échec ; elle ne peut pas être annulée. `outcome_unknown` exige une vérification manuelle.
- La course concurrente entre révocation et frappe reste un risque P1 dans la revue STRIDE ; l'absence de nouvelles frappes après acquittement ne prouve pas l'atomicité d'une frappe déjà en cours.
- Go, TLS et le ramasse-miettes peuvent conserver des copies transitoires que l'application ne peut pas garantir effacées ; voir ADR-0115.
- Un Broker, un proxy ou une identité mTLS compromise reste une compromission d'une frontière de confiance.
- Le parcours B (secret fourni par l'opérateur) est conçu pour RDP/VNC par ADR-0133 (ECDH P-256, HKDF-SHA-256 et AES-256-GCM pour le proxy), mais son implémentation et sa validation restent à réaliser. Cette conception protège contre une Gateway saine qui relaie le ciphertext, pas contre une Gateway compromise qui sert une UI modifiée. Elle ne définit pas de canal pour le parcours SSH de cet ADR.
- Le client SSH doit faire confiance à la clé d'hôte du proxy selon la configuration du déploiement ; cet ADR ne définit pas de nouveau mécanisme de distribution de cette clé.

### 7. Alternatives envisagées

- **Demander le mot de passe cible au client SSH :** rejeté, car il expose le secret à l'opérateur et contourne le Vault et l'injection contrôlée.
- **Faire saisir TOTP dans le terminal SSH :** rejeté, car le serveur SSH ne réalise pas une cérémonie MFA OpenBastion et mélangerait l'authentification de transport avec l'autorisation d'une action sensible.
- **Faire WebAuthn depuis OpenSSH :** rejeté, car un client SSH standard ne dispose pas de l'API WebAuthn du navigateur ; la cérémonie reste dans l'Admin UI.
- **Renvoyer le grant MFA ou le scope Vault au client :** rejeté, car ce sont des capacités internes à usage unique qui ne doivent pas sortir du plan de contrôle.
- **Faire transiter le credential par Gateway ou Broker :** rejeté par ADR-0003 et les policies de gestion des secrets.
- **Présenter le chemin comme un chiffrement E2E client-cible :** rejeté, car le proxy termine le transport client et initie un second transport indépendant.
- **Réessayer automatiquement une injection ambiguë :** rejeté, car une première frappe peut déjà avoir été reçue ; le rejeu pourrait exécuter deux fois l'action sur la cible.

## Références

- ADR-0003 — Les secrets ne traversent jamais le control plane.
- ADR-0008 — Enregistrer ou refuser une session.
- ADR-0010 — mTLS interne et identité issue du certificat.
- ADR-0018 — La terminaison réelle côté proxy.
- ADR-0039 — La clé d'hôte de chaque cible est épinglée au Vault.
- ADR-0046 — Plusieurs instances du proxy SSH et affinité/révocation.
- ADR-0062 — MFA TOTP.
- ADR-0065 — WebAuthn pour les rôles stricts.
- ADR-0097 — Un secret du Vault est saisi dans la session par le proxy.
- ADR-0112 et ADR-0113 — Rapprochement des injections depuis la chaîne d'audit et façade Admin UI.
- ADR-0115 — Réduire la vie des secrets en mémoire et interdire les core dumps.
- ADR-0116 — Attester les métadonnées de session hors de PostgreSQL.
- `docs/security/secret-injection-step-up-contract.md`
- `docs/security/threat-model-secret-injection-adr-0097.md`
- `docs/api/rest/openapi.yaml`
- `docs/api/grpc/README.md`
- `test/integration/secret_injection_flow_test.go`
- `web/admin-ui/src/features/sessions/SecretInjection.tsx`
