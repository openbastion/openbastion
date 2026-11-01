# ADR-0065 — WebAuthn est un second facteur à côté de TOTP ; pour les rôles déclarés stricts, il est le seul qui compte, parce qu'il résiste à l'hameçonnage

**Statut** `Proposé` · 1ᵉʳ novembre 2026 · quatrième lot de la v0.0.1, choisi par Bony Kiss le 1ᵉʳ novembre 2026 avec deux décisions qui sont les siennes : `github.com/go-webauthn/webauthn` v0.18.2, et WebAuthn **second facteur à côté de TOTP, exigé pour les rôles stricts** ; `Accepté` seulement avec son go sur ce texte

**Contexte** — Le second facteur d'ADR-0062 est TOTP. Il arrête le vol d'un mot de passe seul, pas l'hameçonnage : un faux site qui relaie le mot de passe et le code dans la minute obtient le jeton (ADR-0062, limite écrite). WebAuthn (W3C, FIDO2 — clés de sécurité, passkeys, Windows Hello, Touch ID) lie chaque signature à l'**origine** que le navigateur a vue : une clé enrôlée pour `https://bastion.example` ne signe rien pour `https://bastion-example.evil`. La vérification (CBOR, COSE, attestations) se confie à `go-webauthn` v0.18.2 (BSD-3), accordé pour le seul module `authentication` ; il lie sept modules (go-webauthn/x, fxamacker/cbor, mapstructure, go-tpm, msgp, fwd, float16 — MIT, BSD-3 ou Apache-2.0), surveillés par `govulncheck` et Dependabot.

**Décision**

1. **La configuration**, facultative : `WEBAUTHN_RP_ID` (le domaine, `bastion.example`) et `WEBAUTHN_ORIGINS` (les origines exactes de l'Admin UI, `https://bastion.example` ; `http://localhost:<port>` seulement pour le développement, comme le permet WebAuthn) vont ensemble ; une origine qui n'est pas sous `WEBAUTHN_RP_ID` est refusée au démarrage. Sans elles, TOTP seul, comme aujourd'hui.
2. **Les rôles stricts** : `MFA_PHISHING_RESISTANT_ROLES` liste les rôles pour lesquels **seul WebAuthn compte** (par exemple `platform-admin`). Un tel rôle exige aussi un second facteur (il s'ajoute à `MFA_REQUIRED_ROLES`) ; la variable exige `WEBAUTHN_RP_ID`. Un compte qui porte un rôle strict et n'a que TOTP reçoit `enrollment_required` pour WebAuthn : son code TOTP ne lui donne plus de jeton.
3. **Le défi dit les facteurs admis** : `401 {"mfa": "required", "challenge", "factors": ["totp", "webauthn"], "webauthn": {options de la demande}}` — les options (le défi WebAuthn, les identifiants de clés du compte, `rpId`) sont faites à la vérification du mot de passe et gardées avec le défi (`mfa_challenges`). Pour un rôle strict, `factors` ne contient que `webauthn`, et `/auth/mfa/verify` (TOTP) refuse ce défi.
4. **La connexion** : `POST /auth/mfa/webauthn/verify` `{challenge, credential}` (la réponse de `navigator.credentials.get`) → le jeton, écrit d'abord à l'audit (`auth.login_webauthn`, ADR-0064). Sont vérifiés par `go-webauthn` : l'origine (dans `WEBAUTHN_ORIGINS`), le `rpIdHash`, la présence de l'utilisateur, le défi, la signature par la clé enregistrée ; et par OpenBastion : **un compteur de signatures qui recule** refuse la clé (clone), sauf s'il est toujours nul (beaucoup de passkeys).
5. **L'enrôlement**, avec le même code d'administrateur qu'ADR-0062 : `POST /auth/mfa/enroll` prend `factor: "totp" | "webauthn"` ; pour `webauthn` il rend les options de création (attestation `none` : pas de modèle de clé exigé, pas de donnée d'appareil gardée), puis `POST /auth/mfa/webauthn/enroll/confirm` `{challenge, credential}` enregistre la clé, brûle le code d'enrôlement, écrit `auth.mfa_webauthn_registered` à l'audit, et termine la connexion. **Une clé de plus** (une clé de secours) demande un nouveau code d'administrateur ; **5 clés** au plus par compte. Un compte enrôlé en TOTP peut ajouter WebAuthn par ce chemin (c'est ainsi qu'un rôle strict passe de TOTP à WebAuthn).
6. **Ce qui est gardé** : `mfa_webauthn_credentials` (migration `004_webauthn.sql`) — l'identifiant de la clé, sa clé publique, son compteur, son AAGUID, la date d'enrôlement, par compte. Une clé publique n'est pas un secret : elle n'est pas scellée. `mfa reset` efface aussi les clés WebAuthn du compte.
7. **L'Admin UI** appelle `navigator.credentials.create` et `.get` du navigateur (aucune dépendance) ; elle propose la clé de sécurité quand le défi l'admet, et la seule clé pour un rôle strict.
8. **Rien n'est écrit** : ni défi, ni signature, ni code d'enrôlement dans un journal ; ni clé publique dans l'audit (l'événement nomme le compte).

**Conséquences**

- (+) *À mesurer : rouge avant (un `platform-admin` strict se connecte avec TOTP ; aucune route WebAuthn), vert après sur processus réels avec un authentificateur logiciel écrit dans le test, indépendamment de la bibliothèque (clé ES256, attestation `none`, signatures) — enrôlement avec le code d'un administrateur, connexion, refus d'une origine étrangère (l'hameçonnage), d'un `rpId` étranger, d'une signature fausse, d'une clé d'un autre compte, d'un compteur qui recule, d'un défi rejoué ou épuisé, de TOTP pour un rôle strict ; cinq clés au plus ; remise à zéro ; audit ; rien au journal —, mutations.*
- (−) **Une dépendance de plus et sa surface** (un analyseur CBOR, des formats d'attestation) dans le module `authentication`.
- (−) **Attestation `none`** : n'importe quel authentificateur conforme est accepté ; restreindre aux modèles d'une liste (AAGUID, métadonnées FIDO) est un lot à part.
- (−) La vérification de l'utilisateur (code PIN, biométrie) est demandée « de préférence », pas exigée : le second facteur est la possession de la clé.
- (−) WebAuthn ne vaut que dans un navigateur, sur une origine déclarée : la CLI et l'API directe n'ont que TOTP (un rôle strict ne s'y connecte donc pas sans navigateur).
- (−) `WEBAUTHN_ORIGINS` doit suivre l'adresse publique de l'Admin UI : la changer sans la déclarer rend les clés inutilisables (pas les secrets TOTP).
- (−) Pas de passkey sans mot de passe : le mot de passe reste le premier facteur.

**Alternatives envisagées**

- **Une vérification maison sur la bibliothèque standard** (attestation `none` seulement) : écartée par Bony Kiss au profit de `go-webauthn` — un analyseur CBOR maison dans le chemin d'authentification, et aucun moyen futur de restreindre les modèles.
- **WebAuthn au choix pour tous** : écarté par Bony Kiss ; un administrateur pourrait rester sur TOTP, que l'hameçonnage contourne.
- **Passkeys sans mot de passe** : écarté pour ce lot ; un nouveau parcours de connexion, et la question des comptes d'annuaire.
- **Exiger l'attestation `direct`** : donne le modèle de clé, mais demande de garder et de juger des données d'appareil sans politique pour le faire.
