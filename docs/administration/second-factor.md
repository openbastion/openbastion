# Second facteur (TOTP, ADR-0062)

Un compte **local ou d'annuaire** qui porte un rôle déclaré ne reçoit **aucun jeton** pour son seul mot de passe : il faut aussi le code à 6 chiffres de son application d'authentification (TOTP, RFC 6238 — Google Authenticator, Microsoft Authenticator, FreeOTP, 1Password, Bitwarden…). Les comptes OIDC gardent le second facteur de leur fournisseur (ADR-0035).

## Activer

| Variable (Authentication Service) | Rôle |
|---|---|
| `MFA_REQUIRED_ROLES` | Les rôles qui exigent le second facteur, séparés par des virgules : `platform-admin,vault-admin` |
| `MFA_SECRET_KEY_HEX` | La clé qui scelle les secrets TOTP en base (AES-256-GCM), **64 chiffres hexadécimaux**, gardée **hors de la base** : `openssl rand -hex 32` |

Les deux vont ensemble : l'une sans l'autre, une clé de mauvaise longueur ou un nom de rôle invalide, et le service **refuse de démarrer**, sans répéter la clé. Sans aucune des deux, rien ne change (le démarrage le dit). Le démarrage annonce les rôles concernés.

**Perdre `MFA_SECRET_KEY_HEX`, c'est perdre tous les secrets** : chaque compte concerné devra être remis à zéro puis réenrôlé. Sauvegardez-la comme `TOKEN_SIGNING_KEY_HEX`, ailleurs que la base.

## Enrôler un utilisateur

Un utilisateur sans second facteur qui se connecte reçoit `enrollment_required` : il lui faut **un code d'enrôlement émis par un administrateur**. Un mot de passe volé ne suffit donc pas à enrôler l'appareil d'un attaquant.

```sh
# un compte local, par son nom
openbastion-cli mfa enrollment-code -authn https://authentication:8086 -local alice
# un compte d'annuaire, par son nom de connexion (sAMAccountName ou uid) : le compte ldap:<id>
# n'existe qu'après sa première connexion
openbastion-cli mfa enrollment-code -authn https://authentication:8086 -directory alice
```

Le code est **affiché une seule fois**, vaut **24 heures**, sert **une fois** ; un nouveau code annule le précédent. Remettez-le à l'utilisateur **par un autre canal** que son mot de passe (en personne, par téléphone). L'utilisateur saisit ce code dans l'Admin UI, reçoit son secret (base32 et URI `otpauth://`, à recopier dans son application : pas de QR code), puis saisit un premier code pour confirmer. Le code d'enrôlement est alors brûlé.

Un compte déjà enrôlé ne peut pas être réenrôlé, même avec un code valable : il faut d'abord une remise à zéro.

## Appareil perdu

```sh
openbastion-cli mfa reset -authn https://authentication:8086 -username alice     # ldap:<id> pour un compte d'annuaire
```

Le secret est oublié ; l'utilisateur se réenrôle avec un nouveau code. Il n'y a pas de codes de secours.

## Ce que l'utilisateur voit, et les règles

- `POST /auth/login` (ou `/auth/ldap/login`) répond **`401`** avec `{"mfa": "required" | "enrollment_required", "challenge": …, "expiresIn": 300}` quand le mot de passe est bon : un client qui ne connaît pas le second facteur voit un refus. Puis `POST /auth/mfa/verify`, ou `/auth/mfa/enroll` et `/auth/mfa/enroll/confirm`.
- Le défi vaut **5 minutes** et **5 essais** ; ensuite il faut retaper le mot de passe. Chaque étape compte dans le budget de connexion par adresse de la Gateway.
- Un code vaut **±30 s** autour de l'heure du serveur, et **ne sert qu'une fois**.
- Les rôles du jeton sont ceux de la vérification du mot de passe.
- Ni le secret, ni un code, ni un défi n'est écrit dans un journal. L'émission d'un code et la remise à zéro sont écrites **au journal du service** (qui, pour quel compte), **pas encore à l'audit**.
