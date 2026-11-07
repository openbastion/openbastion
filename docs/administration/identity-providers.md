# Fédération d'identité

**OIDC (ADR-0035) et annuaire LDAP/AD (ADR-0061).** ~~La connexion à un fournisseur OIDC se configure via `oidc.issuerUrl`, `oidc.clientId` et `oidc.clientSecretRef` (`docs/deployment/docker-compose.md`). Le mapping des claims vers `username`/`displayName` suit la convention standard OIDC (`preferred_username`, `name`) — personnalisable via `oidc.claimsMapping` si votre IdP diverge.~~ Ce qui existe réellement (ADR-0035) :

| Variable (Authentication Service) | Rôle |
|---|---|
| `OIDC_ISSUER` | L'émetteur, **exactement** tel que le fournisseur le dit dans `/.well-known/openid-configuration` ; `https` (ou `http` vers une adresse de boucle locale) |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Le client déclaré chez le fournisseur ; **le secret n'est jamais journalisé** |
| `OIDC_REDIRECT_URL` | L'URL de retour déclarée chez le fournisseur : la page qui reçoit `code` et `state` et les renvoie à `POST /auth/oidc/callback` |
| `OIDC_ROLE_MAP_FILE` | La table des groupes vers les rôles, JSON : `{"bastion-admins": ["platform-admin", "vault-admin"], "dbas": ["dba"]}` |
| `OIDC_GROUPS_CLAIM` | Le claim des groupes (`groups` par défaut) |

- **Tout ou rien** : une partie seulement des cinq premières variables, une table illisible ou mal formée, un fournisseur injoignable ou qui donne un autre émetteur — **refus de démarrer**. Sans aucune : connexion fédérée désactivée, annoncé au démarrage.
- **Le fournisseur ne décide pas des rôles** : un groupe absent de la table ne donne rien, même s'il porte le nom d'un rôle ; une identité sans rôle est refusée (`403`) et aucun compte n'est créé. Les rôles sont recalculés à chaque connexion : retirer quelqu'un d'un groupe chez le fournisseur lui retire le rôle **à sa prochaine connexion** — le jeton déjà émis vaut jusqu'à son expiration (1 h).
- **Le compte** s'appelle `oidc:<sub>` (jamais le nom choisi chez le fournisseur, qui pourrait être celui d'un compte local) ; il n'a pas de mot de passe ici. Les politiques visent des rôles : rien à créer par utilisateur.
- **Chaque connexion fédérée compte deux fois** dans le budget de connexion par adresse de la Gateway (`/auth/oidc/start` puis `/auth/oidc/callback`, ADR-0014) : derrière un proxy, déclarer `TRUSTED_PROXY_CIDRS`, sinon tous les utilisateurs partagent le budget du proxy.

## Annuaire LDAP ou Active Directory (ADR-0061)

Un utilisateur de l'annuaire se connecte avec **le mot de passe de l'annuaire**, par `POST /auth/ldap/login` (l'Admin UI propose « Annuaire de l'entreprise » dès que c'est activé). OpenBastion ne garde ni ne compare ce mot de passe : c'est l'annuaire qui le vérifie.

| Variable (Authentication Service) | Rôle |
|---|---|
| `LDAP_URL` | `ldaps://dc.example:636`, ou `ldap://dc.example:389` — **StartTLS toujours** : aucun mot de passe ne part en clair, même vers une adresse locale |
| `LDAP_CA_FILE` | Facultatif : l'autorité qui signe le certificat de l'annuaire (sinon, celles du système). La vérification n'est jamais désactivée |
| `LDAP_SCHEMA` | `ad` (Active Directory, Samba AD) ou `rfc` (OpenLDAP et compatibles) |
| `LDAP_BIND_DN` | Le compte de service qui **cherche** les utilisateurs et leurs groupes ; la lecture lui suffit |
| `LDAP_BIND_PASSWORD_FILE` | Son mot de passe, dans un fichier lisible par son seul propriétaire (`0600`), relu à chaque connexion : pour le changer, réécrivez le fichier |
| `LDAP_USER_BASE_DN`, `LDAP_GROUP_BASE_DN` | Où chercher les utilisateurs, et les groupes |
| `LDAP_ROLE_MAP_FILE` | La table des groupes vers les rôles, **par DN** : `{"CN=bastion-admins,CN=Users,DC=example,DC=com": ["platform-admin"]}` (casse et espaces indifférents) |

| `LDAP_SCHEMA` | Nom de connexion | Le compte OpenBastion | Groupes pris en compte |
|---|---|---|---|
| `ad` | `sAMAccountName` | `ldap:<objectGUID>` | directs **et imbriqués** ; un compte désactivé est refusé par l'annuaire |
| `rfc` | `uid` | `ldap:<entryUUID>` | `groupOfNames` (`member`) et `groupOfUniqueNames` (`uniqueMember`), directs seulement |

- **Tout ou rien** : une partie seulement des sept variables, une table illisible ou dont une clé n'est pas un DN, une URL qui n'est ni `ldaps` ni `ldap`, un fichier de mot de passe lisible par d'autres — **refus de démarrer**, sans le mot de passe dans le message. Sans aucune : désactivé, annoncé au démarrage.
- **Un annuaire qui ne répond pas au démarrage n'arrête pas le service** : la connexion locale, la porte de l'administrateur, doit rester ouverte. Le journal le dit (« the directory does not answer now »), et `/auth/ldap/login` répond `503` jusqu'à ce qu'il réponde. **Jamais** de repli sur un compte local.
- **L'annuaire ne décide pas des rôles** : un groupe absent de la table ne donne rien ; un utilisateur sans rôle est refusé (`403`) et aucun compte n'est créé. Les rôles sont recalculés à chaque connexion ; le jeton déjà émis vaut jusqu'à son expiration (1 h).
- **Le compte** s'appelle `ldap:<identifiant stable>`, jamais le nom de connexion (qui peut changer, ou être celui d'un compte local) ; il n'a pas de mot de passe ici et ne se connecte pas par `/auth/login`.
- **Chaque connexion compte dans le budget par adresse de la Gateway**, comme `/auth/login` ; chaque échec compte aussi pour **le verrouillage de l'annuaire** : réglez la politique de verrouillage de l'annuaire en le sachant.

Sur Active Directory, un compte de service en lecture seule suffit :

```text
LDAP_URL=ldaps://dc1.example.com:636
LDAP_SCHEMA=ad
LDAP_BIND_DN=CN=svc-bastion,OU=Service Accounts,DC=example,DC=com
LDAP_BIND_PASSWORD_FILE=/run/secrets/ldap-bind-password
LDAP_USER_BASE_DN=OU=People,DC=example,DC=com
LDAP_GROUP_BASE_DN=DC=example,DC=com
LDAP_ROLE_MAP_FILE=/etc/openbastion/ldap-roles.json
```

## Plusieurs fournisseurs à la fois (ADR-0076)

Les variables ci-dessus déclarent **un** émetteur OIDC et **un** annuaire. Pour en servir plusieurs en même temps (par exemple Active Directory, OpenLDAP et deux émetteurs OIDC), déclarez-les tous dans un fichier, `IDENTITY_PROVIDERS_FILE`, et retirez les variables `OIDC_*` et `LDAP_*` : **les deux ensemble, le service refuse de démarrer**.

> **Avant de passer au fichier : les comptes existants.** Les comptes créés par les variables (`oidc:<sub>`, `ldap:<identifiant>`) **ne peuvent plus se connecter** après le passage, sauf si une entrée les reprend avec `"adopt_legacy_accounts": true` (une entrée de chaque type au plus, et seulement celle **du même fournisseur** qu'avant : ADR-0078 refuse le démarrage sinon). Le démarrage dit combien de comptes ne sont repris par aucune entrée. Détail ci-dessous.

```json
{
  "oidc": [
    {"id": "corp", "label": "Compte Corp", "issuer": "https://login.corp.example", "client_id": "openbastion",
     "client_secret_file": "/run/secrets/corp-oidc-secret", "redirect_url": "https://bastion.example/ui/oidc/callback",
     "role_map_file": "/etc/openbastion/corp-roles.json", "groups_claim": "groups", "adopt_legacy_accounts": true}
  ],
  "directories": [
    {"id": "corp-ad", "label": "Active Directory", "url": "ldaps://dc1.example.com:636", "schema": "ad",
     "bind_dn": "CN=svc-bastion,OU=Service Accounts,DC=example,DC=com", "bind_password_file": "/run/secrets/ad-bind-password",
     "user_base_dn": "OU=People,DC=example,DC=com", "group_base_dn": "DC=example,DC=com", "role_map_file": "/etc/openbastion/ad-roles.json"},
    {"id": "labs", "label": "Annuaire des laboratoires", "url": "ldap://ldap.labs.example:389", "ca_file": "/etc/openbastion/labs-ca.pem",
     "schema": "rfc", "bind_dn": "cn=svc,dc=labs,dc=example", "bind_password_file": "/run/secrets/labs-bind-password",
     "user_base_dn": "ou=people,dc=labs,dc=example", "group_base_dn": "ou=groups,dc=labs,dc=example", "role_map_file": "/etc/openbastion/labs-roles.json"}
  ]
}
```

- **L'identifiant (`id`) lie les comptes à leur fournisseur** : `[a-z0-9-]`, 1 à 32 caractères, unique dans le fichier. **Ne le réutilisez jamais pour un autre fournisseur, et ne changez pas l'émetteur ou l'annuaire d'un identifiant existant** : les comptes de cet identifiant seraient ceux du nouveau. Pour un émetteur OIDC, le service le refuse au démarrage ([ci-dessous](#chaque-fournisseur-oidc-garde-son-émetteur-adr-0078)) ; pour un annuaire, rien ne l'en empêche. Pour un nouveau fournisseur, un nouvel identifiant. Le libellé (`label`, 1 à 64 caractères) est ce que l'écran de connexion affiche.
- **Les comptes** s'appellent `oidc:<id>:<sub>` et `ldap:<id>:<identifiant stable>` : le même `sub` chez deux émetteurs donne deux comptes. Les rôles viennent de la table de **ce** fournisseur seulement.
- **Les comptes existants** (créés par les variables) s'appellent `oidc:<sub>` et `ldap:<identifiant>`. En passant au fichier, **une entrée de chaque type au plus** peut les reprendre avec `"adopt_legacy_accounts": true`. Sans cette déclaration, ils ne peuvent plus se connecter, et le démarrage le dit (« made before ADR-0076 belong to no entry »). Ne reprenez les comptes qu'avec l'entrée **du même fournisseur** qu'avant.
- **Le fichier tout entier, ou rien** : une entrée invalide, un identifiant en double, deux entrées avec le même émetteur (ou le même annuaire et la même base), plus de 16 fournisseurs, une table illisible, un secret lisible par d'autres, un émetteur OIDC injoignable — **refus de démarrer**, sans aucun secret dans le message. Le fichier ne contient pas de secret, mais **il ne doit être modifiable que par son propriétaire** (`0644` au plus) : qui peut l'écrire peut déclarer un fournisseur qui donne `platform-admin`. Un annuaire injoignable, lui, n'arrête pas le service : ses connexions répondent `503`.
- **L'utilisateur choisit** : `POST /auth/oidc/start` prend `{"provider": "<id>"}` et `POST /auth/ldap/login` prend `"directory": "<id>"`, obligatoires dès qu'il y en a plusieurs (`400` sinon). OpenBastion n'essaie **jamais** les annuaires l'un après l'autre : le mot de passe d'un utilisateur ne part que vers l'annuaire qu'il a choisi. `GET /auth/oidc` et `GET /auth/ldap` donnent la liste `[{id, label}]` à l'écran de connexion, rien d'autre.
- **Le retour OIDC s'échange chez le fournisseur où la connexion a commencé**, jamais ailleurs : un code d'un autre fournisseur est refusé (`401`). Déclarez chez chaque fournisseur l'URL de retour de son entrée.
- **Second facteur** : le code d'enrôlement d'un compte d'annuaire du fichier se donne pour son annuaire, `openbastion-cli mfa enrollment-code -authn … -directory alice -directory-id corp-ad` ([`second-factor.md`](second-factor.md)).

## Chaque fournisseur OIDC garde son émetteur (ADR-0078)

Un `sub` n'est unique que chez son émetteur. Le service retient donc, au premier démarrage, l'émetteur de chaque fournisseur OIDC : celui de chaque `id` du fichier, et celui des variables `OIDC_*` (le fournisseur `''`). Le journal le dit (« bound to the issuer … »).

- **Un autre émetteur sous le même fournisseur fait refuser le démarrage.** Cela vaut pour `OIDC_ISSUER` changé, pour l'émetteur d'une entrée du fichier, et pour une entrée qui reprend les comptes des variables (`adopt_legacy_accounts`) sans être leur émetteur. Aucun compte n'est touché, et le message dit comment en sortir.
- **Un nouveau fournisseur prend un nouvel `id`.** Un `id` retiré du fichier n'est pas libéré : le redéclarer avec un autre émetteur est refusé.
- **Le même fournisseur sous une nouvelle URL** (un changement de nom de domaine, avec les mêmes `sub`) se déclare. Dans le fichier, ajoutez `"previous_issuer": "<l'émetteur retenu>"` à l'entrée ; avec les variables, `OIDC_PREVIOUS_ISSUER`. Le changement n'est accepté que si cet émetteur est **exactement** celui retenu. Il est écrit à l'audit (`auth.identity_provider_rebound`, avec les deux émetteurs) **avant** d'être retenu : **l'Audit Service doit répondre à ce démarrage-là**, sinon le service refuse de démarrer et rien ne change. Ensuite, retirez la déclaration (le journal le rappelle).
- **Déclarer un changement, c'est affirmer que le nouvel émetteur parle pour les mêmes personnes.** OpenBastion ne peut pas le vérifier ; il le consigne. Ne le déclarez pas pour un autre fournisseur.
- **Les annuaires ne sont pas concernés** : leurs comptes sont retrouvés par `objectGUID` ou `entryUUID`, uniques par construction, et leur adresse peut changer.
- **Le premier émetteur retenu est celui du premier démarrage avec cette version.** Un changement d'émetteur fait avant ne peut pas être détecté.

## Microsoft Entra ID (ADR-0079)

Entra ID est une entrée `oidc` du fichier, de profil `entra`, liée à **un** tenant déclaré. Le flux est celui d'OIDC (code d'autorisation, PKCE), avec les mêmes contrôles de jeton, le même verrou d'émetteur (ADR-0078) et une table de rôles propre à l'entrée.

```json
{"id": "corp-entra", "label": "Microsoft", "profile": "entra", "tenant_id": "11111111-2222-4333-8444-555555555555",
 "issuer": "https://login.microsoftonline.com/11111111-2222-4333-8444-555555555555/v2.0", "client_id": "<id de l'application>",
 "client_secret_file": "/run/secrets/entra-secret", "redirect_url": "https://bastion.example/ui/oidc/callback",
 "role_map_file": "/etc/openbastion/entra-roles.json"}
```

- **Un tenant, et son émetteur v2 exactement.** `tenant_id` est le GUID du tenant, en minuscules. `issuer` est `https://login.microsoftonline.com/<tenant_id>/v2.0`, au caractère près. `common`, `organizations`, `consumers`, un nom de domaine, l'émetteur v1 (`sts.windows.net`) ou celui d'un autre tenant : **refus de démarrer**. Un `tenant_id` sans `"profile": "entra"` aussi. Pour deux tenants, deux entrées : le même `sub` y donne deux comptes.
- **Chaque jeton doit porter ce tenant** (`tid`). Un jeton sans `tid`, ou d'un autre tenant, est refusé (`401`) avant toute création ou reprise de compte.
- **Les groupes viennent du jeton.** Déclarez-les dans l'application Entra (*Token configuration* → *Add groups claim*, ou `groupMembershipClaims` dans le manifeste) : OpenBastion ne demande pas de scope `groups`, et ne lit que le claim de groupes (`groups_claim`, `groups` par défaut). Les valeurs sont celles qu'Entra met dans le jeton, en général les identifiants (GUID) des groupes : ce sont eux que la table des rôles nomme.
- **Les rôles viennent de la table de l'entrée seulement.** Un claim `roles` ou un rôle d'application Entra ne donne rien. Un groupe absent de la table ne donne rien. Sans aucun groupe de la table : `403`, aucun compte.
- **Trop de groupes : refus.** Quand un utilisateur a plus de groupes qu'un jeton n'en porte, Entra remplace la liste par une référence à Microsoft Graph (`_claim_names`, `_claim_sources`, ou `hasgroups`). OpenBastion refuse alors la connexion (`401`) et **ne suit jamais** cette référence : aucune permission Graph n'est demandée. Réduisez les groupes émis (par exemple *Groups assigned to the application*) pour ces utilisateurs.
- **Les variables `OIDC_*` ne sont jamais Entra ID** : seul le fichier déclare ce profil.

*v0.0.1, à venir* — SAML et SCIM (`docs/architecture/system-overview.md`). Ce document sera mis à jour à leur livraison.
