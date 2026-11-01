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

*v0.0.1, à venir* — Entra ID, SAML et SCIM (`docs/architecture/system-overview.md`). Ce document sera mis à jour à leur livraison.
