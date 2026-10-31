# Fédération d'identité

**Périmètre MVP — OIDC uniquement.** ~~La connexion à un fournisseur OIDC se configure via `oidc.issuerUrl`, `oidc.clientId` et `oidc.clientSecretRef` (`docs/deployment/docker-compose.md`). Le mapping des claims vers `username`/`displayName` suit la convention standard OIDC (`preferred_username`, `name`) — personnalisable via `oidc.claimsMapping` si votre IdP diverge.~~ Ce qui existe réellement (ADR-0035) :

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

*v1.0* — LDAP, Active Directory, Entra ID, SAML et SCIM seront configurables via des sections dédiées de `values.yaml`, chacune correspondant à son connecteur (`docs/architecture/system-overview.md`). Ce document sera mis à jour à leur livraison.
