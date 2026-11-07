# ADR-0076 — Plusieurs fournisseurs d'identité à la fois, chaque compte lié au sien

**Statut** `Proposé` · 7 novembre 2026 · `Accepté` seulement avec le go du propriétaire du projet, cité avec sa date · amende ADR-0035 et ADR-0061

**Contexte** — Le deuxième critère de sortie de la v0.0.1 (`docs/roadmap.md` §3) demande « au moins trois fournisseurs d'identité externes fédérés simultanément en environnement de test ». L'Authentication Service n'en accepte que **deux** au plus : un seul émetteur OIDC (`OIDC_ISSUER`, ADR-0035) et un seul annuaire (`LDAP_URL`, en `ad` ou `rfc`, ADR-0061), chacun « tout ou rien ». OpenLDAP et Active Directory ne peuvent donc pas être servis en même temps.

Un défaut latent vient avec, **lu dans le code, pas encore mesuré**. Un compte fédéré est retrouvé par `(identity_source, external_subject)` (`migrations/002_oidc.sql`, `externalUser`), sans l'émetteur ni l'annuaire. Or un `sub` OIDC n'est unique que **chez son émetteur** (OpenID Connect Core §2). Si un administrateur remplace `OIDC_ISSUER` par un autre fournisseur, le `sub` `42` du nouveau retombe sur le compte `oidc:42` de l'ancien. Il hérite de son historique d'audit et de ses sessions passées ; ses rôles, eux, sont recalculés depuis la table, donc non hérités. Pour l'annuaire, `objectGUID` et `entryUUID` rendent une collision improbable, mais rien ne l'empêche. Avec plusieurs fournisseurs à la fois, cette confusion ne demanderait plus aucune erreur de l'administrateur : il suffirait d'un fournisseur hostile ou mal tenu.

Invariants touchés : l'identité qui décide est celle que le service vérifie, jamais un nom que le client choisit ; défaut strict ; aucun secret au journal.

**Décision**

1. **Chaque fournisseur a un identifiant** déclaré par l'administrateur : `[a-z0-9-]`, 1 à 32 caractères, unique tous types confondus, et jamais réutilisé pour un autre fournisseur (la documentation le dit : l'identifiant *est* le lien des comptes). Chaque fournisseur a aussi un libellé, affiché à l'écran de connexion (1 à 64 caractères imprimables).
2. **Un compte est lié à son fournisseur.** Une colonne `identity_provider` (`TEXT NOT NULL DEFAULT ''`) s'ajoute à `users`. L'index unique devient `(identity_source, identity_provider, external_subject)`. La migration `006` est idempotente : elle ajoute la colonne et le nouvel index, puis retire l'ancien. Aucune ligne n'est réécrite. Le nom d'un nouveau compte est `oidc:<fournisseur>:<sub>` ou `ldap:<fournisseur>:<guid>` : deux fournisseurs ne produisent jamais le même nom.
3. **La configuration est un fichier** : `IDENTITY_PROVIDERS_FILE`, en JSON, avec deux listes, `oidc` et `directories`. Chaque entrée reprend les champs et les contrôles actuels d'ADR-0035 ou d'ADR-0061, plus son identifiant, son libellé et sa propre table des groupes vers les rôles. Les secrets n'y sont jamais écrits : `client_secret_file` et `bind_password_file` désignent des fichiers en `0600`, comme `LDAP_BIND_PASSWORD_FILE` aujourd'hui. Au plus 16 fournisseurs.
4. **Tout ou rien, pour le fichier entier.** Le service refuse de démarrer dans chacun de ces cas, avec un message qui ne cite aucun secret :
   - une entrée invalide, ou un identifiant en double ;
   - deux entrées OIDC avec le même émetteur, ou deux annuaires avec le même `url` et la même base ;
   - un fournisseur injoignable au démarrage (comme aujourd'hui) ;
   - le fichier déclaré en même temps que des variables `OIDC_*` ou `LDAP_*`.
5. **Les variables actuelles restent valides**, pour un fournisseur de chaque type, d'identifiant vide `""`. Leurs comptes gardent leur nom (`oidc:<sub>`, `ldap:<guid>`) et sont retrouvés comme avant : rien ne change pour une installation existante. En passant au fichier, une entrée peut reprendre ces comptes par `"adopt_legacy_accounts": true`, au plus une par type. Sans cette déclaration, ils ne sont rattachés à aucun fournisseur et ne peuvent plus se connecter : défaut strict, et le démarrage le signale.
6. **Une table de rôles par fournisseur.** Un groupe déclaré pour un fournisseur ne donne rien à une identité d'un autre, même s'il porte le même nom ou le même DN.
7. **OIDC : le fournisseur est lié à la tentative.** `POST /auth/oidc/start` prend `{"provider": "<id>"}` (facultatif quand il n'y en a qu'un). La tentative, gardée côté serveur par son `state`, retient le fournisseur. `POST /auth/oidc/callback` échange le code **auprès de ce fournisseur seulement** et exige que l'`iss` du jeton soit exactement le sien. C'est la parade aux attaques de confusion entre fournisseurs (*mix-up*, RFC 9207) : un code ou un jeton d'un autre fournisseur est refusé (`401`). Chaque fournisseur a son URL de retour déclarée.
8. **Annuaire : l'utilisateur choisit, OpenBastion n'essaie jamais tour à tour.** `POST /auth/ldap/login` prend `"directory": "<id>"`. Ce champ est facultatif quand il n'y a qu'un annuaire, et obligatoire sinon : son absence donne un `400` avant tout réseau. Essayer chaque annuaire tour à tour enverrait le mot de passe d'un utilisateur à des annuaires qui ne sont pas le sien : c'est refusé par conception.
9. **Ce qui est public** : `GET /auth/oidc` et `GET /auth/ldap` donnent la liste `[{id, label}]`, rien d'autre (ni émetteur, ni URL, ni base). L'Admin UI propose un bouton par fournisseur. Les routes gardent le budget de connexion par adresse d'ADR-0014.
10. **L'audit** de chaque `auth.login` fédéré porte l'identifiant du fournisseur.

**Preuve attendue** (processus réels) : un vrai OpenLDAP, un vrai Samba AD et un émetteur OIDC, actifs **en même temps** sur un Authentication Service et une Gateway réels, sous PostgreSQL. Chacun connecte son utilisateur, avec les rôles de sa propre table. Tests d'attaque, chacun avec sa contre-épreuve :

- le même `sub` venu de deux émetteurs donne deux comptes distincts ;
- un groupe de même nom dans un autre fournisseur ne donne aucun rôle ;
- un `state` ouvert chez A et terminé avec un code de B est refusé ;
- une connexion annuaire sans `directory`, avec deux annuaires, est refusée sans qu'aucun annuaire ne reçoive de bind ;
- les comptes existants ne sont repris que par l'entrée qui le déclare ;
- un identifiant en double, ou le fichier mêlé aux variables, empêche le démarrage.

**Conséquences**

- (+) Le critère de sortie devient atteignable, et le lien compte–fournisseur ferme la confusion de `sub` entre émetteurs, y compris lors d'un changement d'émetteur.
- (+) Aucune donnée réécrite, aucune installation existante modifiée tant qu'elle garde ses variables.
- (−) **Contrat public élargi** : un champ facultatif sur trois routes et deux listes publiques. Rien n'est retiré, mais les libellés des fournisseurs deviennent lisibles sans connexion.
- (−) **Deux manières de configurer** tant que les variables restent valides ; leur retrait serait une autre décision.
- (−) Les comptes existants **non repris** deviennent inaccessibles en passant au fichier : c'est voulu, mais cela demande un geste explicite, et la documentation doit le dire en tête.
- (−) Un émetteur ou un annuaire injoignable au démarrage empêche de démarrer, et cela vaut désormais pour tous les autres fournisseurs. C'est le comportement actuel, étendu ; le changer serait une autre décision.
- (−) Le `sub` d'un fournisseur reste sa parole : un fournisseur hostile peut créer autant de comptes qu'il veut **chez lui**, mais aucun chez un autre.

**Alternatives envisagées**

- **Variables indexées** (`OIDC_1_ISSUER`, `LDAP_2_URL`…) : écartée. Illisible au-delà de deux fournisseurs, et sans structure pour les tables de rôles.
- **Essayer chaque annuaire tour à tour** : écartée. Le mot de passe partirait vers des annuaires qui ne sont pas celui de l'utilisateur.
- **Le fournisseur tiré de l'URL de l'émetteur** (empreinte) au lieu d'un identifiant déclaré : écartée. Illisible dans les noms, et l'URL d'un fournisseur peut changer sans qu'il change.
- **Renommer les comptes existants** en `oidc:<id>:<sub>` : écartée. Leur historique d'audit est écrit sous l'ancien nom et la chaîne ne se réécrit pas (ADR-0030).
- **Un Authentication Service par fournisseur** : écartée. Plusieurs clés de signature de jeton et plusieurs bases de comptes, pour une seule plateforme.
- **Un courtier d'identité externe** (Keycloak, Dex) devant OpenBastion : écartée. Un composant de plus à opérer, et la fédération reste hors d'OpenBastion, contrairement à la feuille de route ; il reste possible côté client, OpenBastion n'y voyant qu'un émetteur OIDC.
