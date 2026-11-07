# ADR-0078 — Chaque fournisseur OIDC garde son émetteur ; un changement se déclare

**Statut** `Proposé` · 7 novembre 2026 · `Accepté` seulement avec le go du propriétaire du projet, cité avec sa date · amende ADR-0076 (et ADR-0035 pour les variables `OIDC_*`)

**Contexte** — ADR-0076 lie un compte fédéré à l'**identifiant** de son fournisseur, pas à son émetteur. Sa limite restante, laissée « à décider », est donc toujours ouverte. **Mesuré sur `main` (`3159a68`)**, sous PostgreSQL, avec deux émetteurs de test qui donnent le même `sub`, chaque fois en redémarrant l'Authentication Service avec une autre configuration :

| Voie | Avant | Après | Même compte ? |
|---|---|---|---|
| Variables `OIDC_*` : `OIDC_ISSUER` passe de A à B | `oidc:<sub>` | `oidc:<sub>` | **oui** |
| Fichier : l'entrée `corp` passe de l'émetteur A à B | `oidc:corp:<sub>` | `oidc:corp:<sub>` | **oui** |
| Comptes faits par les variables (émetteur A), repris par une entrée d'émetteur B (`adopt_legacy_accounts`) | `oidc:<sub>` | `oidc:<sub>` | **oui** |

Dans les trois cas, l'utilisateur du nouvel émetteur hérite du compte de l'ancien : de son historique d'audit, de ses sessions passées, de ses facteurs MFA enrôlés. Ses rôles, eux, sont recalculés depuis la table. Il suffit d'une erreur de configuration, ou d'un émetteur qui distribue des `sub` déjà vus ailleurs. Rien ne le signale. La parade actuelle (déclarer un nouvel identifiant) repose sur la mémoire de l'administrateur.

Invariants touchés : l'identité qui décide est celle que le service vérifie ; défaut strict ; l'audit précède le geste. Écart connu : `docs/security/known-limitations.md`, ligne « Un fournisseur d'identité dont l'émetteur ou l'annuaire change garde ses comptes ».

**Décision**

1. **L'émetteur de chaque fournisseur OIDC est retenu.** Une table `identity_provider_bindings` (migration `007`, idempotente) : `provider TEXT PRIMARY KEY`, `issuer TEXT NOT NULL`, `bound_at TIMESTAMPTZ NOT NULL DEFAULT now()`. Le fournisseur des variables `OIDC_*` y est la ligne `''`, comme dans `users.identity_provider`. Les annuaires n'y figurent pas (voir le point 7).
2. **Au démarrage, chaque fournisseur OIDC est comparé à sa ligne**, dans une transaction (`INSERT … ON CONFLICT DO NOTHING`, puis `SELECT … FOR UPDATE`), pour que deux réplicas qui démarrent ensemble avec des fichiers différents ne s'accordent pas chacun raison. La comparaison est exacte, au caractère près, comme l'émetteur l'est déjà (ADR-0035) :
   - **aucune ligne** : l'émetteur configuré est retenu, et le démarrage le dit (`provider "corp" bound to issuer https://…`) ;
   - **le même émetteur** : rien ne change ;
   - **un autre émetteur** : le service **refuse de démarrer**. Le message nomme l'identifiant, l'émetteur retenu et celui configuré, puis les deux sorties prévues : déclarer un nouvel identifiant, ou déclarer le changement (point 3). Aucun compte n'est touché.
3. **Un changement d'émetteur se déclare, il ne se devine pas.** L'entrée du fichier prend `"previous_issuer": "<ancien émetteur>"`, et les variables prennent `OIDC_PREVIOUS_ISSUER`. Le changement n'est accepté que si cet ancien émetteur est **exactement** celui retenu. La ligne prend alors le nouvel émetteur. C'est la déclaration de l'administrateur que le nouvel émetteur parle pour les mêmes personnes, avec les mêmes `sub` (un fournisseur qui change de nom de domaine, par exemple). OpenBastion ne peut pas le vérifier ; il le consigne.
   - **L'audit précède le changement** : un événement `auth.identity_provider_rebound` (identifiant, ancien et nouvel émetteur) est écrit **avant** la mise à jour de la ligne. Si l'audit ne répond pas, la ligne n'est pas modifiée et le service refuse de démarrer.
   - Une fois la ligne à jour, `previous_issuer` est sans effet : sa valeur n'est plus celle retenue, et l'émetteur configuré l'est. Le démarrage invite à le retirer.
   - Un `previous_issuer` qui ne correspond pas à la ligne retenue est refusé, comme un émetteur changé sans déclaration.
4. **La reprise des comptes existants suit la même règle.** Une entrée qui déclare `adopt_legacy_accounts` reprend les comptes du fournisseur `''`. Si la ligne `''` existe, l'émetteur de cette entrée doit être exactement le sien, ou le déclarer par `previous_issuer` (point 3). Sinon, le service refuse de démarrer : c'est la troisième voie mesurée plus haut. Si la ligne `''` n'existe pas (une installation passée au fichier avant cette décision), l'émetteur de l'entrée qui reprend est retenu pour `''`, et le démarrage le signale.
5. **Retirer un fournisseur du fichier ne libère pas son identifiant.** Sa ligne reste. Le réutiliser plus tard pour un autre émetteur est refusé (point 2) : c'est la règle « jamais réutilisé » d'ADR-0076, désormais tenue par le service et plus seulement par la documentation.
6. **Ce qui ne change pas** : aucune route, aucun contrat public, aucun compte réécrit. Les lignes de `users` gardent leur clé `(identity_source, identity_provider, external_subject)`.
7. **Les annuaires ne sont pas couverts.** Leur clé de compte (`objectGUID`, `entryUUID`) est unique par construction, contrairement à un `sub` OIDC. Et leur adresse change dans l'exploitation ordinaire (un contrôleur de domaine remplacé, un équilibreur ajouté). Un garde-fou sur l'URL y refuserait surtout des démarrages légitimes.

**Preuve attendue** (processus réels, sous PostgreSQL ; chaque test avec sa contre-épreuve) :

- les trois voies du tableau, rejouées : le second démarrage **refuse**, et aucun jeton n'est émis pour le compte existant ;
- un changement déclaré avec le bon `previous_issuer` est accepté. L'utilisateur du nouvel émetteur retrouve son compte, et l'événement `auth.identity_provider_rebound` est dans la chaîne d'audit **avant** la ligne mise à jour ;
- un `previous_issuer` faux est refusé ;
- l'audit coupé pendant un changement déclaré : refus de démarrer, ligne inchangée ;
- deux processus qui démarrent ensemble avec deux émetteurs différents pour le même identifiant : un seul est retenu, l'autre processus refuse ;
- un identifiant retiré puis redéclaré avec un autre émetteur est refusé.

**Conséquences**

- (+) Le défaut mesuré dans les trois voies devient un refus de démarrer, qui dit pourquoi et comment en sortir. Un changement d'émetteur légitime reste possible, consigné à l'audit.
- (−) **Confiance au premier démarrage** : la première ligne retient l'émetteur configuré à ce moment-là. Une installation dont l'émetteur a déjà changé avant cette décision ne peut pas être détectée. Ses comptes restent tels qu'ils sont.
- (−) **Une déclaration n'est pas une preuve** : `previous_issuer` dit que le nouvel émetteur parle pour les mêmes `sub`. Une déclaration fausse redonne le défaut, mais consigné à l'audit, avec ses deux émetteurs.
- (−) **Disponibilité** : un changement déclaré demande que l'Audit Service réponde au démarrage. Aujourd'hui, l'Authentication Service démarre sans lui (seules les connexions échouent). Le premier enregistrement d'un émetteur, lui, n'en dépend pas : il ne fait que noter l'état existant, et il est journalisé.
- (−) **Une sauvegarde restaurée** d'avant un changement déclaré retient l'ancien émetteur. Le démarrage refuse alors, jusqu'à ce que le changement soit déclaré de nouveau. `docs/deployment/disaster-recovery.md` devra le dire.
- (−) **Les annuaires restent hors du garde-fou** (point 7). La limite les concernant reste dans `known-limitations.md`, réduite à eux.
- (−) Qui peut écrire dans la base de l'Authentication Service peut modifier la ligne sans passer par l'audit. C'est déjà le cas de toutes ses tables : hors du périmètre de cette décision.
- (−) **Un état de plus à opérer** : une table, une variable (`OIDC_PREVIOUS_ISSUER`), un champ de fichier (`previous_issuer`) et un événement d'audit à documenter (`docs/administration/identity-providers.md`, `docs/deployment/configuration.md`, `docs/deployment/troubleshooting.md`, `docs/architecture/data-architecture.md`).

**Alternatives envisagées**

- **Refuser tout changement d'émetteur**, sans possibilité de déclaration (seul un nouvel identifiant) : écartée. Un fournisseur qui change seulement de nom de domaine rendrait tous ses comptes inaccessibles, avec leur MFA et leur historique, sans geste de reprise possible.
- **Une commande `openbastion-cli` pour déclarer le changement** : écartée. Le service refuse de démarrer tant que le changement n'est pas déclaré, et la CLI parle au service en marche. Il faudrait un accès direct à la base, hors du patron du dépôt.
- **Retenir l'émetteur sur chaque compte** (une colonne de `users`) : écartée. Les comptes existants n'ont pas d'émetteur connu à y écrire, donc même confiance au premier usage, ligne par ligne. Un changement déclaré réécrirait toutes les lignes du fournisseur, et chaque connexion ajouterait une comparaison.
- **Mettre l'émetteur dans le nom du compte** : déjà écartée par ADR-0076 (illisible, et le nom est gravé dans l'audit).
- **Avertir au lieu de refuser** : écartée. Défaut strict : un avertissement au journal laisse le nouvel émetteur se connecter aux comptes de l'ancien, ce qui est le défaut lui-même.
- **Couvrir aussi les annuaires par leur URL et leur base** : écartée pour l'instant (point 7). Un garde-fou sur l'identité de l'annuaire (son `domainSID`, par exemple) serait une autre décision.
