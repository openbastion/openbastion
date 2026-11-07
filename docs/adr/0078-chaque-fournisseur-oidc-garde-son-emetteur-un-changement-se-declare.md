# ADR-0078 — Chaque fournisseur OIDC garde son émetteur ; un changement se déclare

**Statut** `Accepté` · 7 novembre 2026 · go du propriétaire du projet le 7 novembre 2026 (« J'accepte ADR-0078 tel quel, go pour la mise en œuvre ») · amende ADR-0076 (et ADR-0035 pour les variables `OIDC_*`)

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

- (+) **Mesuré** (7 novembre 2026, `test/integration/issuer_binding_flow_test.go`, 5 à 7 s) : un Authentication Service réel, sous PostgreSQL, derrière une vraie Gateway, avec un vrai Audit Service et deux émetteurs de test au même `sub`. Les trois voies du tableau refusent maintenant de démarrer, en nommant le fournisseur, les deux émetteurs et la déclaration attendue. Un `previous_issuer` faux est refusé. L'audit coupé, le changement déclaré n'est pas fait. Déclaré depuis l'émetteur retenu, il est accepté : l'utilisateur retrouve son compte, et l'événement `auth.identity_provider_rebound` arrive à l'Audit Service quand la ligne porte encore l'ancien émetteur. Un `id` retiré puis redéclaré est refusé. Une entrée refusée n'en laisse aucune autre liée. Deux démarrages simultanés : un seul tourne, l'autre refuse. Neuf sous-tests verts ; deux mutations tuées sur ces processus (le garde-fou retiré, l'audit écrit après la ligne).
- (+) **Tests unitaires** : dix tests de la décision, cinq mutations sur cinq tuées (un changement non déclaré accepté, un changement depuis un autre émetteur accepté, un changement sans audit, l'audit écrit après la ligne, les nouvelles lignes gardées malgré un refus). **PostgreSQL** : deux tests (création unique, changement sur demande, annulation complète sur refus ; deux transactions simultanées voient le même émetteur), trois mutations sur trois tuées (validation malgré un refus, `Created` toujours vrai, mise à jour ignorée).
- (+) Le défaut mesuré dans les trois voies devient un refus de démarrer, qui dit pourquoi et comment en sortir. Un changement d'émetteur légitime reste possible, consigné à l'audit.
- (−) **Confiance au premier démarrage** : la première ligne retient l'émetteur configuré à ce moment-là. Une installation dont l'émetteur a déjà changé avant cette décision ne peut pas être détectée. Ses comptes restent tels qu'ils sont.
- (−) **Une déclaration n'est pas une preuve** : `previous_issuer` dit que le nouvel émetteur parle pour les mêmes `sub`. Une déclaration fausse redonne le défaut, mais consigné à l'audit, avec ses deux émetteurs.
- (−) **Disponibilité** : un changement déclaré demande que l'Audit Service réponde au démarrage. Aujourd'hui, l'Authentication Service démarre sans lui (seules les connexions échouent). Le premier enregistrement d'un émetteur, lui, n'en dépend pas : il ne fait que noter l'état existant, et il est journalisé.
- (−) **Une sauvegarde restaurée** d'avant un changement déclaré retient l'ancien émetteur. Le démarrage refuse alors, jusqu'à ce que le changement soit déclaré de nouveau. `docs/deployment/disaster-recovery.md` devra le dire.
- (−) **Les annuaires restent hors du garde-fou** (point 7). La limite les concernant reste dans `known-limitations.md`, réduite à eux.
- (−) Qui peut écrire dans la base de l'Authentication Service peut modifier la ligne sans passer par l'audit. C'est déjà le cas de toutes ses tables : hors du périmètre de cette décision.
- (−) **Un état de plus à opérer** : une table, une variable (`OIDC_PREVIOUS_ISSUER`), un champ de fichier (`previous_issuer`) et un événement d'audit à documenter (`docs/administration/identity-providers.md`, `docs/deployment/configuration.md`, `docs/deployment/troubleshooting.md`, `docs/architecture/data-architecture.md`).

**Précisions de mise en œuvre** (7 novembre 2026, sans changer la décision)

- **Tout ou rien, pour l'ensemble des fournisseurs** : toutes les lignes sont tenues et vérifiées dans une seule transaction, après les autres contrôles du démarrage. Un refus, et aucune ligne n'est créée ni changée, même pour les fournisseurs nouveaux : une faute de frappe dans un émetteur ne se retrouve pas retenue au démarrage suivant. Les changements déclarés ne sont écrits à l'audit qu'une fois toutes les vérifications passées.
- **Si la validation échoue après l'écriture à l'audit**, l'audit dit un changement qui n'a pas été retenu. Le démarrage suivant le refait et l'écrit de nouveau. C'est l'ordre de tout le dépôt : l'audit avant le geste, jamais l'inverse.
- **L'événement** : action `auth.identity_provider_rebound`, type `identity_provider`, ressource = l'`id` (`(variables)` pour le fournisseur `''`), détails `previous_issuer` et `issuer` (ADR-0068). Un émetteur de plus de 256 octets ne peut pas y être écrit : son changement est refusé.
- **`OIDC_PREVIOUS_ISSUER`** fait partie des variables `OIDC_*` exclues avec `IDENTITY_PROVIDERS_FILE`. Seule, sans OIDC configuré, elle fait refuser le démarrage.
- **Les tests d'intégration** démarrent leurs émetteurs sur des ports nouveaux à chaque passage. Ceux qui réutilisent un `id` fixe ou les variables oublient d'abord ce qu'un passage précédent a retenu. Les listes de purge du CI et de `make test-postgres` comprennent la table.

**Alternatives envisagées**

- **Refuser tout changement d'émetteur**, sans possibilité de déclaration (seul un nouvel identifiant) : écartée. Un fournisseur qui change seulement de nom de domaine rendrait tous ses comptes inaccessibles, avec leur MFA et leur historique, sans geste de reprise possible.
- **Une commande `openbastion-cli` pour déclarer le changement** : écartée. Le service refuse de démarrer tant que le changement n'est pas déclaré, et la CLI parle au service en marche. Il faudrait un accès direct à la base, hors du patron du dépôt.
- **Retenir l'émetteur sur chaque compte** (une colonne de `users`) : écartée. Les comptes existants n'ont pas d'émetteur connu à y écrire, donc même confiance au premier usage, ligne par ligne. Un changement déclaré réécrirait toutes les lignes du fournisseur, et chaque connexion ajouterait une comparaison.
- **Mettre l'émetteur dans le nom du compte** : déjà écartée par ADR-0076 (illisible, et le nom est gravé dans l'audit).
- **Avertir au lieu de refuser** : écartée. Défaut strict : un avertissement au journal laisse le nouvel émetteur se connecter aux comptes de l'ancien, ce qui est le défaut lui-même.
- **Couvrir aussi les annuaires par leur URL et leur base** : écartée pour l'instant (point 7). Un garde-fou sur l'identité de l'annuaire (son `domainSID`, par exemple) serait une autre décision.
