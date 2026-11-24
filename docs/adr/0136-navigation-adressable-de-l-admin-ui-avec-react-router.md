# ADR-0136 — La navigation de l'Admin UI devient adressable, avec `react-router`, une déclaration unique et des refus explicites

**Statut** `Proposé` · 24 novembre 2026 · `Accepté` seulement avec le go du propriétaire du projet, cité avec sa date. L'audit de la refonte et ses cinq décisions ont été validés par Bony Kiss le 24 novembre 2026 ; cet ADR fixe la première des cinq, le routage.

**Contexte** — L'Admin UI garde sa destination dans un état React (`Tab`, `app/App.tsx`), pas dans une URL. Mesuré sur `2a177f47` : 7 destinations, 113 fichiers TS/TSX (16 525 lignes), 37 fichiers de tests (299 `it()`), `app/AppShell.tsx` 552 lignes, 18 capacités du catalogue de l'ADR-0131.

Trois conséquences observées :

- une destination ne se partage pas, ne survit pas à un rechargement, et les boutons Précédent/Suivant ne reviennent pas à l'écran précédent ;
- les onglets d'Accès privilégiés, de Sessions, d'Audit & conformité et de Paramètres, ainsi que les filtres, ne sont pas adressables ;
- une destination interdite retombe silencieusement sur Vue d'ensemble (`shownTab`) : un lien direct vers une page non autorisée afficherait un autre écran sans explication.

Le shell reste monolithique : `AppShell.tsx` (552 lignes) porte son propre piège de focus pour la navigation mobile et des restitutions de focus manuelles, et les primitives `Sidebar`, `Breadcrumb`, `Command`, `Sheet` et `Tooltip` de `@openbastion/ui` ne sont utilisées par aucun écran applicatif — seulement par leurs propres tests.

Deux ADR acceptés interdisent aujourd'hui le routeur : l'ADR-0036 règle 1 (« ni routeur ») et l'ADR-0073, qui écarte l'introduction d'un routeur en réservant un ADR distinct à un besoin démontré. L'audit [`docs/ui/audit-refonte-admin-ui.md`](../ui/audit-refonte-admin-ui.md) démontre ce besoin ; le présent ADR le tranche.

Rien à changer côté serveur : `services/access/api-gateway/internal/interfaces/ui.go` sert déjà `index.html` (`no-store`) pour tout chemin sans extension, donc `/ui/access/accounts` rend la page. La CSP ne bouge pas.

**Décision**

1. **Une seule dépendance de routage : `react-router`, en mode bibliothèque.** Version exacte épinglée dans `package.json` et `package-lock.json`, `npm ci`. Elle est ajoutée aux dépendances de `web/admin-ui` et aux `peerDependencies` de `@openbastion/ui` ; le package ne crée aucun routeur et n'impose aucune instance : l'application fournit le routeur et la déclaration. Aucune autre dépendance n'est ajoutée — ni gestionnaire d'état, ni framework CSS. *Amende l'ADR-0036 règle 1 et l'ADR-0073.*
2. **`basename = import.meta.env.BASE_URL`** : `/ui/` quand la Gateway sert l'interface, `/` sous `BASE44_PREVIEW_MODE=1`. Aucun chemin absolu n'est écrit en dur.
3. **Une déclaration unique**, `web/admin-ui/src/app/navigation.ts` : chaque destination porte son chemin, ses clés de libellé, son icône, sa capacité requise, son groupe et ses sous-routes. La barre latérale, la palette `Ctrl+K`/`Cmd+K`, le fil d'Ariane, les raccourcis clavier et les gardes de route en dérivent. Aucune seconde table de navigation.
4. **Table de routes cible**, livrée par incréments (7 à 11 de l'audit) :

| URL | Écran | Garde |
|---|---|---|
| `/ui/login` | `Login` | anonyme |
| `/ui/mfa` | `SecondFactor` (état de challenge en mémoire) | challenge en cours |
| `/ui/oidc/callback` | `OidcCallback` | anonyme |
| `/ui/` → `/ui/overview` | redirection | — |
| `/ui/overview` | `Overview` | jeton |
| `/ui/access` → `/ui/access/resources` | `Accounts` onglet Ressources | `accounts.list` |
| `/ui/access/accounts` | onglet Comptes | `accounts.list` |
| `/ui/access/accounts/:accountId` *(avec l'incrément détail)* | panneau de détail | `accounts.list` |
| `/ui/access/accounts/onboard` | `OnboardAccount` | `accounts.onboard` |
| `/ui/access/policies` | `PolicyForm` | `policies.create` |
| `/ui/access/requests` | Demandes | `sessions.approve` |
| `/ui/sessions` → `/ui/sessions/live` | `Sessions` En direct | jeton |
| `/ui/sessions/history` | `SessionHistory` | jeton |
| `/ui/sessions/recordings` · `/ui/sessions/recordings/:sessionId` | Enregistrements + replay | `recordings.read` |
| `/ui/sessions/alerts` | `SessionAlerts` | jeton |
| `/ui/sessions/:sessionId` | détail (panneau) | jeton |
| `/ui/infrastructure` | `Infrastructure` | jeton |
| `/ui/audit` → `/ui/audit/journal` · `/reports` · `/evidence` · `/retention` | `AuditCompliance` | jeton |
| `/ui/security` | `SecurityCenter` | `accounts.list` |
| `/ui/settings` → `/general` · `/security` · `/identities` · `/integrations` · `/notifications` | `Settings` | jeton |
| `*` | **404** | — |

   Règles : aucune route pour une fonction absente (le détail de compte n'arrive qu'avec son panneau) ; les onglets déjà livrés deviennent des sous-routes ; les filtres persistants passent en `searchParams` ; les noms de domaine sont `audit` et `security` — pas les clés actuelles, inversées.
5. **Refus explicites** : `AuthGate` (jeton en mémoire) → `CapabilityGate` (capacité manquante : page 403 nommant la capacité, navigation inchangée) → écran ; un `AppErrorBoundary` par route ; chemin inconnu : 404. Une garde de route n'est jamais une protection : le serveur reste l'autorité (ADR-0131 §6).
6. **L'état vit dans l'URL** : onglets et filtres en `searchParams` (`?protocol=ssh&rule=…`, `?from=&to=&status=`). Jamais de secret, de jeton, d'identifiant de session ni de recherche libre au-delà de ce qui est déjà visible et non sensible (ADR-0073 §6) ; l'état de dialogue reste local.
7. **Le rechargement passe par la connexion** : le jeton vit en mémoire (ADR-0036 règle 5). Recharger `/ui/access/accounts` affiche la connexion, puis **la même URL** rend l'écran demandé. Cela remplace le `history.replaceState("/ui/")` codé en dur de `OidcCallback`.
8. **Le shell partagé rejoint `@openbastion/ui`** : structure (`AppShell`, `AppSidebar`, `AppHeader`, `AppBreadcrumbs`, `AppContent`, `AppPage`), interactions (palette, thèmes, menu utilisateur, sélecteur d'espace, navigation mobile, focus) et gardes/erreurs (`AppRouteGuard`, `AppLoadingState`, `AppErrorBoundary`, `AppNotificationProvider`). L'`AppShell.tsx` de l'application est remplacé à l'incrément 6, en conservant favoris, réduction, thème, densité, palette, pied de page et les tests existants.
9. **Réversibilité** : chaque incrément se livre seul, sur sa branche, avec `make ui-test ui-build` ; retirer le routeur ramène les onglets en état React.

**Conséquences**

- (+) **Mesuré** : le diagnostic ci-dessus (7 destinations, 113 fichiers, 16 525 lignes, 37 fichiers de tests, 299 `it()`, 552 lignes de shell, 18 capacités) ; le repli SPA existe déjà et est testé côté Go (ADR-0036) — aucun changement serveur, aucun élargissement de CSP, aucun appel hors Gateway n'est nécessaire.
- (+) **Attendu, à mesurer aux incréments 7 à 11** : liens profonds, Précédent/Suivant, filtres partageables, 403 et 404 explicites, une seule déclaration de navigation pour la barre latérale, la palette, le fil d'Ariane et les gardes ; le shell partagé réutilise les primitives déjà testées du package. Ces gains ne sont pas encore constatés par un test : aucun code n'est modifié par cet ADR.
- (−) Une dépendance d'exécution de plus ; la taille du bundle augmentera — à mesurer à l'incrément 7, pas estimée ici.
- (−) Le jeton en mémoire : un lien profond passe **toujours** par la connexion, et un rechargement déconnecte. L'URL est restituée après authentification, jamais avant.
- (−) Une garde de route ne protège rien : le serveur décide (ADR-0131 §6) ; une page masquée n'est pas une ressource inaccessible.
- (−) Les capacités sont lues une fois par jeton : la page 403 reflète le jeton courant, pas une politique changée depuis la connexion.
- (−) Aucune route pour une fonction absente : le détail de compte attend son panneau (incrément 12), et les écrans sans contrat API restent des onglets « indisponible ».
- (−) Les tests de navigation existants doivent être réécrits, jamais supprimés ni affaiblis ; `make ui-test ui-build` reste vert à chaque incrément.
- (−) `react-router` en peer dependency : un consommateur de `@openbastion/ui` sans cette dépendance échoue à la construction, pas silencieusement.
- (−) Aucun changement d'API, de Gateway, de CSP ni de gestion du jeton. `.agents/rules/frontend.md` règle 1 et l'invariant ADR-0036 de `.agents/architecture/invariants.md` (« à l'exécution React seulement ») sont mis à jour quand la dépendance entre réellement (incrément 7).

**Alternatives envisagées**

- **Rester sans routeur** (onglets en état React) : écarté — pas de lien profond, pas de Précédent/Suivant, pas de filtre partageable ; les incréments 7 à 11 de l'audit se ferment.
- **Shell router-agnostique à base de `renderLink`** : écarté par le propriétaire — une indirection de plus pour le même résultat ; le shell a besoin de l'historique et de la localisation, et la peer dependency le dit explicitement.
- **Routage par ancre (`#/access/accounts`)** : écarté — le repli SPA existe et est testé, une seconde grammaire d'URL n'apporte rien et n'exercerait pas le chemin réel.
- **Routes serveur par écran** : écarté — un contrat serveur de plus, une surface de plus, aucun bénéfice.
- **Un gestionnaire d'état tiers avec le routeur** : écarté — l'URL porte l'état de navigation ; les préférences restent dans le stockage local existant.
