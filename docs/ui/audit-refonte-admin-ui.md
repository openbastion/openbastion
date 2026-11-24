# Audit — refonte de l'Admin UI

**Statut** Audit livré le 23 novembre 2026, **validé par Bony Kiss le 24 novembre 2026** avec ses cinq décisions (§7). Chiffres re-mesurés sur `2a177f47` le 24 novembre 2026. Aucun fichier n'a été modifié par l'audit.

## 0. Méthode, périmètre, limites

| Élément | Ce qui a été fait |
|---|---|
| Code lu | `web/admin-ui/src` (113 fichiers TS/TSX, 16 525 lignes), `web/packages/{ui,design-tokens,icons}` |
| Documents | `docs/ui/reference-screens/README.md`, `ecarts-admin-ui.md`, `docs/development/admin-ui-design-system.md`, `.agents/rules/frontend.md`, ADR-0036, ADR-0073, ADR-0075, ADR-0131 |
| Contrats | `docs/api/rest/openapi.yaml`, routes de `services/access/api-gateway/internal/interfaces/` |
| Non fait | Aucun test exécuté (pile arrêtée pendant l'audit) ; aucune capture navigateur ; aucune comparaison pixel à pixel avec les SVG. Les écarts de mise en page fine (espacements, couleurs exactes) ne sont pas mesurés ici. |

## 1. Ce que l'UI est aujourd'hui, mesuré

| Élément | Valeur |
|---|---|
| Destinations de premier niveau | 7 (`overview`, `accounts`, `sessions`, `infrastructure`, `security`, `posture`, `settings`) |
| Fichiers TS/TSX | 113, 16 525 lignes |
| Fichiers de tests | 37, 299 `it()` |
| Shell | `app/AppShell.tsx`, 552 lignes |
| Capacités appliquées | 18, catalogue ADR-0131 (comptes, politiques, sessions, secrets, enregistrements, injections) |
| Internationalisation | FR/EN paritaire, test de parité des clés |
| Références visuelles | 40 cadres Figma extraits ; 24 maquettes comparées écran par écran dans `ecarts-admin-ui.md` |

## 2. Trois constats qui commandent le reste

1. **Le routeur est interdit par deux ADR acceptés** : ADR-0036 règle 1 (« ni routeur ») et ADR-0073, dont l'alternative « introduire un routeur » est écartée au profit d'un ADR distinct si le besoin est démontré. La migration est donc bloquée jusqu'à l'acceptation de [l'ADR-0136](../adr/0136-navigation-adressable-de-l-admin-ui-avec-react-router.md).
2. **Le shell est monolithique et n'utilise pas le socle partagé** : `AppShell.tsx` (552 lignes) contient son propre piège de focus pour la navigation mobile et des restitutions de focus manuelles ; les primitives `Sidebar`, `Breadcrumb`, `Command`, `Sheet` et `Tooltip` de `@openbastion/ui` ne sont utilisées par **aucun** écran applicatif, seulement par leurs tests.
3. **La documentation d'écarts est périmée** : `ecarts-admin-ui.md` compare `main` à `8da45e3` et décrit comme manquants des comportements livrés depuis (état d'envoi, erreurs par champ, zone de texte, compteur de ticket, Annuler).

## 3. Défauts d'architecture d'information

- **Clés inversées** : l'onglet `security` affiche « Audit & conformité », l'onglet `posture` affiche « Sécurité » (`src/shared/i18n/locales/fr.ts`). Toute table de routes doit utiliser les noms de domaine (`audit`, `security`), pas les clés actuelles.
- **Onglet interdit = repli silencieux** sur Vue d'ensemble (`shownTab` dans `app/App.tsx`). Avec des URLs, un accès direct doit produire un 403 explicite, jamais un autre écran.

## 4. Documents périmés (à corriger dans l'incrément qui livre le code)

| Document | Problème constaté |
|---|---|
| `docs/ui/reference-screens/ecarts-admin-ui.md` | compare à `8da45e3` ; décrit comme manquants des comportements livrés (`SessionRequest` : envoi, erreurs par champ, `Textarea`, compteur de ticket, Annuler) ; ne mentionne pas le panneau de détail comme travail restant prioritaire |
| `docs/ui/reference-screens/README.md` | statuts « Partiel » à revalider ; « replay vidéo » présenté comme à faire alors qu'il est monté |
| `.agents/rules/frontend.md` règle 7 | cite `web/packages/design-tokens/tokens.css` et `src/app/styles.css` : aucun des deux n'existe (tokens dans `design-tokens/styles.css`) |
| `docs/development/admin-ui-design-system.md` (étapes 5 septies et 6) | « 21 fichiers, 194 tests » ; l'inventaire mesuré est 37 fichiers, 299 `it()` — chiffres à re-mesurer, pas à recopier |
| `AGENTS.md` (section Base44) | exacte sur l'environnement ; à compléter après la migration de routage (chemins `/ui/*`) |

## 5. Cible : navigation adressable

La décision, la table de routes complète et les gardes sont dans [l'ADR-0136](../adr/0136-navigation-adressable-de-l-admin-ui-avec-react-router.md). Trois points vérifiés ici :

- **Le repli SPA existe déjà** : `services/access/api-gateway/internal/interfaces/ui.go` sert `index.html` (`no-store`) pour tout chemin sans extension ; aucun changement serveur n'est nécessaire pour les liens profonds, et la CSP reste inchangée.
- **Le jeton reste en mémoire** (ADR-0036 règle 5) : recharger une URL affiche la connexion, puis la même URL rend l'écran demandé. C'est le comportement à tester, et il remplace le `history.replaceState("/ui/")` codé en dur de `OidcCallback`.
- **Une garde de route n'est pas une autorisation** : le serveur reste l'autorité (ADR-0131 §6) ; la page 403 nomme la capacité manquante et laisse la navigation intacte.

## 6. Plan d'implémentation incrémental

| # | Livrable | Contrôle de sortie | Réversibilité |
|---|---|---|---|
| 0 | **Audit commité** : ce document + corrections factuelles de `ecarts-admin-ui.md` | relecture propriétaire | revert d'un fichier |
| 1 | **ADR routage** : ADR-0136 + amendements 0036/0073 | ADR accepté | doc seule |
| 2 | **Baseline mesurée** : `make ui-test ui-build`, comptage tests/fichiers, captures 1440/768/320, inventaire des assertions de navigation | chiffres réels consignés | aucun code |
| 3 | **Shell — structure** : `AppShell*`, `AppSidebar*`, `AppNavigation*`, `AppHeader`, `AppBreadcrumbs`, `AppContent`, `AppPage` dans `@openbastion/ui` + tests package | tests package seuls, app inchangée | package non consommé |
| 4 | **Shell — interactions** : `AppCommandPalette`, `AppThemeProvider`, `AppUserMenu`, `AppWorkspaceSelector`, `AppMobileNavigation`, focus/clavier | tests focus, Échap, restitution, `Ctrl+K` | idem |
| 5 | **Shell — garde/erreurs** : `AppRouteGuard`, `AppLoadingState`, `AppErrorBoundary`, `AppNotificationProvider` | tests 403/500/chargement | idem |
| 6 | **Adoption du shell** (sans routeur) : `AppShell.tsx` de l'app remplacé par le shell du package + déclaration `app/navigation.ts` | parité : favoris, réduction, thème, densité, palette, pied de page, tests existants verts | retour au composant local |
| 7 | **Routeur plat** : `app/router.tsx`, 7 routes, `basename = BASE_URL`, `App` en layout, `onTab` → `navigate` | liens profonds, Précédent/Suivant, rechargement → connexion → même URL, 404 | retrait du routeur, retour aux onglets |
| 8 | **Gardes de route** : 403 explicite, redirection `/ui/` → `/ui/overview`, `ErrorBoundary` par route | tests par capacité, accès direct refusé | sans drapeau, revert du layout |
| 9 | **Sous-routes Accès** : ressources/comptes/politiques/demandes + `searchParams` filtres | URLs partageables, vues enregistrées intactes | routes conservées en redirections |
| 10 | **Sous-routes Sessions** : live/historique/enregistrements/replay/alertes + `/sessions/:id` | replay par URL, recherche par identifiant | idem |
| 11 | **Sous-routes Audit/Paramètres** : 4 + 5 sous-routes | onglets adressables | idem |
| 12 | **Écrans vs SVG** : par ordre de priorité des écarts (détail compte, demandes, replay SSH, colonnes, textes) | comparaison documentée écran par écran | par écran |
| 13 | **Tokens/identité** (si décidé) : palette officielle, logo, police | `ui-tokens-test` + décision ADR | tokens versionnés |
| 14 | **Clôture documentaire** : `ecarts-admin-ui.md`, README, `.agents/rules/frontend.md`, ADR à jour | docs = code au commit | doc seule |

Chaque incrément est livrable seul, sur sa branche, avec `make ui-test ui-build` et sa PR vers `main` ; aucun ne touche un contrat API, une capacité ou un invariant.

## 7. Cinq décisions validées le 24 novembre 2026

1. **ADR react-router** : rédigé ([ADR-0136](../adr/0136-navigation-adressable-de-l-admin-ui-avec-react-router.md)) ; son acceptation ouvre les incréments 7 à 11. Rester sans routeur les ferme.
2. **Périmètre du shell partagé** : composants génériques dans `@openbastion/ui`, avec `react-router` en peer dependency ; l'application fournit le routeur et la déclaration.
3. **Accès direct à une page interdite** : 403 explicite, au lieu du repli silencieux sur Vue d'ensemble.
4. **État dans l'URL** : filtres et onglets en `searchParams` ; rien de sensible en URL.
5. **Identité visuelle** : décision reportée à l'incrément 13 — palette Figma ou tokens actuels, Inter ou pile système, logo du package ou `BrandMark` ; choix réversible.
