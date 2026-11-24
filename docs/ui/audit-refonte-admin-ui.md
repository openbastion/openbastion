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

1. **Le routeur est interdit par deux ADR acceptés** : ADR-0036 règle 1 (« ni routeur ») et ADR-0073, dont l'alternative « introduire un routeur » est écartée au profit d'un ADR distinct si le besoin est démontré. La migration est donc bloquée jusqu'à l'acceptation de [l'ADR-0137](../adr/0137-navigation-adressable-de-l-admin-ui-avec-react-router.md).
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

La décision, la table de routes complète et les gardes sont dans [l'ADR-0137](../adr/0137-navigation-adressable-de-l-admin-ui-avec-react-router.md). Trois points vérifiés ici :

- **Le repli SPA existe déjà** : `services/access/api-gateway/internal/interfaces/ui.go` sert `index.html` (`no-store`) pour tout chemin sans extension ; aucun changement serveur n'est nécessaire pour les liens profonds, et la CSP reste inchangée.
- **Le jeton reste en mémoire** (ADR-0036 règle 5) : recharger une URL affiche la connexion, puis la même URL rend l'écran demandé. C'est le comportement à tester, et il remplace le `history.replaceState("/ui/")` codé en dur de `OidcCallback`.
- **Une garde de route n'est pas une autorisation** : le serveur reste l'autorité (ADR-0131 §6) ; la page 403 nomme la capacité manquante et laisse la navigation intacte.

## 6. Plan d'implémentation incrémental

| # | Livrable | Contrôle de sortie | Réversibilité |
|---|---|---|---|
| 0 | **Audit commité** : ce document + corrections factuelles de `ecarts-admin-ui.md` | relecture propriétaire | revert d'un fichier |
| 1 | **ADR routage** : ADR-0137 + amendements 0036/0073 | ADR proposé | doc seule |
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

1. **ADR react-router** : rédigé ([ADR-0137](../adr/0137-navigation-adressable-de-l-admin-ui-avec-react-router.md)) ; son acceptation ouvre les incréments 7 à 11. Rester sans routeur les ferme.
2. **Périmètre du shell partagé** : composants génériques dans `@openbastion/ui`, avec `react-router` en peer dependency ; l'application fournit le routeur et la déclaration.
3. **Accès direct à une page interdite** : 403 explicite, au lieu du repli silencieux sur Vue d'ensemble.
4. **État dans l'URL** : filtres et onglets en `searchParams` ; rien de sensible en URL.
5. **Identité visuelle** : décision reportée à l'incrément 13 — palette Figma ou tokens actuels, Inter ou pile système, logo du package ou `BrandMark` ; choix réversible.

## 8. Inventaire des composants monolithiques à extraire vers `@openbastion/ui`

Relevé sur cette branche (`admin-ui-baseline`), avant tout changement de code, sur `web/admin-ui/src/app/AppShell.tsx` (552 lignes) et `web/admin-ui/src/shared/`. Les plages de lignes désignent le fichier tel qu'il est au relevé ; elles servent à l'extraction, pas à une lecture durable.

### 8.1 `AppShell.tsx` — décomposition en dix blocs

| Lignes | Bloc actuel | Nature | Cible dans `@openbastion/ui` | Incrément |
|---|---|---|---|---|
| 42–66 | `tabs`, `groups`, `Tab`, `tabOrder` | déclaration de navigation de l'application | reste dans l'app : `app/navigation.ts` (ADR-0137 §3) | 6 |
| 68–72 | `isTextEntry` | utilitaire clavier (champ de saisie vs raccourci) | `lib/keyboard.ts` du package | 4 |
| 74–293 | état, préférences, thème, densité, raccourcis, focus, menus, piège de focus mobile | interactions et cycle de vie | `AppShell`, `AppThemeProvider`, `AppMobileNavigation` | 3–4 |
| 295–326 | `renderNavItem` | item de navigation, actif et favori | `AppNavigationItem` | 3 |
| 328 | lien d'évitement (`skip-link`) | structure | `AppShell` (prop `skipLink`) | 3 |
| 330–356 | palette `Ctrl+K` et dialogue de préférences | interactions | `AppCommandPalette` ; le dialogue de préférences reste dans l'app | 4 |
| 357–381 | `<aside>` : marque, titre, bouton replier | structure | `AppSidebar`, `AppSidebarBrand` | 3 |
| 382–405 | sélecteur d'espace de travail | interaction | `AppWorkspaceSelector` | 4 |
| 406–428 | `<nav>` : favoris, groupes, ressources | structure | `AppNavigation`, `AppNavigationGroup`, `AppNavigationResources` | 3 |
| 429–435 | pied de barre latérale (statut console) | structure | `AppSidebarFooter` | 3 |
| 436–479 | menu utilisateur (identité, langue, thème, préférences, déconnexion) | interaction | `AppUserMenu` | 4 |
| 480–542 | `<header>` : fil d'Ariane, déclencheur de recherche, badge d'environnement, notifications, aide, menu mobile | structure | `AppHeader`, `AppBreadcrumbs`, `AppHeaderActions` | 3 |
| 543–547 | `<main>` et bandeau capacités indisponibles | structure | `AppContent` (slot `banner`) | 3 |
| 548 | `LegalNotice` | pied de page | `AppShell` (slot `footer`) | 3 |

Contrat à conserver : le shell extrait rend les **mêmes** classes et rôles que l'actuel (`.app-workspace`, `.app-sidebar`, `.app-content`, `.app-header`, `.app-main`, `.nav-item`, `.nav-group`, `.sidebar-*`, `.legal-notice`, `role="complementary"` nommé, `role="navigation"` nommé, `main#main-content` en `tabIndex=-1`). C'est ce contrat que les tests existants pinent (voir §9.3), et c'est lui qui rend l'incrément 6 réversible.

### 8.2 Composants génériques de `shared/ui` et `shared/`

| Fichier | Lignes | Contenu | Décision |
|---|---|---|---|
| `shared/ui/AdminPage.tsx` | 68 | `AdminPage` + `PageHead` (cadre d'écran, consignations, actions) | → `AppPage` / `AppPageHead`, sans i18n : le libellé du dépliant des consignations passe en prop | 3 |
| `shared/BrandMark.tsx` | 12 | bouclier OpenBastion, décoratif | → `AppBrandMark` (motif paramétrable) ; la marque textuelle reste dans l'app | 3 |
| `shared/ui/ConfirmDialog.tsx` | 82 | confirmation destructive sur `Dialog` | → `AppConfirmDialog` | 4 |
| `shared/ui/CommandPalette.tsx` | 162 | palette : index local, filtre, clavier, focus | → `AppCommandPalette` générique ; l'app fournit l'index de commandes | 4 |
| `shared/ui/Modal.tsx` | 31 | enveloppe de `Dialog` (titre, description, fermeture) | doublon du primitif `Dialog` : supprimé au profit du package | 4 |
| `shared/ui/GatedButton.tsx` | 28 | bouton désactivé faute de capacité, avec explication | → `AppCapabilityButton` (garde/erreurs) | 5 |
| `shared/ui/FormCard.tsx` | 57 | carte de formulaire (titre, description, soumission) | → `AppFormCard` | 12 |
| `shared/ui/Pager.tsx` · `ReferencePager.tsx` | 33 · 65 | pagination simple et pagination de référence | → `AppPager` (une seule implémentation) | 12 |
| `shared/ui/ReferenceCard.tsx` · `ReferenceMetric.tsx` | 106 · 35 | carte et métrique de tableau de bord | restent dans l'app (présentation d'écran, pas de shell) | — |
| `shared/ui/OperatorPreferencesDialog.tsx` | 138 | préférences de l'opérateur | reste dans l'app ; ses champs viennent déjà du package | — |
| `shared/ui/LanguageSwitcher.tsx` | 28 | sélecteur de langue | reste dans l'app (i18n propre à l'application) | — |
| `shared/ui/StatusBadge.tsx` | 18 | badge de statut métier | reste dans l'app (mappe des statuts métier) | — |
| `shared/LegalNotice.tsx` | 33 | mentions AGPL et révision source | reste dans l'app (constantes de construction Vite) | — |

Les trois ré-exports d'une ligne (`Button.tsx`, `Badge.tsx`, `InlineNotice.tsx`) ne sont pas des composants monolithiques : ce sont des alias de compatibilité du package, à conserver.

### 8.3 Primitives du package déjà disponibles mais inutilisées

Vérifié : aucune occurrence hors tests dans `web/admin-ui/src`.

| Primitive | Fichier | Usage applicatif | Décision |
|---|---|---|---|
| `Sidebar` | `components/Sidebar.tsx` | 0 | socle de `AppSidebar` (incrément 3) |
| `Breadcrumb` | `components/Breadcrumb.tsx` | 0 | socle de `AppBreadcrumbs` (incrément 3) |
| `Command` | `components/Command.tsx` | 0 | socle de `AppCommandPalette` (incrément 4) |
| `Sheet` | `components/Sheet.tsx` | 0 | navigation mobile (incrément 4) |
| `Tooltip` | `components/Tooltip.tsx` | 0 | libellés des boutons icône (incrément 4) |

**Hors périmètre** : les écrans métier (`features/*`) et la déclaration de navigation restent dans l'application. Aucun composant de ce tableau ne change de comportement à l'extraction ; l'incrément 3 les livre dans le package sans que l'application les consomme.
