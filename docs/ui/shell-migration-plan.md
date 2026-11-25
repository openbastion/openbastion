# Plan de migration du shell local vers `@openbastion/ui/shell` (incréments 4 à 6)

**Statut** Préparation, aucun code modifié. Source : `web/admin-ui/src/app/AppShell.tsx` (552 lignes) et `web/packages/ui/src/shell/` (PR #305).

## 1. Ce que le package fournit déjà (structurel uniquement)

`AppShell` (grille `app-workspace`, backdrop mobile, `inert`, skip-link, pied), `AppSidebar` (+`Brand`, `Footer`, emplacements `context` et `userMenu`), `AppNavigation` (sections, favoris, ressources, `onSelect`, `onToggleFavorite`), `AppHeader` (emplacements `breadcrumbs`, `search`, `actions`), `AppBreadcrumbs`, `AppContent`, `AppPage`/`AppPageHead`, `AppBrandMark`. Le package ne gère **aucun état** : tout est passé par props.

## 2. Ce qui n'existe pas dans `packages/ui/src` (vérifié par recherche)

Aucun fichier ne contient : palette de commandes (seules les primitives `Command*` existent), thème, menu utilisateur, navigation mobile (ouverture/fermeture/focus), dialogue de confirmation applicatif (`AlertDialog` existe en primitive), `AppCapabilityButton`, `AppLoadingState` (`Skeleton` existe), `AppErrorBoundary`, `AppNotificationProvider` (`Toast`/`Toaster`/`use-toast` existent), 403/404 génériques. Ce sont les livrables des incréments 4 et 5. Côté application, leurs équivalents locaux sont `shared/ui/CommandPalette`, `ConfirmDialog`, `GatedButton`, `OperatorPreferencesDialog`, `InlineNotice`.

## 3. Comportements du shell local à préserver (inventaire du code)

| Comportement | Où dans `AppShell.tsx` | Cible |
|---|---|---|
| Préférences (thème, densité, favoris, sidebar repliée) lues/écrites via `operatorPreferences` | `useState(readOperatorPreferences)`, `updatePreferences` | reste dans l'app (métier) ; le package reçoit `collapsed`, les favoris |
| Thème `light/dark/system` + `matchMedia` → `data-theme`, densité → `data-density` | deux `useEffect` | `AppThemeProvider` (incrément 4), préférence fournie par l'app |
| Raccourcis : Ctrl/Meta+K (palette, actif dès le layout), Alt+Maj+1…6 (destinations), inhibés dans un champ de saisie ou une modale | `useLayoutEffect` | hook générique ; la table de destinations vient de `navigation.ts` |
| Focus : `main` après navigation ; retour au bouton de palette, de menu utilisateur, de préférences | 4 `useEffect` + refs `*WasOpen` | dans les composants d'interaction |
| Menu utilisateur : Échap, clic extérieur, retour du focus, thème, préférences, langue, déconnexion | `userMenuOpen` + écouteurs | `AppUserMenu` |
| Navigation mobile : dialogue modal, backdrop, `inert` sur l'en-tête, fermeture au choix | `mobileOpen` | `AppMobileNavigation` ; piège de focus et Échap **à vérifier** : le code actuel n'en contient pas de visible dans ce fichier, à tester avant de promettre |
| Notifications : panneau vide `role="status"` | `notificationsOpen` | `AppNotificationProvider` seulement si une source existe ; sinon conserver l'état vide |
| Sélecteur d'espace | voir `workspace-selector.md` | emplacement `context` de `AppSidebar` |
| Pied légal `LegalNotice`, lien d'aide externe, badge d'environnement | JSX | emplacements `footer`, `actions` |

## 4. Étapes proposées (une PR chacune)

1. **PR A (incrément 4a) — livrée sur la branche `admin-ui-refactor`** : `useAppTheme`/`AppThemeProvider`/`useEffectiveTheme` (`packages/ui/src/theme`) et `useAppShortcuts` (`hooks/use-app-shortcuts.ts`) ; `app/AppShell.tsx` les consomme (−≈70 lignes), tests `shared/ui-package-theme-shortcuts.test.tsx` (6) ; mesuré : 42 fichiers, 346 tests verts, JS 783,86 kB / 221,83 kB gzip (+0,22 kB). Les écouteurs lisent leurs callbacks à l'événement (plus de dépendances périmées). Contre-épreuve de mutation non faite. Objectif initial : extraire sans changer le rendu `AppThemeProvider` et le hook de raccourcis, avec les tests existants (`app.test.tsx`, `preferences.test.tsx`) inchangés et verts.
2. **PR B (4b)** : `AppUserMenu`, `AppMobileNavigation` (avec test de piège de focus/Échap écrit d'abord, rouge si absent), palette générique par-dessus `Command*`.
3. **PR C (5)** : `AppLoadingState`, `AppErrorBoundary`, `AppConfirmDialog`, `AppCapabilityButton`, `AppNotificationProvider`, pages de refus génériques ; aucune capacité métier dans le package.
4. **PR D (6)** : `app/AppShell.tsx` compose les composants du package ; suppression du code local dupliqué ; `ui-package-shell.test.tsx` complété.
5. **PR E (7)** : `react-router` (version exacte, peer dependency de `@openbastion/ui`), `navigation.ts`, `router.tsx`.

## 5. Risques

- Les écouteurs globaux (clavier, pointeur) dupliqués entre ancien et nouveau shell pendant une migration partielle : migrer un comportement à la fois, jamais deux implémentations actives.
- L'ordre `useLayoutEffect` de Ctrl/Meta+K a une raison documentée (fenêtre post-connexion) : le conserver tel quel.
- `tabOrder` indexe Alt+Maj+1…6 sur 7 destinations : la septième n'a pas de raccourci aujourd'hui ; comportement à conserver, pas à « corriger » sans décision.
- Le CSS passe par `design-tokens` : un changement exige `restart web` dans le sandbox.
