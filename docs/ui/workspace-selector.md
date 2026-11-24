# Sélecteur d'espace de travail de l'Admin UI — analyse et décision

**Statut** Analyse du code au 24 novembre 2026. Décision du propriétaire (option 1) : le sélecteur reste, sans chevron pour le moment, car des éléments de sélection viendront plus tard dans ce menu.

## 1. Fonctionnement actuel (`web/admin-ui/src/app/AppShell.tsx`)

- Un bouton `sidebar-workspace-card` (`aria-expanded`, `aria-controls="workspace-menu"`) affiche la marque d'environnement, le libellé **« Production »** et le sous-titre « Console d'administration » (clés i18n `shell.environment.production`, `shell.sidebar.workspaceContext`), plus un `ChevronDown`.
- Au clic, `workspaceMenuOpen` ouvre une région `workspace-menu` : légende « configuré », une seule entrée cochée (`Production`) et le texte `shell.environment.singleWorkspace`. Échap et clic extérieur (`.sidebar-workspace-selector`) le ferment.
- **Aucun espace de travail réel** : « Production » est un libellé en dur côté i18n. Aucun appel API, aucun contexte, aucune préférence, aucun filtrage des données par espace. Le badge `environment-badge` de l'en-tête répète la même chaîne.
- Test : `app.test.tsx` l'ouvre via son nom accessible (`Production … Console d'administration`).

## 2. Écart avec le produit

Le produit n'a pas de multi-espace (`openapi.yaml` n'expose aucun espace ni environnement). Le contrôle ressemble à un sélecteur, donc **promet** une fonction absente. C'est l'écart que la décision « option 1 » encadre : on le garde comme **indicateur de contexte**, honnêtement étiqueté (« un seul espace »), sans affordance de sélection.

## 3. Décision : migrer, ne pas refaire

| Option | Verdict |
|---|---|
| Migrer tel quel dans le slot `context` de `AppSidebar` | **Retenue.** Le composant est présentatif ; le package n'a rien à savoir de « Production ». |
| Refaire un vrai sélecteur (liste, persistance, filtrage) | Écartée : aucun contrat API ; ce serait un faux écran. Un ADR et un endpoint seraient requis. |
| Supprimer | Écartée : la maquette le montre et le propriétaire le garde. |

Migration : un `AppWorkspaceContext` générique dans `@openbastion/ui` (bouton + menu, props `label`, `description`, `items`, `value`, `menuLabel`, `emptyNote`), alimenté par l'application. Pour l'instant `items` n'a qu'une entrée, **sans chevron** (supprimer `ChevronDown` et `workspace-selector-chevron` à la migration, le chevron revenant avec ≥ 2 entrées). Le test existant reste valable : le nom accessible du bouton ne contient pas le chevron (`aria-hidden`).

## 4. À ne pas faire

Ne pas persister un « espace » dans `operatorPreferences`, ne pas l'envoyer à la Gateway, ne pas le mettre dans l'URL.
