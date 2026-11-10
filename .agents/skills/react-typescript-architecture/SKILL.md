---
name: react-typescript-architecture
description: Structure et code de l'Admin UI d'OpenBastion (React 19, TypeScript, Vite) — à utiliser pour écrire ou réorganiser un écran, un client d'API ou un état dans web/admin-ui.
---

# Architecture React + TypeScript (Admin UI)

Règles : `rules/frontend.md`. Décision : ADR-0036.

## Structure

```
web/admin-ui/src/
  app/        App.tsx (routes, navigation), AppHeader.tsx (en-tête et sections), main.tsx (UNE instance d'Api), styles.css (variables CSS)
  features/   un dossier par écran : accounts/, sessions/, policies/, audit/, login/ — le conteneur de l'écran et ses composants
  shared/     api.ts (client, types et chemins de l'API publique), session.tsx (contexte connecté), Notice.tsx,
              ui/ (AdminPage, Pager, FormCard : la présentation partagée des écrans)
  test-helpers.ts   fakeApi, fakeToken
```

## À faire

- Un type TypeScript par ressource de l'API dans `shared/api.ts`, aligné sur l'OpenAPI (`docs/api/rest/openapi.yaml`) ; un champ ajouté côté API s'ajoute ici, optionnel s'il peut manquer (comptes antérieurs).
- L'accès à l'API passe par `useSignedIn().api.request(method, path, body?)` ; les identifiants dans un chemin passent par `encodeURIComponent`.
- Un geste qui écrit passe par une fonction `act(message, run)` locale à l'écran : efface les notices, attend, affiche succès ou erreur, recharge.
- État local (`useState`), chargement par `useCallback` + `useEffect` ; pas de bibliothèque d'état, pas de routeur tiers.

## À ne pas faire

- Recréer `Api` dans un rendu (valeur par défaut d'un paramètre de composant) : le jeton se perd — défaut réel déjà corrigé (`main.tsx`).
- Stocker le jeton ailleurs qu'en mémoire ; ajouter une dépendance d'exécution sans demander.
- `dangerouslySetInnerHTML`, `eval`, styles en ligne qui exigeraient d'assouplir la CSP.
