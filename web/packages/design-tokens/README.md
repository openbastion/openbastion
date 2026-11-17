# @openbastion/design-tokens

Source CSS canonique de la charte OpenBastion Infrastructure (ADR-0073 et ADR-0075).

- `styles.css` est la feuille de style canonique : tokens primitifs et sémantiques, thèmes clair/sombre, primitives UI partagées et styles de shell.
- Admin UI et User Portal importent uniquement `@openbastion/design-tokens/styles.css`. Aucun stylesheet applicatif global parallèle ne doit être ajouté : les styles partagés sont centralisés ici.
- Les composants consomment les tokens sémantiques `--ob-color-*`, jamais les primitives.
- Le package ne contient aucun JavaScript exécuté dans le navigateur et aucune dépendance tierce.
- `npm run check:contrast` vérifie les paires de contraste opaques définies par la charte avec Node.js uniquement.
- `make ui-tokens-test` exécute aussi `scripts/check-app-colors.mjs`, qui interdit les couleurs littérales hors du package de tokens dans l'Admin UI, les primitives partagées et les icônes React.

Le package est privé au monorepo et distribué sous AGPL-3.0-only.
