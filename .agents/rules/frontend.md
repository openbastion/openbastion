# Admin UI (`web/admin-ui`, ADR-0036)

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

1. React + Vite + TypeScript, versions exactes, lockfile commité, `npm ci`. Les applications fournissent React/React DOM et les peer dependencies Radix exigées par `@openbastion/ui` ; aucune autre dépendance UI ne doit être ajoutée hors du package partagé.
2. L'UI ne parle qu'à l'**API publique**, sur la même origine (servie par la Gateway sous `/ui/`) ; aucune origine tierce, aucun script en ligne : la CSP stricte de la Gateway ne se relâche pas pour l'UI.
3. Le jeton vit **en mémoire** seulement (jamais `localStorage`, `sessionStorage` ni cookie posé par l'UI) ; une seule instance d'`Api` est passée à `App` (`src/app/main.tsx`) — une valeur par défaut recréée à chaque rendu perdait le jeton.
4. Un secret saisi (secret initial d'un compte) est envoyé une fois, puis effacé du formulaire ; il n'est jamais affiché ni relu.
5. Tout ce qui vient de l'API est rendu **comme du texte** (jamais `dangerouslySetInnerHTML`) : un enregistrement de session contient ce qu'un opérateur a tapé.
6. Les refus de l'API sont affichés tels quels (`Notice`, rôle `alert`) ; les succès en rôle `status`.
7. Libellés en français ; composants React partagés depuis `@openbastion/ui`, tokens sémantiques depuis `web/packages/design-tokens/tokens.css`, styles partagés depuis `web/packages/ui/styles.css`, styles applicatifs dans `src/app/styles.css` ; formulaires étiquetés (`label`), utilisables au clavier. Les primitives simples sont natives ; Radix UI est réservé aux interactions complexes et reste encapsulé.
8. `BASE44_PREVIEW_MODE=1` est le **seul** drapeau qui change la configuration Vite (base `/` et relais vers la Gateway) ; sans lui, un `vite build` reste servi sous `/ui/`.
9. Tests : Vitest + Testing Library, avec `fakeApi` (`src/test-helpers.ts`) ; chaque écran a un test du cas heureux et du refus. `make ui-test ui-build` passe avant un commit qui touche l'UI.
