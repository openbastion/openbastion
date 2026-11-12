# ADR-0096 — Le package d’icônes rejoint le socle frontend partagé

**Statut** `Accepté` · 12 novembre 2026 · décision demandée explicitement par le propriétaire du projet.

**Contexte** — Le package `@openbastion/icons` était isolé dans `web/openbastion-icons/`, alors que les tokens, primitives et autres bibliothèques communes sont regroupés sous `web/packages/`. Cette exception rendait l’arborescence, les montages Compose, les builds Docker, les contrôles de licence et les mises à jour de dépendances moins cohérents. L’ADR-0073, accepté, et les historiques antérieurs citent l’ancien emplacement ; un ADR accepté n’est pas réécrit.

**Décision**

1. Déplacer sans modifier le contenu fonctionnel le package vers `web/packages/icons/`. Le nom npm public reste `@openbastion/icons` et ses exports (`.`, `./styles.css`, `./assets/*`, `./package.json`) restent inchangés.
2. Faire pointer les dépendances locales `file:` vers `../packages/icons` et régénérer le lockfile Admin UI. Aucun changement de version ni de dépendance externe n’est introduit.
3. Mettre à jour les commandes Make, l’action de configuration Node, Dependabot, le contrôle des licences, le contrôle des couleurs, `deploy/base44/docker-compose.yml` et `deploy/docker-compose/Dockerfile`. Base44 consomme le package depuis le montage partagé `/packages`.
4. Mettre à jour l’arborescence de référence, le guide Design System, l’ADR-0075 encore proposé, le skill frontend et les instructions de développement. L’ADR-0073 et les journaux historiques qui décrivent l’état antérieur conservent leur chemin d’époque ; le présent ADR en est la référence de migration.
5. Conserver l’API publique du package et les imports TypeScript (`@openbastion/icons`) : seul son emplacement source dans le monorepo change.
6. Pour les travaux continus sur une branche longue, récupérer régulièrement `origin/main`, comparer la divergence et intégrer les changements de `main` avant de poursuivre ou de livrer un incrément. Ne jamais pousser directement sur `main` ni réécrire l’historique publié.

**Conséquences**

- (+) Une seule racine `web/packages/` rassemble les bibliothèques partagées. Les consommateurs npm gardent le même nom et les mêmes exports.
- (+) Les builds Docker et Base44 utilisent le nouvel emplacement ; les outils de dépendances, d’audit et de licence suivent le déplacement.
- (−) Tout script, montage ou documentation externe qui référence l’ancien chemin doit être mis à jour. Les anciens ADR et relevés historiques sont volontairement conservés tels qu’ils décrivaient la situation au moment de leur rédaction.
- (−) Le User Portal ne reçoit pas de nouvelle dépendance ni de parcours fonctionnel dans cet incrément.

**Alternatives envisagées**

- **Conserver `web/openbastion-icons/`** : écarté, car cela maintient une exception de structure sans bénéfice technique.
- **Renommer le package npm** : écarté, car cela casserait les imports publics sans nécessité ; `@openbastion/icons` reste stable.
