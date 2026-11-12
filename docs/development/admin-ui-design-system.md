# Design System — OpenBastion Infrastructure

**Périmètre :** Admin UI et socle visuel partagé avec le User Portal
**Décisions de référence :** ADR-0073 §3 et ADR-0075 §3
**État :** charte produit sélectionnée ; implémentation progressive

## 1. Direction artistique et ergonomique

**OpenBastion Infrastructure** est une identité de console d'exploitation : précise, structurée, dense sans être chargée, et conçue pour des opérateurs qui doivent comparer des ressources, repérer un état anormal et agir sans ambiguïté.

La direction est proche de l'expérience ergonomique de consoles d'infrastructure telles que UniFi Network : navigation latérale persistante, hiérarchie stable, tableaux informatifs, filtres explicites, états compréhensibles et interactions prévisibles. La référence est limitée à ces qualités fonctionnelles. OpenBastion conserve une identité originale : aucun logo, code, icône, capture, texte propriétaire, illustration ou composition distinctive d'un produit tiers n'est repris.

### Principes

- **Opérationnel d'abord :** la structure et les données utiles priment sur la décoration.
- **Navigation constante :** navigation latérale sur grand écran, réduite sans perte de repères, panneau accessible sur petit écran.
- **Tableaux avant les cartes :** utiliser un tableau pour comparer, trier ou parcourir des ressources ; réserver les cartes aux regroupements et synthèses qui ont un sens.
- **Densité maîtrisée :** informations scannables, colonnes alignées, nombres à chasse fixe, filtres explicites et espaces réguliers.
- **Surfaces neutres :** fonds sobres, séparateurs visibles, ombres discrètes, rayons limités ; pas de gradients décoratifs, de grille de cartes uniforme ou d'animation permanente.
- **États explicites :** un état ne dépend jamais uniquement d'une couleur ; libellé, icône ou texte d'aide complète la couleur.
- **Actions sûres :** les opérations sensibles décrivent leur cible et leur effet avant confirmation ; aucun changement visuel ne modifie les autorisations backend.

## 2. Palette de référence

Les valeurs ci-dessous sont les couleurs de départ de la charte. Les composants utilisent les tokens sémantiques, jamais ces valeurs primitives directement. Les fonds doux d'état, superpositions et variantes de composants seront définis uniquement lorsqu'un usage réel les nécessite et mesurés sur leur fond effectif.

| Rôle | Clair | Sombre |
|---|---|---|
| Fond de page | `#F5F7FA` | `#0F1720` |
| Surface | `#FFFFFF` | `#17222D` |
| Surface élevée | `#FFFFFF` | `#1D2B38` |
| Texte principal | `#17212B` | `#F3F6F9` |
| Texte secondaire | `#526171` | `#B4C0CB` |
| Séparateur | `#D8E0E8` | `#334353` |
| Bordure de contrôle | `#64748B` | `#72869A` |
| Accent / focus | `#1769AA` | `#66B8FF` |
| Texte sur action primaire | `#FFFFFF` | `#0F1720` |
| Succès | `#126B4F` | `#66D6A5` |
| Avertissement | `#8A5700` | `#FFD27A` |
| Danger | `#B42318` | `#FF8D86` |
| Fond de navigation latérale | `#17222D` | `#17222D` |
| Texte principal de navigation | `#F3F6F9` | `#F3F6F9` |
| Texte secondaire de navigation | `#B4C0CB` | `#B4C0CB` |
| Accent de navigation | `#66B8FF` | `#66B8FF` |

### Contrastes mesurés

Ratios calculés à partir des valeurs hexadécimales ci-dessus selon la formule WCAG relative-luminance. Les mesures concernent uniquement les paires listées ; elles ne valent pas audit de l'interface complète.

| Paire | Clair | Sombre | Seuil visé |
|---|---:|---:|---:|
| Texte principal / surface | 16,29:1 | 14,86:1 | 4,5:1 |
| Texte secondaire / surface | 6,35:1 | 8,70:1 | 4,5:1 |
| Accent / surface | 5,77:1 | 7,57:1 | 4,5:1 |
| Succès / surface | 6,48:1 | 9,00:1 | 4,5:1 |
| Avertissement / surface | 6,10:1 | 11,32:1 | 4,5:1 |
| Danger / surface | 6,57:1 | 7,22:1 | 4,5:1 |
| Bordure de contrôle / surface | 4,76:1 | 4,29:1 | 3:1 |
| Texte sur action primaire / accent | 5,77:1 | 8,48:1 | 4,5:1 |
| Texte principal navigation / fond navigation | 14,86:1 | 14,86:1 | 4,5:1 |
| Texte secondaire navigation / fond navigation | 8,70:1 | 8,70:1 | 4,5:1 |
| Accent navigation / fond navigation | 7,57:1 | 7,57:1 | 4,5:1 |
| Accent navigation active / fond sélectionné | 5,88:1 | 5,88:1 | 4,5:1 |
| Badge info / fond info | 5,09:1 | 5,88:1 | 4,5:1 |
| Badge succès / fond succès | 5,80:1 | 6,88:1 | 4,5:1 |
| Badge avertissement / fond avertissement | 5,64:1 | 8,59:1 | 4,5:1 |
| Badge danger / fond danger | 5,85:1 | 6,20:1 | 4,5:1 |
| Badge neutre / surface subtile | 5,71:1 | 7,80:1 | 4,5:1 |

Le séparateur léger n'est pas destiné à être l'unique contour d'un contrôle interactif. Les contrôles, indicateurs de focus et éléments graphiques nécessaires à la compréhension utilisent des tokens de contraste adaptés. Les valeurs sont à revalider si un fond, une opacité ou une composition change.

## 3. Tokens et conventions

Le package `web/packages/design-tokens/` est la source de vérité partagée. Il sépare :

1. **Tokens primitifs** : valeurs de palette et échelles (couleur, espace, rayon, typographie, ombre, mouvement).
2. **Tokens sémantiques** : rôles consommés par les composants (`bg-canvas`, `bg-surface`, `text-primary`, `text-secondary`, `border-subtle`, `border-control`, `accent`, `focus-ring`, `status-success`, `status-warning`, `status-danger`).

Règles :

- les composants ne référencent jamais une couleur primitive ou un code hexadécimal ;
- les thèmes redéfinissent les tokens sémantiques, pas les styles des composants ;
- aucun token n'est ajouté sans consommateur réel ;
- les couleurs d'état ne sont pas détournées pour décorer une action ;
- les nombres, dates, durées et identifiants techniques utilisent des chiffres tabulaires lorsque cela facilite la comparaison.

### Typographie

Police système sans chargement distant : `system-ui`, `-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, `Roboto`, sans-serif. Aucun téléchargement de police ni nouvelle dépendance n'est introduit par défaut.

Échelle initiale : texte courant 14–16 px selon densité, aide 12–13 px, titres de section 18–20 px, titre de page 24–28 px. Les tailles restent fluides et ne doivent pas empêcher le zoom à 200 %.

### Espacement, densité et géométrie

Échelle de base : 4, 8, 12, 16, 20, 24 et 32 px. Rayons : 4 px pour les contrôles compacts, 6 px pour les surfaces et 8 px pour les panneaux ; les badges peuvent être entièrement arrondis. Les ombres sont réservées aux surfaces réellement superposées.

Les modes de densité `compact` et `comfortable` restent disponibles. Le mode compact réduit les espaces non essentiels, jamais la taille de texte, le focus ou la zone d'activation des commandes. Les cibles tactiles visent 44 × 44 px ; une cible de 40 px est un minimum de conception sur les surfaces denses, avec espacement suffisant.

### Structure de la console

- En-tête clair et compact avec marque, recherche/commandes, préférences et identité de session.
- Barre latérale sombre persistante, sections groupées et état courant évident ; mode réduit avec infobulles accessibles.
- En-tête de page avec titre, description, fil d'Ariane si utile et action principale.
- Contenu en largeur maîtrisée ; les tableaux défilent localement si nécessaire.
- Sur petit écran, navigation en panneau modal avec focus géré et retour au déclencheur.

Les dimensions exactes du shell sont des valeurs d'implémentation réversibles ; elles seront validées sur les écrans réels et les largeurs de référence 320, 768, 1024 et 1440 px.

## 4. Thèmes, accessibilité et mouvement

- Thèmes `light` et `dark`, avec `system` comme préférence initiale.
- Le thème explicite est une préférence de présentation non sensible ; il ne modifie jamais les données ni les droits.
- Aucun flash de thème ne doit être introduit par le chargement ; le mécanisme de pré-initialisation doit respecter la CSP et ne pas ajouter de script inline.
- Focus visible avec indicateur distinct du simple changement de couleur de fond.
- Navigation clavier complète, ordre de focus logique, noms accessibles, annonces `status`/`alert` et gestion de focus pour dialogues et panneaux.
- `prefers-reduced-motion` réduit ou supprime les déplacements ; aucune information n'est portée par le mouvement seul.
- `forced-colors` et zoom 200 % restent fonctionnels.
- Cible WCAG 2.2 AA ; aucune conformité globale n'est revendiquée sans audit clavier, lecteur d'écran et mesures sur rendu réel.

## 5. Composants et frontières

Les tokens sont dans `web/packages/design-tokens/`. Les primitives CSS réutilisées par plusieurs applications résident dans `web/packages/ui/styles.css` ; les wrappers React, libellés et états propres à une application restent dans son `src/shared/ui/`. Les icônes OpenBastion existantes restent dans `web/openbastion-icons/`. Les composants et styles strictement propres à l'Admin UI peuvent rester dans `web/admin-ui/src/shared/` ; ils ne sont déplacés dans le package partagé qu'après preuve de réutilisation.

La bibliothèque évolue par besoin réel : shell/navigation, page header, boutons et champs, tables, badges d'état, alertes, skeletons, dialogues de confirmation, pagination, timeline et visualisation de commandes. Les composants partagés n'importent aucun client API et ne connaissent aucun domaine PAM.

Aucune dépendance npm externe à l'exécution, bibliothèque de composants, framework CSS, routeur ou gestionnaire d'état n'est ajouté par ce plan. Une telle évolution requiert une justification et l'accord préalable du propriétaire.

## 6. Invariants fonctionnels à préserver

Le changement visuel ne supprime ni ne redéfinit les fonctionnalités UX-01 à UX-05 déjà livrées. Les comportements suivants constituent des critères de non-régression :

- navigation par domaines, réduction de la barre latérale, navigation mobile, focus vers le contenu principal et raccourcis `Alt+Maj+1..6` ;
- palette `Ctrl+K` / `Cmd+K`, recherche des seules destinations et ressources exposées, navigation clavier et retour du focus ;
- états PAM, confirmations sensibles, refus API, non-réaffichage des secrets, relecture et états des sessions ;
- Vue générale et Centre de sécurité limités aux données et couvertures effectivement renvoyées par l'API ; aucune métrique, alerte, recherche ou capacité simulée ;
- thèmes, densité, état réduit, destination initiale, favoris, dialogue de préférences et vues de comptes sauvegardées ;
- clés de stockage `openbastion.admin-ui.preferences.v1` et `openbastion.admin-ui.account-views.v1` conservées. Aucun jeton, secret, compte, hôte, identifiant de session, recherche libre ou donnée personnelle n'est ajouté au stockage navigateur.

Les vues sauvegardées restent limitées à 12, avec un nom de 32 caractères maximum et les filtres déjà définis ; elles s'appliquent uniquement aux 20 comptes de la page déjà chargée. Aucun comportement de recherche globale ou de synchronisation multi-appareils n'est ajouté implicitement. Toute migration de format de préférence doit être explicite, testée et réversible.

Un composant peut être remplacé uniquement si ses comportements, libellés accessibles, états, raccourcis, persistance et tests sont conservés. Les tests existants ne sont ni supprimés ni affaiblis.

## 7. Plan d'implémentation incrémental

| Étape | Livrable | Contrôles de sortie |
|---|---|---|
| 0 — Baseline | Inventaire UX-01..05, captures de référence si disponibles, état des tests et audit des couleurs existantes | Baseline `make ui-test ui-build`, inventaire des usages CSS et aucune modification fonctionnelle |
| 1 — Charte et contrats | ADR-0073/0075 précisés, présente spécification, frontières de packages et plan validés | Relecture des décisions, `git diff --check` |
| 2 — Tokens (livré) | Package CSS `web/packages/design-tokens/`, palettes clair/sombre, tokens sémantiques, import reproductible et contrôle de contraste intégré à Make | `make ui-tokens-test` : 18 paires contrôlées à cette étape ; `make ui-test ui-build` : 13 fichiers, 142 tests, TypeScript et Vite réussis |
| 3 — Shell (implémenté) | En-tête clair, sidebar sombre, navigation active, densité, thèmes, responsive et focus | `make ui-test ui-build` : 13 fichiers, 142 tests, TypeScript et Vite réussis ; 26 paires vérifiées ; revue visuelle multi-viewport à faire |
| 4 — Primitives (implémenté) | Package CSS partagé `web/packages/ui/` : boutons, badges, notices, surfaces, en-têtes, formulaires, tableaux, filtres, détails structurés et pagination ; wrappers React propres à l’Admin UI | 14 fichiers Vitest, 147 tests ; 36 paires de contraste ; TypeScript et Vite réussis |
| 5 — Migration des écrans (en cours) | Vue générale, Centre de sécurité, comptes, demandes d’approbation et détail de session migrés vers les patterns partagés ; replay reste à migrer | 14 fichiers Vitest, 147 tests ; TypeScript et Vite réussis ; flux de décision et contrats API conservés ; revue visuelle multi-viewport à faire |
| 6 — Finition et audit | Réduction des valeurs locales, revue clavier/lecteur d'écran, thèmes, mouvement et responsive | `make ui-test ui-build`, audit des contrastes rendus, `git diff --check`, limites consignées |

Chaque étape constitue un incrément cohérent : fichiers explicitement sélectionnés, commit DCO, push sur `refactor/refactor-admin-ui`, puis validation avant l'étape suivante. Aucun changement n'est poussé directement sur `main`.

## 8. Risques et limites connus

- Les ratios calculés sur des couleurs opaques ne couvrent pas les superpositions, les états hover/disabled, les graphiques ni les surfaces composées.
- L'absence de navigateur/lecteur d'écran dans une étape empêche de revendiquer une validation visuelle ou d'accessibilité complète ; les vérifications non réalisées doivent être signalées.
- Les préférences sont locales au navigateur et partagées sur un navigateur utilisé par plusieurs personnes ; elles ne doivent contenir aucune donnée personnelle ou sensible.
- Les écrans restent limités aux contrats API publics et aux autorisations backend disponibles.
- Les dimensions du shell, l'échelle typographique et certains rayons sont des paramètres réversibles jusqu'à validation sur l'interface complète.
