# ADR-0073 — L'Admin UI adopte un système de conception cohérent et une expérience opérateur progressive

**Statut** `Proposé` · 6 novembre 2026 · acceptation explicite du propriétaire requise.

## Contexte

L'Admin UI est maintenant une application réelle sous `web/admin-ui/`, construite avec React, TypeScript et Vite, servie par l'API Gateway sous `/ui/`. Elle couvre progressivement les parcours du MVP : authentification locale et OIDC, gestion des comptes privilégiés, création de politiques, demandes et décisions break-glass, consultation d'une session et lecture d'un enregistrement.

L'ADR-0036 fixe volontairement une base minimale et sûre : React et React DOM à l'exécution, sans routeur, bibliothèque de composants ni gestionnaire d'état tiers ; communication exclusivement avec l'API publique de la Gateway ; même origine ; CSP stricte ; jeton conservé en mémoire seulement ; aucun secret de cible rendu à l'administrateur. Cette décision reste valable et n'est pas remise en cause.

L'interface doit maintenant grandir sans devenir une juxtaposition d'écrans indépendants. Les besoins identifiés sont transverses : retrouver rapidement une ressource, comprendre l'état d'une opération, distinguer une absence de données d'un refus ou d'une panne, naviguer entre les domaines PAM, et réaliser les gestes fréquents au clavier comme à la souris. La cohérence visuelle, l'accessibilité, le responsive et la lisibilité des actions sensibles doivent être des propriétés de l'application, pas des corrections tardives propres à chaque écran.

Plusieurs idées de l'évolution UX dépassent toutefois les capacités actuellement documentées de l'API publique : tableau de bord agrégé, recherche globale dans les événements d'audit, inventaire complet des politiques, indicateurs de posture, analytics et notifications temps réel. L'interface ne doit ni simuler ces données ni contourner la Gateway pour les obtenir. Les capacités absentes devront être conçues dans des décisions et contrats API dédiés.

La présente décision porte donc sur le socle d'expérience et la manière de faire évoluer l'interface. Elle ne prétend pas que toutes les fonctions proposées sont déjà disponibles.

## Décision

### 1. Préserver le socle de sécurité et la pile de l'ADR-0036

1. Conserver `web/admin-ui/`, React, TypeScript, Vite, Vitest, jsdom et Testing Library.
2. Ne pas ajouter, dans le cadre de cette décision, de routeur, de bibliothèque de composants, de framework CSS, de gestionnaire d'état, de moteur de recherche client ou de dépendance d'interface à l'exécution.
3. Continuer à servir l'application par la Gateway sous `/ui/`, sur la même origine que l'API.
4. L'interface appelle exclusivement les routes publiques documentées de la Gateway. Elle ne contacte directement aucun microservice, base de données, bus, moteur de recherche ou stockage objet.
5. Conserver la CSP stricte, l'absence de scripts inline, le rendu des données non fiables comme du texte, et le jeton d'accès en mémoire seulement. Aucun jeton, secret, ticket de session, code MFA, code OIDC ou credential ne doit être persisté dans `localStorage`, `sessionStorage`, IndexedDB, une URL ou un journal.
6. L'API et les services restent les autorités pour l'identité, l'autorisation, l'approbation et l'audit. Masquer ou désactiver une action dans l'interface améliore l'expérience mais ne constitue jamais un contrôle de sécurité.

### 2. Organiser l'interface par domaines opérateur

Le shell applicatif adopte une navigation latérale structurée par domaines, avec un contenu principal clairement hiérarchisé. Les domaines cibles sont :

- **Vue générale** : synthèse des informations effectivement disponibles.
- **Accès privilégiés** : comptes, demandes d'accès et politiques lorsque les routes correspondantes existent.
- **Sessions** : sessions actives ou consultables, détails, enregistrements et relecture selon les droits.
- **Secrets** : métadonnées et opérations de gestion autorisées ; jamais la valeur d'un secret.
- **Identités** : utilisateurs, groupes, facteurs et fournisseurs d'identité lorsqu'ils sont exposés par l'API.
- **Gouvernance** : approbations, workflows et revues lorsqu'ils sont implémentés.
- **Sécurité et audit** : alertes, événements et preuves uniquement lorsque les API correspondantes existent.
- **Administration** : configuration et intégrations réellement prises en charge.

Règles de navigation :

1. N'afficher comme destinations actives que les écrans implémentés et alimentés par un contrat disponible. Une fonction future ne doit pas être présentée comme opérationnelle.
2. Les sections sans capacité disponible peuvent être omises ; aucun lien mort, écran factice ou compteur inventé n'est autorisé.
3. La navigation indique l'emplacement courant, conserve un fil d'Ariane lorsque la profondeur le justifie et permet de réduire la barre latérale.
4. Sur petit écran, la navigation devient un panneau accessible qui ne masque pas durablement le contenu et rend le focus à son déclencheur à la fermeture.
5. La navigation clavier, le focus visible et les états actif/inactif ne dépendent pas uniquement de la couleur ou d'une icône.

### 3. Introduire un shell et un langage visuel communs

Le shell partagé comprend, selon le contexte :

- barre latérale de navigation ;
- en-tête de page avec titre, description et actions principales ;
- fil d'Ariane ;
- zone de contenu ;
- zone de notifications et d'identité de l'utilisateur ;
- panneau de recherche/commande lorsqu'il sera implémenté.

Un système de tokens CSS centralise les couleurs sémantiques, typographies, espacements, rayons, bordures, ombres, couches, tailles de focus et points de rupture. Les composants consomment ces tokens plutôt que des valeurs arbitraires locales.

Les thèmes clair et sombre sont deux thèmes du même système de tokens. Ils doivent conserver les mêmes contrastes, états, niveaux d'information et affordances. Le choix du thème est une préférence d'affichage non sensible ; il ne modifie ni les permissions ni les données chargées.

Le package local `web/openbastion-icons` reste la source des icônes de produit. Les icônes ne remplacent jamais un libellé nécessaire et leur rendu doit rester compatible avec la CSP de l'ADR-0036.

### 4. Construire une bibliothèque de composants interne et limitée

Les composants partagés vivent dans la zone `shared` déjà présente dans `web/admin-ui/src/`. Les fonctionnalités métier restent dans `features`, et l'assemblage de l'application dans `app`.

La bibliothèque couvre progressivement les primitives utiles :

- **Structure** : AppShell, Sidebar, PageHeader, Breadcrumbs, Tabs, Drawer.
- **Actions et formulaires** : Button, Input, Select, Checkbox, FormField, ConfirmationDialog.
- **Données** : DataTable, EmptyState, Skeleton, Pagination si le contrat la nécessite, Timeline, CodeViewer.
- **Retour utilisateur** : Alert, Toast, StatusBadge, InlineError, LoadingState.
- **Sécurité** : PermissionNotice, RiskIndicator, SecretMetadata, SensitiveActionConfirmation.

Chaque composant partagé possède une API explicite, des états documentés et des tests ciblés. Une abstraction n'est créée que lorsqu'au moins deux usages réels en justifient la réutilisation ; les écrans ne doivent pas être transformés en framework générique prématuré.

Les composants métier restent responsables de leurs libellés, règles de validation et appels API. Les primitives partagées ne connaissent ni les endpoints ni les modèles des microservices.

### 5. Normaliser les états et les retours d'interaction

Tout écran alimenté par une API distingue explicitement :

1. chargement ;
2. succès avec données ;
3. succès sans résultat ;
4. refus d'accès ;
5. ressource absente ;
6. erreur métier récupérable ;
7. indisponibilité ou erreur technique ;
8. action en cours et résultat de l'action.

Un état vide explique ce que l'utilisateur peut faire ensuite, sans laisser croire qu'une erreur est une absence de données. Un refus affiche le code public stable et un message opérateur sûr ; il ne révèle jamais une cause interne, une existence protégée ou une donnée sensible.

Les actions destructrices ou à privilèges élevés indiquent leur cible et leurs conséquences avant confirmation. Une justification n'est demandée que si le contrat API l'exige ou si une décision métier l'a définie. Annuler une confirmation n'envoie aucune requête. Les opérations non idempotentes ne sont pas relancées automatiquement après une réponse ambiguë.

Les opérations groupées ne sont proposées que si leur sémantique est explicite : atomicité garantie par le serveur ou résultat individuel par élément, avec traitement visible des succès partiels. L'interface ne transforme pas une série d'appels indépendants en une opération présentée comme atomique.

### 6. Ajouter une recherche et une palette de commandes sans contourner les contrats

Une palette de commandes accessible au clavier (raccourci conventionnel `Ctrl+K`, avec adaptation au système et possibilité de désactivation) est une capacité cible pour :

- naviguer vers un écran déjà disponible ;
- retrouver une ressource déjà accessible par une route publique ;
- déclencher une action existante et autorisée, après les confirmations requises.

La palette ne devient jamais un canal privilégié. Elle réutilise les mêmes fonctions de présentation et les mêmes appels API que les écrans.

La recherche transversale dans des ressources non chargées, les événements d'audit, les enregistrements ou l'index OpenSearch nécessite des routes publiques dédiées, paginées, filtrées, autorisées et auditées. Elle est hors périmètre d'implémentation de cet ADR. Aucun accès direct à OpenSearch et aucun téléchargement massif de données pour fabriquer une recherche locale ne sont autorisés.

Les préférences de recherche, favoris et éléments récents ne peuvent contenir que des identifiants ou métadonnées non sensibles déjà visibles par l'utilisateur. Leur persistance et leur synchronisation multi-appareils feront l'objet d'une décision séparée si elles deviennent nécessaires.

### 7. Encadrer le tableau de bord et les indicateurs de sécurité

La Vue générale est construite uniquement à partir de données réelles retournées par les API publiques auxquelles l'utilisateur est autorisé. Chaque widget distingue :

- valeur disponible et date de fraîcheur ;
- absence réelle de résultat ;
- information non prise en charge ;
- refus d'accès ;
- source indisponible.

Aucun chiffre, score de risque, état de conformité, taux de couverture ou tendance n'est calculé à partir de données partielles sans définition explicite. Un score de risque exige une méthode, des facteurs explicables, une version de calcul et un contrat de données dédiés.

Les métriques agrégées, le Security Center, les notifications temps réel et les rapports ne sont pas introduits par simple assemblage de réponses existantes. Ils nécessitent leurs contrats, règles d'autorisation, limites de pagination, exigences de fraîcheur et décisions d'audit propres.

### 8. Rendre l'accessibilité et le responsive vérifiables

L'objectif de conception est **WCAG 2.2 niveau AA**. Il s'applique aux nouveaux composants et aux écrans modifiés ; il ne constitue pas une déclaration de conformité globale avant audit.

Exigences minimales :

- structure sémantique et noms accessibles ;
- navigation complète au clavier ;
- ordre de tabulation cohérent et focus visible ;
- gestion du focus à l'ouverture/fermeture des dialogues et panneaux ;
- annonces accessibles des erreurs, chargements et mises à jour importantes ;
- contraste vérifié pour le texte, les contrôles et les états ;
- aucune information transmise uniquement par la couleur ;
- respect de `prefers-reduced-motion` ;
- zoom et redistribution du contenu sans perte fonctionnelle ;
- cibles interactives suffisamment grandes et espacées ;
- tableaux utilisables au clavier et lisibles sur petit écran.

Les tests automatisés complètent, sans la remplacer, une vérification manuelle au clavier et avec lecteur d'écran.

### 9. Définir une évolution incrémentale et testable

Les lots d'implémentation sont ordonnés ainsi :

1. **UX-01 — Fondations** : tokens, thèmes, shell, navigation, responsive et composants de base.
2. **UX-02 — Productivité** : états communs, filtres et recherche/palette limités aux ressources et actions déjà exposées.
3. **UX-03 — Parcours PAM** : homogénéisation des écrans comptes, sessions, enregistrements, approbations et secrets.
4. **UX-04 — Visibilité** : tableau de bord et centre de sécurité uniquement au rythme des contrats API réels.
5. **UX-05 — Personnalisation** : vues sauvegardées, favoris, préférences et raccourcis complémentaires, après définition de leur stockage et de leur cycle de vie.

Chaque lot reste livrable indépendamment et conserve le comportement des parcours existants. Aucun lot UX ne doit introduire silencieusement une route Gateway, un droit, une table, un événement d'audit ou un nouveau service.

Pour chaque comportement ajouté, les tests Vitest/Testing Library couvrent les états heureux, vides, refusés et en erreur, ainsi que l'absence d'appel API lorsqu'une action est annulée. Les tests vérifient également le focus, les libellés accessibles et les invariants de non-divulgation des secrets. Les changements d'interface passent `make ui-test ui-build`. Une suite navigateur E2E sera introduite par décision dédiée si elle exige une nouvelle dépendance ou une nouvelle infrastructure.

## Conséquences

- (+) Une structure commune réduit les divergences d'écran et permet d'améliorer les parcours sans réécrire l'application.
- (+) Les domaines fonctionnels et les états sont lisibles ; les fonctions non implémentées ne sont plus suggérées comme disponibles.
- (+) La recherche et la palette restent des raccourcis vers les capacités autorisées, et non un nouveau chemin d'accès aux données.
- (+) La séparation `app / features / shared` existante est renforcée sans déplacer les responsabilités métier dans les composants génériques.
- (+) Les exigences d'accessibilité, de responsive et de sécurité UX deviennent des critères de revue et de test.
- (+) Aucun nouveau paquet npm à l'exécution, aucune route API et aucun service ne sont requis par la décision elle-même.
- (−) Cette ADR est une décision d'architecture : elle ne livre ni le shell, ni le dashboard, ni la recherche, ni la bibliothèque de composants.
- (−) L'API actuelle ne permet pas encore toutes les vues souhaitées, notamment une recherche globale complète, une liste exhaustive des politiques et une vue générale agrégée. Ces capacités restent absentes jusqu'à livraison de contrats dédiés.
- (−) Le maintien d'une pile frontend volontairement minimale demande de construire et maintenir certains composants en interne ; les composants complexes ne doivent pas être réinventés sans besoin démontré.
- (−) WCAG 2.2 AA est une cible, pas une conformité mesurée. Un audit manuel et des tests sur navigateurs/lecteurs d'écran restent nécessaires.
- (−) Aucune mesure de temps de tâche, de taux d'erreur ou de performance UX n'est disponible à la date de cette décision ; aucune amélioration quantitative n'est revendiquée.
- (−) Les tests E2E navigateur, la persistance multi-appareils des préférences, les notifications temps réel et les opérations groupées restent hors du premier lot.

## Alternatives envisagées

- **Adopter immédiatement une bibliothèque UI complète** : écarté pour préserver la pile minimale et la CSP de l'ADR-0036, éviter une dépendance runtime supplémentaire et garder le contrôle sur les composants sensibles. Une réévaluation reste possible sur preuve d'un besoin et par décision dédiée.
- **Introduire un routeur et un gestionnaire d'état tiers dès maintenant** : écarté ; la navigation et les besoins d'état doivent d'abord être éprouvés avec les parcours réels. Un besoin démontré pourra faire l'objet d'un ADR distinct.
- **Créer un dashboard et une recherche en agrégeant directement les bases ou services internes** : refusé ; cela contournerait la Gateway, l'autorisation, les contrats publics et les frontières de service.
- **Afficher des compteurs, scores ou alertes simulés en attendant les API** : refusé ; cela donnerait à l'opérateur une représentation fausse de la posture de sécurité.
- **Faire une refonte visuelle complète en une seule livraison** : écarté au profit de lots indépendants, testables et réversibles qui préservent les parcours existants.
- **Construire une interface distincte servie par un autre domaine** : écarté ; cela réintroduirait CORS et une origine supplémentaire, en contradiction avec l'ADR-0036.
