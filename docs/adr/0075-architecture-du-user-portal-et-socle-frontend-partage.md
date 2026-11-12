# ADR-0075 — Architecture du User Portal et socle frontend partagé

**Statut** `Proposé` · 6 novembre 2026 · acceptation explicite du propriétaire du projet requise.

## Contexte

OpenBastion possède une application d'administration `web/admin-ui/`, dont la pile, le mode de service et les contraintes de sécurité sont définis par l'ADR-0036. Le portail destiné aux utilisateurs finaux répond à un autre objectif : découvrir les ressources auxquelles ils ont droit, demander un accès, lancer une session proxifiée, suivre leurs demandes et consulter leur activité.

Ces deux interfaces partagent des besoins transverses (tokens visuels, primitives accessibles, icônes, client API et types de contrats), mais ne partagent ni les mêmes parcours, ni les mêmes responsabilités métier. Faire du portail une section de l'Admin UI mélangerait les usages opérateur et self-service et compliquerait leur évolution indépendante.

La structure de référence du dépôt est `docs/development/repository-structure.md`, en particulier sa section 5. La présente ADR formalise l'arborescence frontend détaillée retenue : applications indépendantes sous `web/`, package d'icônes dédié et packages frontend partagés. Elle ne crée pas de nouvelle capacité backend et ne prétend pas que les parcours décrits sont déjà tous exposés par l'API.

L'ADR-0036 reste applicable : les interfaces web communiquent exclusivement avec l'API publique de l'API Gateway, sont servies sous la même origine et ne stockent pas de jeton d'accès dans un stockage persistant du navigateur. Les services, bases de données, bus, moteurs de recherche et stockages objets ne sont jamais accessibles directement depuis le navigateur.

## Décision

### 1. Deux applications frontend indépendantes

Le dépôt contient deux applications distinctes :

- `web/admin-ui/` : interface des administrateurs et opérateurs, gouvernance, configuration, supervision et audit selon les capacités réellement disponibles ;
- `web/user-portal/` : interface self-service des utilisateurs, demandes d'accès, lancement et suivi des sessions et activité personnelle.

Chaque application possède son propre point d'entrée, son routeur, ses providers, ses layouts, ses fonctionnalités et ses tests. Aucune application n'importe le code métier de l'autre. Les évolutions et livraisons de l'une ne doivent pas imposer une régression fonctionnelle à l'autre.

Le User Portal adopte React, TypeScript et Vite, en cohérence avec l'ADR-0036. Le choix de nouvelles dépendances runtime, d'un routeur tiers ou d'un gestionnaire d'état tiers n'est pas implicite dans cette ADR : toute dépendance supplémentaire doit être justifiée, évaluée pour la sécurité et validée séparément.

### 2. Arborescence frontend normative

L'organisation cible est la suivante. Elle constitue la référence pour les incréments frontend ; les répertoires peuvent être créés progressivement à mesure que les fonctionnalités sont implémentées.

```text
web/
├── admin-ui/
│   ├── src/
│   └── ...
│
├── user-portal/
│   └── src/
│       ├── app/
│       │   ├── router/
│       │   ├── providers/
│       │   └── layouts/
│       │
│       ├── features/
│       │   ├── home/
│       │   ├── resources/
│       │   ├── access-requests/
│       │   ├── sessions/
│       │   ├── approvals/
│       │   ├── activity/
│       │   └── profile/
│       │
│       ├── components/
│       │   ├── navigation/
│       │   ├── resources/
│       │   ├── sessions/
│       │   └── feedback/
│       │
│       ├── services/
│       ├── hooks/
│       ├── stores/
│       ├── types/
│       └── test/
│
├── openbastion-icons/
│   ├── src/
│   └── ...
│
├── packages/
│   ├── ui/
│   ├── design-tokens/
│   ├── api-client/
│   ├── contracts/
│   └── utilities/
│
└── package.json
```

Le manifeste racine `web/package.json` coordonne les outils et scripts communs au frontend. Les modalités précises de gestion des workspaces, des lockfiles, de construction et de publication des packages devront préserver les installations reproductibles (`npm ci`) et seront vérifiées dans l'incrément d'outillage frontend ; cette ADR ne justifie pas une migration silencieuse des lockfiles existants.

### 3. Frontières et responsabilités des packages partagés

| Emplacement | Responsabilité | Interdictions |
|---|---|---|
| `web/openbastion-icons/` | Icônes de marque et icônes fonctionnelles OpenBastion, exports React/SVG et ressources associées | Pas de logique métier ni d'accès réseau |
| `web/packages/design-tokens/` | Source de vérité de la charte OpenBastion Infrastructure : palettes primitives et sémantiques, typographie, espacements, densité, rayons, bordures, élévation, focus, mouvement, points de rupture et thèmes clair/sombre | Pas de composants, de préférences utilisateur, de données métier ni de décision d'autorisation |
| `web/packages/ui/` | Primitives CSS génériques (boutons, badges, notices, surfaces, en-têtes, formulaires, tableaux, filtres, indicateurs et états vides), accessibles et construites exclusivement avec les tokens partagés ; wrappers React et logique de présentation propres à chaque application | Pas de connaissance des endpoints, des ressources PAM ou des règles de privilège ; pas de copie de composants propriétaires tiers |
| `web/packages/api-client/` | Transport HTTP vers l'API publique Gateway, gestion cohérente des erreurs et des identifiants de corrélation | Aucun appel direct aux microservices ; aucun stockage persistant de jeton ou de secret |
| `web/packages/contracts/` | Types et schémas frontend dérivés des contrats API publics versionnés | Pas de modèles internes copiés depuis les bases ou les domaines privés des services |
| `web/packages/utilities/` | Fonctions frontend génériques sans dépendance métier | Pas de logique d'autorisation faisant autorité |

Les applications consomment les packages partagés par leurs interfaces publiques. Les packages partagés ne dépendent jamais d'une application. Les dépendances entre packages doivent rester orientées vers les couches les plus génériques ; les cycles sont interdits.

Le package `contracts` ne devient pas une seconde source de vérité : OpenAPI et les contrats publics restent la référence backend. Les types TypeScript sont générés ou synchronisés depuis ces contrats selon un processus vérifiable. Les messages gRPC internes et les modèles de persistance ne sont pas exposés au navigateur.

### 3.1 Charte graphique partagée : OpenBastion Infrastructure

Les deux applications adoptent une même identité visuelle nommée **OpenBastion Infrastructure**. La direction recherchée reprend les qualités fonctionnelles d'une console d'infrastructure moderne, notamment celles observées dans UniFi Network : navigation latérale persistante, hiérarchie de page nette, densité d'information maîtrisée, tableaux lisibles, filtres explicites, états opérationnels visibles et interactions prévisibles. Il s'agit d'une inspiration ergonomique, pas d'une reproduction : aucun logo, pictogramme, code, capture, texte propriétaire, illustration ni agencement distinctif de Ubiquiti/UniFi n'est repris.

La charte s'applique aux deux applications sans fusionner leurs responsabilités :

- l'Admin UI reste une console d'exploitation, d'administration, de gouvernance et d'audit ;
- le User Portal reste un espace de self-service centré sur les ressources, les demandes, les sessions et l'activité personnelle.

Leur navigation métier, leurs autorisations, leurs états et leurs données restent indépendants. Seuls l'identité visuelle, les tokens, les primitives réellement génériques et les règles d'accessibilité sont partagés.

Principes visuels obligatoires :

1. **Structure avant décoration** : barre latérale sombre structurée, en-tête clair compact, titre et contexte de page, contenu principal clairement délimité ; les cartes ne remplacent pas les tableaux lorsque l'utilisateur doit comparer ou parcourir des lignes.
2. **Densité lisible** : priorité aux informations utiles, colonnes alignées, nombres tabulaires, filtres visibles, pagination conforme aux contrats réels ; la compacité ne réduit ni la lisibilité ni les cibles tactiles.
3. **Surfaces sobres** : fonds neutres, séparateurs explicites, ombres rares et faibles, rayons cohérents ; pas de dégradés décoratifs, de grandes cartes uniformes ni d'animation permanente.
4. **Sémantique explicite** : succès, avertissement, danger, sélection, indisponibilité et focus sont identifiables par leur libellé ou pictogramme en plus de leur couleur.
5. **Thèmes équivalents** : clair et sombre exposent les mêmes actions, informations, niveaux de priorité et états. Le thème système est utilisé par défaut ; le choix explicite reste une préférence locale non sensible.
6. **Accessibilité et adaptation** : navigation clavier, focus visible, zoom, réduction du mouvement, mode contraste forcé et fonctionnement à partir de 320 px ; les tableaux peuvent défiler dans leur conteneur sans imposer un débordement horizontal à toute la page.

La palette normative, les rôles de tokens, les règles de typographie, d'espacement, de densité, de mouvement et le plan de migration sont définis dans [`../development/admin-ui-design-system.md`](../development/admin-ui-design-system.md). Les composants consomment exclusivement des tokens sémantiques ; les valeurs primitives ne sont jamais utilisées directement dans les composants. Les icônes restent issues de `web/openbastion-icons/` et héritent de `currentColor`.

La cible d'accessibilité est WCAG 2.2 AA. Les ratios documentés dans la spécification portent uniquement sur les paires de couleurs explicitement mesurées ; ils ne constituent pas une déclaration de conformité de l'application. Les états, contrôles, bordures, focus, icônes, graphiques et composants composés doivent être vérifiés sur leurs surfaces effectivement rendues, dans les deux thèmes.

### 4. Responsabilités propres au User Portal

Les domaines fonctionnels du portail sont :

- **home** : synthèse personnelle composée uniquement de données réelles et autorisées ;
- **resources** : catalogue des ressources accessibles, avec métadonnées non sensibles et actions autorisées ;
- **access-requests** : création, justification et suivi des demandes d'accès ;
- **sessions** : lancement et suivi des sessions proxifiées, durée restante, état et historique ;
- **approvals** : décisions d'approbation uniquement pour les utilisateurs disposant du rôle correspondant ;
- **activity** : activité propre à l'utilisateur, limitée aux événements que l'API lui permet de consulter ;
- **profile** : préférences non sensibles et informations d'identité exposées par les API prévues.

Les composants communs propres au portail résident dans `user-portal/src/components/`. Les composants spécifiques à une fonctionnalité restent dans son dossier `features/<domaine>/` tant qu'ils n'ont pas de réutilisation réelle. Un composant ne rejoint `packages/ui/` que s'il est indépendant du métier et utile à plusieurs applications.

### 5. Parcours et séparation des rôles

Le portail guide l'utilisateur à travers le parcours suivant :

1. authentification via le mécanisme OIDC de la plateforme ;
2. consultation des ressources autorisées par le backend ;
3. demande d'accès avec justification et informations exigées par la politique ;
4. approbation éventuelle par le workflow backend ;
5. création d'une session par le Session Broker ;
6. lancement à l'aide d'un ticket éphémère, à usage unique et limité à la session ;
7. suivi, terminaison et consultation de l'activité selon les droits.

L'interface ne décide jamais qu'un utilisateur possède un privilège. Les règles RBAC/ABAC, l'éligibilité d'une ressource, les approbations, les durées, les limites et les révocations sont évaluées côté serveur à chaque opération.

Le rôle d'approbateur ne transforme pas le portail en Admin UI : seules les décisions explicitement permises par les contrats publics sont proposées, dans un parcours séparé et audité.

### 6. Sécurité et non-divulgation

Les invariants suivants sont obligatoires :

- Toutes les requêtes passent par l'API Gateway publique, sur une origine maîtrisée et sous TLS.
- Aucun accès navigateur direct aux microservices, bases de données, NATS/Kafka, Redis, OpenSearch ou MinIO.
- Aucun mot de passe, clé privée, secret de cible ou credential privilégié n'est transmis au navigateur.
- Le navigateur ne reçoit qu'un ticket de lancement de session borné, éphémère, à usage unique et non réutilisable ; le secret de la cible reste dans le plan de contrôle/proxy selon l'ADR-0003.
- Les jetons d'accès restent en mémoire uniquement, conformément à l'ADR-0036 ; aucun jeton ou ticket n'est écrit dans `localStorage`, `sessionStorage`, IndexedDB, une URL ou un journal.
- Les cookies éventuels de session d'interface sont `Secure`, `HttpOnly`, `SameSite` et protégés contre les requêtes CSRF ; leur introduction nécessite un contrat d'authentification explicite.
- CSP stricte, rendu des données non fiables comme texte, validation côté serveur, limitation de débit et protection contre l'IDOR/XSS/CSRF/SSRF restent obligatoires.
- Chaque lecture ou mutation est autorisée côté serveur. Masquer un bouton dans React n'est jamais un contrôle d'accès.
- Les erreurs publiques sont présentées à partir de codes stables ; aucune erreur interne, donnée protégée ou existence de ressource non autorisée n'est révélée.

L'application doit distinguer les états de chargement, vide, interdit, absent, erreur métier, erreur technique, action en cours et résultat. Les actions sensibles explicitent leur cible et leurs conséquences ; les mutations non idempotentes ne sont pas rejouées automatiquement après une réponse ambiguë.

### 7. Hébergement et intégration Gateway

Le User Portal reste une application distincte au niveau du build et de l'arborescence, mais partage le modèle de déploiement de même origine défini par l'ADR-0036. Le chemin HTTP de montage, les variables de build et les changements du serveur statique Gateway doivent être définis et testés avant son exposition ; cette ADR ne prétend pas qu'une route `/portal/` existe déjà.

Les deux applications ne partagent ni serveur de développement ni runtime métier. Le déploiement doit permettre à la Gateway de servir les artefacts construits sans ouvrir une origine tierce et sans assouplir la CSP. Une application non configurée ne doit pas être servie par défaut.

### 8. Accessibilité, responsive et qualité

L'objectif est WCAG 2.2 niveau AA, sans revendiquer de conformité avant audit. Les écrans doivent être utilisables au clavier, disposer de noms accessibles, conserver un focus visible, gérer correctement les dialogues et panneaux, annoncer les erreurs et changements d'état, respecter les préférences de réduction des animations et rester fonctionnels sur petits écrans.

Les tests unitaires couvrent les états heureux, vides, refusés et en erreur, les contrôles d'accès côté interface sans leur attribuer de valeur de sécurité, l'absence de requête après annulation et les invariants de non-divulgation. Les tests API et E2E valident les contrats et les parcours avec la Gateway réelle. Les contrôles d'accessibilité automatisés complètent une vérification manuelle clavier/lecteur d'écran.

### 9. Évolution incrémentale

Les lots fonctionnels sont séparés afin de livrer une base utile sans simuler les capacités non disponibles :

1. **UP-01 — Fondations** : application, shell, navigation, tokens, thèmes, packages partagés minimaux et tests.
2. **UP-02 — Home et ressources** : synthèse limitée aux API existantes, catalogue autorisé et recherche dans les données effectivement exposées.
3. **UP-03 — Access Requests** : création, justification, suivi et timeline des décisions.
4. **UP-04 — Sessions** : lancement SSH via Broker, états, durée, terminaison et historique.
5. **UP-05 — Protocoles et transferts** : RDP/VNC/Kubernetes et transferts uniquement lorsque les proxies et contrats correspondants sont disponibles.
6. **UP-06 — Approvals, Activity et Profile** : décisions conditionnées par rôle, activité personnelle, MFA et préférences.

Aucun écran ne présente de données, compteurs, disponibilité, scores ou fonctions simulés. Une capacité backend absente reste absente de l'interface jusqu'à livraison de son contrat public.

## Conséquences

- (+) Les parcours d'administration et de self-service sont isolés, tout en partageant un socle frontend contrôlé.
- (+) L'arborescence devient explicite et stable ; chaque dossier a une responsabilité identifiée.
- (+) Les contrats publics restent la seule source de vérité des données consommées par les applications.
- (+) Le portail ne devient pas un chemin alternatif d'accès aux secrets ou aux services internes.
- (+) Les packages partagés peuvent évoluer indépendamment des domaines métier, sans dépendance circulaire entre applications.
- (+) La livraison progressive permet de ne proposer que les capacités réellement disponibles et autorisées.
- (−) La maintenance d'un socle partagé demande des règles de versionnement, de compatibilité et des tests de consommation par les deux applications.
- (−) La séparation des builds implique de traiter explicitement la configuration Gateway, les chemins de base et les artefacts statiques.
- (−) Les parcours complets dépendent de contrats API qui ne sont pas tous disponibles aujourd'hui.
- (−) La gestion des workspaces et lockfiles n'est pas résolue par cette ADR et doit être traitée sans casser la reproductibilité de l'ADR-0036.
- (−) WCAG 2.2 AA est une cible de conception ; un audit manuel reste nécessaire.

## Alternatives envisagées

- **Ajouter le portail comme section de `admin-ui`** : écarté, car les publics, permissions, navigation et cycles d'évolution sont différents.
- **Dupliquer tous les composants, tokens, icônes et clients API** : écarté, car cela créerait des divergences et des correctifs de sécurité à appliquer plusieurs fois.
- **Créer un package métier commun aux deux applications** : écarté ; seules les primitives UI, tokens, icônes, utilitaires et contrats publics sont partagés. Les fonctionnalités restent dans leur application.
- **Faire communiquer directement le portail avec les services backend** : refusé, car cela contournerait Gateway, l'autorisation, l'audit et les frontières de confiance.
- **Exposer les secrets ou identifiants de cible au navigateur pour simplifier la connexion** : refusé, en contradiction avec l'ADR-0003 et le principe PAM.
- **Créer immédiatement une application frontend universelle unique** : écarté au profit de deux applications indépendantes, avec packages partagés explicites.
