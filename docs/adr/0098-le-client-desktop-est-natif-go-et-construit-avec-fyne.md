# ADR-0098 — Le client Desktop OpenBastion est une application native Go construite avec Fyne

**Statut** `Proposé` · 13 novembre 2026 · décision soumise à validation du propriétaire du projet

## Contexte

OpenBastion prévoit un client Desktop pour les opérateurs privilégiés. Le document d'architecture préparatoire « OpenBastion — Desktop Client natif Go + Fyne » recommande de remplacer le choix initial Tauri par une application native développée en Go.

Le dépôt est un monorepo multi-module Go (ADR-0002) et Go est le langage de référence des services backend (ADR-0004). Le client Desktop doit offrir une expérience opérateur native sans devenir un second plan de contrôle ni réimplémenter les protocoles d'accès.

À la date de cette décision :

- le répertoire `desktop/` n'existe pas encore sur `main` ;
- le futur `desktop/tauri-client` est une cible documentaire, pas une application livrée ;
- l'Admin UI reste une application React, Vite et TypeScript servie par la Gateway (ADR-0036 et ADR-0073) ;
- le User Portal conserve son architecture propre (ADR-0075) ;
- les sessions SSH et écran RDP/VNC ont déjà leurs contrats côté Gateway, Broker et proxies.

Le besoin est donc de choisir un socle de présentation et d'intégration Desktop, pas de déplacer les fonctions PAM dans le poste opérateur.

## Décision

### 1. Framework et langage

1. Le client Desktop OpenBastion est une application native **Go** construite avec **Fyne Core** (`fyne.io/fyne`, documentation sur <https://fyne.io/>).
2. **Tauri est abandonné comme cible du futur client Desktop**. Aucun runtime Rust, WebView, React, TypeScript, Node.js ou bundle frontend n'est requis pour l'application Fyne.
3. Le code métier du client, ses adaptateurs API, son orchestration de session et ses composants d'interface sont écrits en Go. Les bibliothèques tierces conservent leurs langages et toolchains propres.
4. `fyne-x` (`fyne-io/fyne-x`) est une collection d'extensions **facultative**. Elle n'est pas une dépendance structurante au démarrage. Chaque composant éventuellement retenu doit être évalué, testé, épinglé sur une version publiée et soumis à la revue de licence, maintenance, sécurité et compatibilité avec la version de Fyne adoptée.
5. Fyne Core et les dépendances transitives sont épinglés dans les fichiers Go. Aucune branche flottante (`master`, `develop`) n'est utilisée comme dépendance de production.

### 2. Périmètre fonctionnel

Le client Desktop est un **client de confiance limitée**. Il fournit une interface opérateur pour :

- l'authentification et le choix du tenant/organisation ;
- la découverte des ressources et comptes autorisés ;
- la demande, la justification et le suivi d'une session ;
- l'affichage des sessions actives et de leur état ;
- le terminal SSH et l'affichage/interaction écran RDP ou VNC via les flux autorisés ;
- la consultation des événements, notifications et demandes d'approbation autorisées ;
- les préférences locales non sensibles et les diagnostics expurgés.

Il ne remplace pas l'Admin UI, le User Portal, la CLI ni les SDK. Il ne fournit pas d'interface locale d'administration des services.

### 3. Frontières de sécurité et accès aux sessions

1. Toutes les communications passent par l'API Gateway publique, sous TLS. Le client ne contacte jamais directement une cible, un proxy interne, le Session Broker, le Vault, le Secrets Manager ou une base de données.
2. L'autorisation reste décidée côté serveur (RBAC/ABAC, approbations, fenêtre horaire, MFA et politiques). Le client ne fait qu'afficher les décisions et présenter les preuves d'authentification requises.
3. Le flux de connexion SSH réutilise le contrat `POST /sessions/{id}/connect` et son ticket éphémère. Le client ne reçoit ni ne conserve le mot de passe ou la clé privée de la cible.
4. Le flux RDP/VNC réutilise le contrat d'attachement écran de la Gateway (`/sessions/{id}/screen`, `openbastion.screen.v1`) et son cookie d'attachement à durée et usage bornés. Le client ne se connecte jamais à l'adresse IP de la cible.
5. Le client ne contourne pas les règles « enregistrer ou refuser » (ADR-0008), la séparation du control plane et des secrets (ADR-0003), ni les invariants de saisie de secret (ADR-0097).
6. Les jetons, cookies d'attachement et secrets temporaires restent en mémoire autant que possible, sont exclus des logs/crash reports et sont effacés à la déconnexion. Aucun secret de cible ni jeton de session n'est écrit dans les préférences Fyne, le trousseau applicatif ou un fichier de configuration.
7. Les journaux locaux sont minimaux, expurgés et ne se substituent jamais à l'Audit Service. Les actions sensibles restent auditées côté serveur.

### 4. Authentification native

1. Le client utilise le flux OIDC Authorization Code avec PKCE, conforme à ADR-0035, auprès de Keycloak ou du fournisseur fédéré configuré.
2. L'authentification interactive s'effectue dans le navigateur système, jamais dans un WebView embarqué contrôlé par le client.
3. Le retour vers l'application utilise un mécanisme de callback natif enregistré et vérifié (URI scheme ou listener loopback éphémère selon la plateforme), avec état anti-CSRF, nonce, validation stricte de l'émetteur et échange PKCE.
4. Les politiques MFA restent appliquées par l'IdP et les services OpenBastion (ADR-0062 et ADR-0065). Le client ne prétend pas fournir une implémentation native WebAuthn/FIDO2 tant qu'un mécanisme de plateforme sûr et portable n'a pas été validé.
5. Aucun flux Resource Owner Password Credentials, mot de passe IdP stocké localement ou secret client statique n'est introduit.

### 5. Organisation du code

Le client est ajouté au monorepo sous `desktop/fyne-client/`, comme module Go dédié raccordé à `go.work` selon ADR-0002. La structure initiale proposée est :

```text
desktop/fyne-client/
  go.mod
  cmd/openbastion-desktop/
    main.go
  internal/
    app/                 # cycle de vie et composition Fyne
    auth/                # OIDC/PKCE et callback système
    gateway/             # client REST, WebSocket et gestion TLS
    sessions/            # cas d'usage et états de session
    terminal/            # rendu et saisie SSH
    screen/               # rendu image et événements clavier/souris RDP/VNC
    approvals/            # demandes et suivi d'approbation
    audit/                # consultation des événements autorisés
    securestore/          # abstraction minimale pour secrets locaux temporaires
    settings/             # préférences non sensibles
    ui/
      views/
      widgets/
      theme/
  assets/
  packaging/
  test/
```

Les couches UI ne contiennent pas de logique d'autorisation. Les cas d'usage dépendent d'interfaces Go, et les adaptateurs réseau restent isolés. Les moteurs SSH/RDP/VNC du backend ne sont pas importés dans le client.

### 6. Contraintes de compilation et de distribution

1. Le code applicatif est Go, mais Fyne Desktop utilise des pilotes natifs qui requièrent **CGO** et une toolchain C adaptée à la plateforme. « Client développé en Go » ne signifie donc pas « compilation sans CGo ».
2. La CI doit compiler et tester au minimum Linux, Windows et macOS sur des runners adaptés, avec les dépendances système documentées et les versions de toolchain épinglées.
3. Les artefacts sont signés, accompagnés de leur provenance et SBOM, puis publiés selon la chaîne de livraison existante (ADR-0094).
4. Le packaging et la mise à jour ne doivent pas exécuter de code téléchargé non vérifié. La vérification de signature et de provenance précède toute installation ou mise à jour.
5. Les builds reproductibles, la réduction de surface de dépendances et la revue des licences sont des critères de livraison, pas des tâches postérieures à la v1.

### 7. Critères avant le premier incrément fonctionnel

Avant de déclarer le socle prêt :

- valider les builds Fyne sur Linux, Windows et macOS, incluant les toolchains CGO ;
- valider le cycle OIDC/PKCE avec navigateur système et callback sur chaque OS ;
- démontrer qu'aucun accès réseau direct à une cible n'est possible ;
- démontrer l'absence de jetons, cookies, secrets et contenus de session dans les logs et fichiers locaux ;
- tester l'attachement SSH et RDP/VNC avec les contrats de la Gateway, y compris expiration, révocation et refus ;
- mesurer le rendu écran, le débit d'événements et la consommation mémoire sur une session longue ;
- vérifier l'accessibilité clavier, le redimensionnement, le scaling DPI et les thèmes clair/sombre ;
- valider les dépendances Fyne et tout composant `fyne-x` retenu par analyse de licence et de vulnérabilités.

Aucune session réelle n'est activée par un prototype qui n'a pas passé ces contrôles.

## Conséquences

- (+) Un seul langage applicatif pour le client et les services : Go ; moins de duplication de modèles, d'outillage et de compétences.
- (+) Application desktop native sans runtime WebView, bundle JavaScript ou couche Rust/Tauri.
- (+) Réutilisation des contrats Gateway/Broker/proxies et maintien des invariants PAM côté serveur.
- (+) Le client ne possède aucun accès direct aux cibles ni aux secrets des comptes privilégiés.
- (+) Fyne fournit les primitives UI multiplateformes ; `fyne-x` peut enrichir l'interface sans imposer ses composants à l'architecture.
- (−) CGO et les toolchains natives augmentent la complexité de compilation et de packaging.
- (−) Les widgets riches (terminal, écran distant, presse-papiers, raccourcis clavier) demanderont des composants Fyne dédiés et des tests de performance/accessibilité.
- (−) Les capacités d'intégration OS et d'authentification forte doivent être validées par plateforme ; Fyne ne remplace pas les API natives de sécurité.
- (−) Le choix Fyne ne rend pas l'application « Go pur » au sens d'une compilation sans dépendances C natives.
- (−) Cette décision ne constitue pas une autorisation de démarrer l'implémentation : les critères de la section 7 et les ADR complémentaires doivent être traités.

## Alternatives envisagées

- **Tauri (Rust + WebView + frontend web)** : écarté pour le futur Desktop Client car il maintient une pile frontend distincte du backend Go et un runtime WebView. L'Admin UI web reste React/Vite.
- **Wails** : écarté comme choix principal ; bien qu'il expose une API Go et une UI web, il conserve une dépendance au rendu WebView et à une pile frontend.
- **Electron** : écarté en raison du runtime Chromium/Node.js embarqué et de son empreinte.
- **Gio** : non retenu à ce stade ; Fyne présente un socle de widgets et un écosystème plus directement adaptés au besoin d'une application d'administration multiplateforme. À réévaluer seulement si un prototype révèle une limite bloquante.
- **Fyne Core seul, sans évaluer `fyne-x`** : retenu comme point de départ ; les extensions ne sont ajoutées qu'en réponse à un besoin démontré.
