# ADR-0072 — Les exécutables OpenBastion adoptent Cobra et exposent une version de build homogène

**Statut** Proposé · 6 novembre 2026 · aucun changement de code ni aucune dépendance Cobra ne sont introduits avant acceptation explicite de cet ADR.

## Contexte

Le dépôt ne possède pas un seul programme en ligne de commande. Il contient plusieurs exécutables Go, avec des modes d'administration, des commandes de PKI et des processus de service. Une migration qui ne couvrirait que cli/openbastion-cli laisserait des interfaces incohérentes et empêcherait de diagnostiquer simplement le binaire réellement déployé.

Inventaire vérifié dans le dépôt :

| Exécutable | Rôle et commandes actuelles |
|---|---|
| cli/openbastion-cli | CLI opérateur : user create, audit verify-chain, mfa enrollment-code, mfa reset, mfa keys, mfa revoke-key, version |
| pkg/mtls/cmd/openbastion-pki | Outil PKI : init, issue, all |
| services/access/api-gateway/cmd/api-gateway | Processus API Gateway |
| services/access/authentication/cmd/authentication | Processus Authentication |
| services/access/authorization/cmd/authorization | Processus Authorization |
| services/access/session-broker/cmd/session-broker | Processus Session Broker |
| services/proxy/rdp-vnc-proxy/cmd/rdp-vnc-proxy | Processus RDP/VNC Proxy |
| services/proxy/ssh-proxy/cmd/ssh-proxy | Processus SSH Proxy |
| services/recording-audit/audit-service/cmd/audit-service | Processus Audit Service |
| services/recording-audit/command-recorder/cmd/command-recorder | Processus Command Recorder |
| services/recording-audit/video-recorder/cmd/video-recorder | Processus Video Recorder |
| services/vault/password-vault/cmd/password-vault | Processus Password Vault |

Cela représente **12 exécutables de production**. test/integration/cmd/demo-ssh-target est un binaire de fixture réservé aux tests : il n'est pas un outil ni un service livré et reste hors du périmètre de cette migration.

pkg/buildinfo expose aujourd'hui la version estampillée et un commit, mais pas une fiche de build uniforme. La CLI opérateur affiche seulement buildinfo.String() et les services inscrivent cette forme compacte dans leur journal. Il manque une commande standard, utilisable sans démarrer un serveur ni contacter un service, pour identifier précisément un binaire.

## Décision proposée

### 1. Périmètre et bibliothèque de commandes

Adopter github.com/spf13/cobra pour les arbres de commandes des exécutables de production listés ci-dessus :

- openbastion-cli conserve ses commandes opérateur et ses contrats existants ;
- openbastion-pki conserve init, issue et all ;
- chaque binaire de service conserve son comportement de démarrage par défaut, porté par la commande racine, et ajoute la sous-commande version ;
- chaque exécutable fournit donc la même commande version et la même option --short.

Créer un petit module partagé pkg/command pour les éléments Cobra transverses (au minimum la construction de la commande version). Il dépend de pkg/buildinfo et de Cobra. Les commandes métier restent dans leur module et leur domaine ; le module partagé ne connaît ni les clients réseau, ni les services, ni les secrets.

La CLI opérateur est organisée ainsi :

    openbastion-cli user create
    openbastion-cli audit verify-chain
    openbastion-cli mfa enrollment-code
    openbastion-cli mfa reset
    openbastion-cli mfa keys
    openbastion-cli mfa revoke-key
    openbastion-cli version [--short]

La PKI est organisée ainsi :

    openbastion-pki init
    openbastion-pki issue
    openbastion-pki all
    openbastion-pki version [--short]

Les dix commandes de service conservent le démarrage normal sans argument. Leur racine Cobra exécute le démarrage du service ; version est un chemin sans effet de bord qui s'arrête avant toute initialisation réseau, base de données, mTLS, coffre ou recorder.

### 2. Contrat de version, identique sur les douze exécutables

<binaire> version écrit exactement quatre champs, dans cet ordre, sur la sortie standard :

    Version:           dev
    Go version:        go1.27.3
    Built:             b75be22
    OS/Arch:           linux/amd64

Les valeurs sont dynamiques et proviennent du binaire exécuté, pas de constantes propres à l'exemple :

- Version : valeur pkg/buildinfo.Version, estampillée par les -ldflags de construction ; dev sans estampille ;
- Go version : runtime.Version() ;
- Built : révision VCS enregistrée par runtime/debug.ReadBuildInfo, limitée à sept caractères hexadécimaux ; unknown si la révision n'est pas disponible ;
- OS/Arch : runtime.GOOS + "/" + runtime.GOARCH.

<binaire> version --short écrit uniquement la valeur de Version suivie d'un saut de ligne, sans libellé, préfixe, décoration ni autre sortie. Le contrat d'acceptation comprend cet exemple exact :

    $ openbastion-cli version --short
    dev

La même forme doit fonctionner pour openbastion-pki et chacun des dix binaires de service. --short est une option de la commande version, pas une option globale. Les arguments inconnus ou incompatibles avec version sont refusés avec un code de sortie non nul.

Ajouter à pkg/buildinfo une représentation structurée des quatre champs et un formateur détaillé. Garder buildinfo.String() et son rendu compact actuels stables pour ne pas modifier implicitement les journaux de démarrage ni les consommateurs existants ; la nouvelle commande version utilise le formateur détaillé. La version courte lit le même champ Version que la sortie détaillée.

Les constructions doivent conserver les -ldflags de version existants et les métadonnées VCS Go (-buildvcs=true lorsque la source Git est disponible). Une construction depuis une archive ou un contexte sans métadonnées VCS reste possible et affiche unknown pour Built ; elle ne doit pas inventer une révision.

### 3. Compatibilité CLI opérateur

Préserver les noms et la signification des options existantes, notamment leur forme à tiret simple, tout en acceptant la forme à double tiret prise en charge par Cobra/pflag :

| Commande | Options conservées |
|---|---|
| user create | -authn, -username, -roles, -display |
| audit verify-chain | -audit |
| mfa enrollment-code | -authn, -local, -directory |
| mfa reset | -authn, -username |
| mfa keys | -authn, -username |
| mfa revoke-key | -authn, -username, -key |

Les paramètres obligatoires sont validés avant tout appel réseau. -local et -directory restent mutuellement exclusifs. Les arguments positionnels superflus et les options inconnues sont refusés. Les handlers utilisent RunE, avec les flux stdin/stdout/stderr injectés pour les tests.

### 4. Sécurité et absence de régression

- Aucun constructeur de commande, PersistentPreRunE ou PreRunE ne déclenche d'effet de bord ; les effets sont dans le handler explicitement exécuté.
- Le mot de passe de user create reste lu depuis stdin uniquement. Aucun flag --password, argument positionnel, variable d'environnement implicite ou fichier de configuration ne l'expose.
- L'identité mTLS mtls.AdminCLI, INTERNAL_TLS=required, la vérification du pair attendu et les routes internes restent obligatoires ; aucune option Cobra ne peut désactiver ou contourner ces contrôles.
- Les codes MFA à usage unique restent affichés une seule fois sur stdout après réponse valide ; ils ne sont jamais journalisés.
- Les services gardent leurs variables d'environnement, leurs valeurs par défaut, leurs validations, leurs signaux et leur ordre d'initialisation actuels. La sous-commande version ne lit aucun secret et n'ouvre aucune connexion.
- Ne pas introduire Viper, de chargement implicite de configuration, de commande de complétion automatique dans cette première migration, ni de flag --version concurrent de version.
- La commande version ne change pas le format existant de buildinfo.String() dans les journaux.

### 5. Organisation cible indicative

    pkg/buildinfo/
      buildinfo.go
      buildinfo_test.go
    pkg/command/
      go.mod
      version.go
      version_test.go
    cli/openbastion-cli/
      main.go
      internal/command/
        root.go
        user.go
        audit.go
        mfa.go
        version.go
      internal/operator/
        client.go
        user.go
        audit.go
        mfa.go
    pkg/mtls/cmd/openbastion-pki/
      main.go
      command/
        root.go
        init.go
        issue.go
        all.go
    services/<domaine>/<service>/cmd/<binaire>/
      main.go
      command.go

Cette arborescence est une cible de séparation des responsabilités, pas une obligation de déplacer la logique métier existante si cela augmente inutilement le risque. Les services peuvent garder leurs fonctions de démarrage dans leur module et ne déléguer à Cobra que le dispatch et l'exécution.

### 6. Dépendances et gouvernance

- Épingler une version stable de github.com/spf13/cobra dans les modules qui l'importent et committer go.mod/go.sum ; aucune dépendance téléchargée à la volée à l'exécution.
- Ne pas ajouter Viper ni un framework de configuration.
- La dépendance commune à Cobra est centralisée dans pkg/command autant que possible ; les modules ne dupliquent pas le formatage de version.
- La migration est découpée en changements testables : pkg/buildinfo et pkg/command, CLI opérateur, PKI, puis services par lots. Chaque lot conserve un démarrage et des comportements vérifiés avant le suivant.

## Conséquences

### Positives attendues

- Un opérateur peut identifier chaque binaire avec la même commande, y compris dans une image ou un pod, sans initialiser le service.
- La forme courte est stable pour les scripts et les sondes de diagnostic : version --short ne renvoie que la version.
- Cobra apporte une arborescence, l'aide, la validation des arguments et un comportement d'erreur cohérent, sans mélanger le dispatch CLI et les opérations métier.
- Les douze exécutables de production sont recensés ; l'outil de test demo-ssh-target reste explicitement exclu.

### Coûts et limites

- Cobra devient une dépendance de construction des exécutables concernés ; la version est épinglée et soumise aux contrôles de dépendances existants.
- Les services ont une commande racine dont le RunE doit préserver exactement le cycle de vie actuel. Une migration service par service est préférable à une réécriture simultanée.
- Built n'est pas une preuve cryptographique de provenance. La signature et l'attestation des artefacts restent des sujets distincts.
- unknown est attendu si les métadonnées VCS sont absentes ; les builds de release doivent être réalisés depuis un checkout traçable.
- Le changement d'affichage détaillé concerne la commande explicite version, pas les journaux actuels.

### Tests et critères d'acceptation obligatoires

1. pkg/buildinfo : tests unitaires des valeurs, du format détaillé, de la forme courte, des valeurs de repli et de l'absence de révision VCS.
2. pkg/command : la sortie courte est strictement dev suivi d'un saut de ligne pour une version dev ; la sortie détaillée contient les quatre champs, dans l'ordre et sans champ manquant.
3. Pour chacun des douze exécutables : test de fumée version --short sans réseau ni effet de bord ; le binaire de service ne doit pas démarrer son serveur sur ce chemin.
4. Pour chaque binaire : version affiche les quatre valeurs correspondant à ce binaire (Go, OS/architecture et révision compris).
5. CLI opérateur : tests de l'arbre Cobra, aide, options historiques à tiret simple et double, validation avant réseau, refus des arguments inconnus, stdin du mot de passe, absence de flag mot de passe, mTLS obligatoire et identité de pair attendue.
6. PKI : tests des trois commandes existantes, des options et de leurs erreurs, sans modifier les durées de validité ni le format des certificats.
7. Services : tests que le démarrage sans argument conserve ses valeurs d'environnement et son comportement, et que version quitte avant toute initialisation réseau/stockage.
8. Gates du dépôt : make build vet test proto-lint, tests ciblés -race des modules touchés, gofmt et git diff --check.
9. Vérifier les binaires construits depuis le Makefile et les Dockerfiles, pas seulement les tests go run, afin de prouver que l'estampillage et les métadonnées VCS arrivent jusqu'aux exécutables.

## Alternatives envisagées

- **Garder flag de la bibliothèque standard** : dépendance évitée, mais chaque binaire continuerait à réinventer son aide, ses sous-commandes et son formatage. Écarté pour les outils opérateur et PKI ; les services auraient malgré tout besoin d'un dispatch uniforme.
- **Cobra uniquement dans openbastion-cli** : migration plus petite, mais laisse la PKI et les services sans contrat commun de diagnostic. Écarté au vu de l'inventaire des douze exécutables.
- **urfave/cli ou Kong** : alternatives viables, mais Cobra offre un modèle de commandes imbriquées éprouvé et un écosystème Go largement utilisé. Une seule bibliothèque est retenue.
- **Viper pour les configurations** : non retenu ; les services conservent leur contrat d'environnement explicite et la CLI ne charge pas de configuration implicite.
- **Répéter la construction de version dans chaque module** : duplication et dérive de format. Écarté au profit de pkg/command.
