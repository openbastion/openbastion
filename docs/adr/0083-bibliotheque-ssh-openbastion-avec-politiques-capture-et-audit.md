# ADR-0083 — La bibliothèque SSH OpenBastion intègre politiques, capture et audit au cycle protocolaire

- **Statut** : Proposé
- **Date** : 2026-11-08
- **Décideurs** : Mainteneurs OpenBastion
- **Périmètre** : future bibliothèque Go publique `github.com/openbastion/ssh`, SSH Proxy et contrats d'intégration

## Contexte

Le SSH Proxy d'OpenBastion possède déjà un parcours de session intégré au modèle PAM : authentification côté client, connexion à la cible avec identité d'hôte épinglée, shell/PTY, exec contrôlé, SFTP/SCP, enregistrement et révocation. Ces garanties sont aujourd'hui distribuées entre le proxy, `pkg/proxycore`, les codecs de transfert, le Vault, le Command Recorder et l'Audit Service.

Une bibliothèque SSH réutilisable doit rendre ces comportements accessibles sans rendre le moteur dépendant des microservices OpenBastion. Le projet `melbahja/goph` constitue une référence d'ergonomie d'API Go (client, commandes, contexte, SFTP, clés et proxy), pas un moteur de capture de commandes, de règles ou d'audit. OpenBastion ne doit ni le présenter comme tel, ni en copier le code.

Le besoin est donc de séparer le cœur protocolaire SSH des capacités PAM qui doivent intervenir au bon moment du cycle d'une session. La distinction est importante : une requête SSH `exec` est une chaîne opaque transmise au serveur distant ; elle ne prouve pas quelles commandes un shell exécutera ensuite. Un shell interactif/PTY ne permet pas non plus de reconstruire de manière fiable chaque commande réellement interprétée.

## Décision

1. **Créer une bibliothèque Go autonome** sous le module public `github.com/openbastion/ssh`, publiée sous AGPL-3.0, avec sa propre documentation, ses exemples, sa politique de compatibilité et ses tests. Le code sera original ; les références externes n'autorisent aucune copie d'implémentation.
2. **Séparer les couches** :
   - cœur protocolaire : transport SSH, échange de clés, authentification, channels, requests, exec, shell/PTY et subsystems ;
   - capacités : gestion de session, exécution de commandes, transferts et instrumentation ;
   - ports de sécurité : politique, enregistrement, audit et vérification d'identité de cible ;
   - adaptateurs : intégration au SSH Proxy et à `pkg/proxycore`, hors du cœur de la bibliothèque.
3. **Exposer des contrats injectables**, sans dépendance directe à PostgreSQL, Redis, NATS, Kafka, OpenSearch, MinIO ou aux services HTTP d'OpenBastion. Les contrats publics devront couvrir au minimum :
   - `Policy.Evaluate(ctx, request) -> decision` ;
   - `Recorder.Prepare(ctx, event) -> receipt`, puis `Complete(ctx, receipt, result)` ;
   - `Auditor.Emit(ctx, event)` ;
   - `HostKeyVerifier.Verify(ctx, target, presentedKey)` ;
   - cycle de vie et annulation de session.
   Les types définitifs seront stabilisés après revue des usages réels du proxy ; ces signatures sont conceptuelles, pas encore une API garantie.
4. **Imposer l'ordre d'exécution suivant** pour toute opération contrôlée : authentifier le client et identifier la cible ; vérifier la clé/certificat d'hôte ; évaluer la politique ; faire acquitter l'événement préalable par le Recorder et l'Auditor selon le contrat applicable ; seulement ensuite transmettre ou démarrer l'opération ; enfin enregistrer son résultat. Une panne de politique, d'enregistrement obligatoire ou d'audit obligatoire refuse l'opération (fail-closed).
5. **Ne jamais confondre capture et interprétation** :
   - pour `exec`, capturer la requête exacte reçue, la décision, les flux, le code de sortie et les métadonnées bornées ; ne pas affirmer que cette chaîne décrit toutes les commandes effectivement exécutées ;
   - pour shell/PTY, capturer le flux terminal et les événements clavier autorisés, avec horodatage ; ne pas promettre une détection fiable de chaque commande, alias, script ou commande multi-ligne ;
   - pour SFTP/SCP et futurs modes de transfert, observer les opérations au niveau du protocole et acquitter les événements avant le transfert des données correspondantes ;
   - rsync distant reste régi par ADR-0082 et son mode dédié ; il ne devient pas une commande shell générique.
6. **Définir les règles comme des décisions de politique**, pas comme du code de stockage : identité utilisateur, compte privilégié, cible, type de canal, mode d'exécution, commande exec reconnue, transfert, fenêtre horaire, durée et contraintes de session. Un refus explicite l'emporte sur toute autorisation ; absence de règle correspondante = refus, conformément aux invariants d'Authorization.
7. **Maintenir l'audit centralisé** : la bibliothèque émet des événements structurés, versionnés, bornés et associés à la session ; elle ne détient aucune clé de signature de la chaîne d'audit et ne remplace pas l'Audit Service. Aucun mot de passe, clé privée, jeton ou contenu secret ne doit apparaître dans les événements.
8. **Préserver les invariants existants** :
   - secrets hors du control plane (ADR-0003) ;
   - enregistrer ou refuser, y compris avant le démarrage d'une commande ou d'un transfert (ADR-0008 et ADR-0038) ;
   - mTLS interne et identité d'appelant issue du certificat (ADR-0010) ;
   - révocation et expiration terminent réellement les connexions (ADR-0018) ;
   - identité de cible vérifiée avant authentification (ADR-0039 et ADR-0048) ;
   - événements d'audit bornés et protégés (ADR-0025, ADR-0026, ADR-0027 et ADR-0068).
9. **Migrer progressivement** depuis `services/proxy/ssh-proxy`. Le proxy reste l'adaptateur et le point de contrôle de la plateforme ; aucune réécriture globale ni activation de comportement non couvert par les tests n'est autorisée. Les capacités existantes restent inchangées jusqu'à ce que la bibliothèque démontre une parité vérifiée.
10. **Valider avant publication** : tests unitaires, tests de conformité SSH, interopérabilité avec OpenSSH réel, fuzzing des parseurs et codecs, tests race, limites de mémoire/temps, tests d'ordre d'acquittement, révocation, recorder/audit indisponibles, clés d'hôte incorrectes et tests négatifs d'injection.

## Contrat fonctionnel initial

| Domaine | Contrat |
|---|---|
| Client et serveur | API Go contextuelle, erreurs typées, fermeture déterministe |
| Authentification | méthodes explicitement activées ; aucune méthode faible implicite |
| Identité de cible | vérification obligatoire ; aucun `InsecureIgnoreHostKey` par défaut |
| Exec | requête opaque capturée ; allow-list explicite fournie par la politique |
| Shell/PTY | flux terminal horodaté ; aucune promesse de sémantique shell |
| Subsystems | dispatch explicite, notamment SFTP |
| Enregistrement | préparation/acquittement avant opération contrôlée ; fail-closed |
| Audit | événements bornés, sans secret ; signature/chaînage délégués au service |
| Dépendances | cœur protocolaire indépendant des infrastructures OpenBastion |

## Conséquences

### (+) Résultats attendus, non encore mesurés

- Le proxy et d'autres applications Go pourront partager un moteur SSH sans importer les microservices.
- Les politiques et les points d'acquittement seront testables sans base de données ni bus.
- L'API publique permettra une évolution indépendante du cycle de livraison du monorepo.

Aucun de ces bénéfices n'est encore mesuré : la bibliothèque n'existe pas et aucune extraction n'a été réalisée.

### (−) Limites et coûts

- Le découplage et la stabilisation d'une API publique ajoutent une charge de maintenance et de compatibilité.
- La capture d'un `exec` ne révèle pas nécessairement les commandes exécutées après interprétation par le shell distant.
- Un PTY ne permet pas une attribution certaine de chaque commande ; une enforcement fiable nécessite un contrôle côté cible ou un environnement d'exécution contraint.
- Les fonctionnalités SSH avancées, algorithmes, extensions et compatibilités serveurs devront être explicitement déclarés et testés.
- La bibliothèque ne garantit pas seule l'intégrité de la chaîne d'audit, le stockage durable ou le chiffrement des enregistrements.
- La migration progressive peut maintenir temporairement deux chemins d'implémentation ; ils devront être comparés et l'ancien chemin ne sera retiré qu'après parité prouvée.
- L'API et les types proposés ici restent renversables jusqu'à leur implémentation et leur première version stable.

## Alternatives envisagées

- **Forker `melbahja/goph`** : rejeté ; le besoin porte aussi sur un moteur de proxy contrôlable et instrumentable, et non sur un simple client SSH. Aucune copie de code n'est nécessaire.
- **Ajouter les règles et l'audit directement au SSH Proxy** : rejeté comme architecture cible ; cela conserverait le couplage entre protocole et infrastructure et limiterait la réutilisation.
- **Faire dépendre la bibliothèque des services OpenBastion** : rejeté ; cela rendrait le module non autonome et difficile à tester.
- **Réécrire immédiatement le SSH Proxy** : rejeté ; risque de régression des invariants et absence de bénéfice démontré avant extraction incrémentale.
- **Promettre la capture sémantique de toutes les commandes PTY** : rejeté ; SSH ne fournit pas cette sémantique au proxy.

## Références

- [ADR-0003 — Les secrets ne traversent jamais le control plane](0003-les-secrets-ne-traversent-jamais-le-control-plane.md)
- [ADR-0008 — Enregistrer ou refuser](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md)
- [ADR-0010 — mTLS interne](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md)
- [ADR-0018 — Terminaison effective d'une session](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md)
- [ADR-0038 — SFTP et SCP à travers le proxy](0038-sftp-et-scp-a-travers-le-proxy-chaque-transfert-est.md)
- [ADR-0039 — Clé d'hôte épinglée](0039-la-cle-d-hote-de-chaque-cible-est-epinglee-au-vault-et.md)
- [ADR-0082 — rsync distant via SSH](0082-rsync-distant-passe-par-le-proxy-ssh-sans-shell-arbitraire.md)
