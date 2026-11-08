# ADR-0081 — Veille RDP externe et intégration sélective des enseignements

- **Statut** : Proposé
- **Date** : 2026-11-08
- **Décideurs** : Mainteneurs OpenBastion
- **Périmètre** : proxy RDP/VNC, moteur RDP Go pur, enregistrement, sécurité transport et interopérabilité

## Contexte

OpenBastion développe un proxy RDP original en Go, intégré au modèle PAM du projet. Le proxy doit terminer la connexion vers la cible, ne jamais exposer les credentials au control plane, vérifier l'identité TLS de la cible, exiger l'enregistrement de session et appliquer les règles d'autorisation et de révocation définies par les ADR existantes.

Trois dépôts externes constituent des références techniques suivies :

- [bouncyball-git/gopher-rdp](https://github.com/bouncyball-git/gopher-rdp) : bibliothèque/client RDP Go pur, avec une couverture étendue de codecs, canaux virtuels et modes de rendu.
- [casvisor/gordp](https://github.com/casvisor/gordp) : moteur RDP Go pur utilisé par Casvisor, avec callbacks, événements de redirection, GFX et primitives de replay.
- [casvisor/casvisor](https://github.com/casvisor/casvisor) : bastion d'accès distant qui fournit des références produit pour les politiques d'accès, les sessions, l'audit et les passerelles réseau.

Ces projets évoluent indépendamment. Leurs fonctionnalités, niveaux d'interopérabilité, modèles de confiance, dépendances, licences et pratiques de sécurité peuvent changer. Une veille régulière est nécessaire, sans transformer OpenBastion en simple intégrateur de bibliothèques tierces.

À la date de rédaction, OpenBastion possède un socle RDP Go pur substantiel (X.224/HYBRID, TLS épinglé, CredSSP/NTLMv2, MCS/GCC, licensing partiel, négociation de capacités et décodage graphique partiel). Le runtime RDP demeure désactivé et l'interopérabilité Windows/RDS réelle n'est pas encore démontrée. Le parcours VNC de bout en bout a été validé avec TigerVNC 1.13.1 ; ses limites fonctionnelles restent documentées dans `docs/security/known-limitations.md`.

## Décision

1. **Maintenir une veille hebdomadaire** sur les trois dépôts nommés ci-dessus, leurs releases, tags, commits, pull requests, issues et avis de sécurité pertinents.
2. **Produire un rapport hebdomadaire différentiel** qui identifie :
   - les nouvelles fonctionnalités RDP, codecs, ordres graphiques, canaux virtuels et capacités de redirection ;
   - les corrections de sécurité, vulnérabilités, changements cryptographiques et durcissements TLS/CredSSP/NTLM ;
   - les améliorations de robustesse, interopérabilité Windows/RDS, tests, fuzzing, performance, mémoire et concurrence ;
   - les changements de licence, dépendances et provenance ;
   - la pertinence pour OpenBastion, le risque, les preuves et une recommandation : adopter le concept, réimplémenter, tester, surveiller ou rejeter.
3. **Ne pas intégrer automatiquement du code tiers**. La veille sert à éclairer les décisions ; toute dépendance ou reprise de code nécessite une ADR ou une mise à jour d'ADR, une revue de licence/provenance, une revue sécurité et des tests dédiés.
4. **Préserver une implémentation originale** du protocole RDP dans OpenBastion. Les idées et comportements protocolaires documentés peuvent guider une implémentation indépendante ; aucun code propriétaire, secret, test non autorisé ou élément protégé ne doit être copié.
5. **N'accepter aucune régression des invariants existants** :
   - secrets hors du control plane (ADR-0003) ;
   - session enregistrée ou refusée, perte d'enregistrement traitée en mode fail-closed (ADR-0008 et ADR-0070) ;
   - identité de cible vérifiée et pin TLS contrôlé avant authentification (ADR-0069 et ADR-0071) ;
   - mTLS interne et autorisation d'appelant explicite (ADR-0010) ;
   - tickets à usage unique, révocation effective et audit des actions.
6. **Ne jamais importer un comportement de sécurité permissif sans justification** : validation de certificat désactivée, pinning optionnel par défaut, downgrade TLS, protocoles cryptographiques obsolètes, authentification permissive, redirections non bornées ou enregistrement désactivable sont des signaux de rejet jusqu'à preuve d'une alternative sûre.
7. **Transformer les résultats validés en travail OpenBastion traçable** : issue ou tâche ciblée, test de non-régression, mise à jour de `docs/security/known-limitations.md`, roadmap et documentation de protocole lorsque l'état du dépôt change.

## Critères d'évaluation

Chaque observation est évaluée selon les axes suivants :

| Axe | Questions |
|---|---|
| Sécurité | Validation TLS, pinning, CredSSP, NTLM, parsing borné, authentification, redirections, secrets, audit et fail-closed |
| Couverture RDP | X.224, NLA/CredSSP, MCS/GCC, licensing, capabilities, slow/fast path, drawing orders, codecs, GFX et virtual channels |
| Interopérabilité | Windows Server/RDS, versions clientes/serveurs, modes NLA, certificats, licences CAL et scénarios négatifs |
| Enregistrement | Complétude, ordre, horodatage, chiffrement, acquittement, replay et corrélation audit |
| Robustesse | Fuzzing, limites mémoire/CPU, timeouts, fragmentation, concurrence, tests race et gestion des erreurs |
| Exploitabilité | Observabilité, diagnostics, déploiement, configuration sûre et compatibilité cloud/on-prem |
| Licence/provenance | Licence SPDX, dépendances transitives, notices, provenance et compatibilité avec AGPL-3.0 |

Une fonctionnalité n'est considérée comme « disponible » dans OpenBastion qu'après implémentation, tests pertinents et activation effective dans le runtime. Un décodeur présent mais non raccordé, une capacité non annoncée ou un test contre un serveur de substitution ne prouvent pas l'interopérabilité Windows/RDS.

## Conséquences

### Positives

- Les évolutions externes alimentent une roadmap RDP priorisée et fondée sur des preuves.
- Les corrections de sécurité pertinentes peuvent être détectées rapidement.
- Les écarts entre moteur protocolaire, runtime, tests et documentation sont explicitement suivis.
- OpenBastion conserve la maîtrise de ses invariants PAM et de son implémentation.

### Négatives et coûts

- La veille exige un rapport régulier et une qualification humaine des changements.
- Les écarts de protocole et les régressions devront être reproduits dans des tests OpenBastion avant adoption.
- Une réimplémentation originale peut coûter plus cher qu'une dépendance, mais réduit le risque de couplage et préserve le contrôle de sécurité.

## Alternatives envisagées

- **Adopter directement gopher-rdp ou gordp** : rejeté à ce stade. La couverture protocolaire ne suffit pas à établir la conformité aux invariants de sécurité et d'enregistrement d'OpenBastion.
- **Remplacer le proxy par Casvisor** : rejeté. Casvisor est un benchmark produit utile, mais son architecture et ses arbitrages ne correspondent pas à la séparation de services et aux garanties de contrôle d'OpenBastion.
- **Ne pas effectuer de veille structurée** : rejeté. Cela ferait perdre les corrections de sécurité et les avancées d'interopérabilité utiles.
- **Réexaminer une dépendance à l'avenir** : possible uniquement après audit complet, validation de licence/provenance, threat modeling et ADR dédiée.

## Références

- [ADR-0003 — Les secrets ne traversent jamais le control plane](0003-les-secrets-ne-traversent-jamais-le-control-plane.md)
- [ADR-0008 — Enregistrer ou refuser](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md)
- [ADR-0010 — mTLS interne](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md)
- [ADR-0069 — Le proxy RDP vérifie la cible](0069-le-proxy-rdp-verifie-la-cible-et-refuse-les-sessions-non-enregistrees.md)
- [ADR-0070 — Le Video Recorder acquitte les segments](0070-le-video-recorder-acquitte-des-segments-chiffres-avant-de-les-servir.md)
- [ADR-0071 — Proxy RDP/VNC Go pur](0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md)
- [Limites connues](../security/known-limitations.md)
- [Roadmap](../roadmap.md)
