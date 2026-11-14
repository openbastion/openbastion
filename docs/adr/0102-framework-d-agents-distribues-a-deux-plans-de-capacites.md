# ADR-0102 — Le framework d'agents sépare le transport réseau de la télémétrie de sécurité

**Statut** Proposé · 14 novembre 2026

**Contexte**

OpenBastion ne dispose pas encore de passerelle sortante pour les réseaux privés ni de collecteur hôte. Un agent unique cumulant tunnel réseau, collecte système et exécution administrative concentrerait des privilèges excessifs. La décision touche ADR-0003 (aucun secret dans le control plane), ADR-0008 (enregistrer ou refuser), ADR-0010 (identité mTLS) et ADR-0050 (transport interne).

**Décision**

1. Le framework comprend deux produits et deux domaines de privilèges indépendants : **Network Agent**, pour les flux vers des cibles autorisées, et **Security Agent**, pour la collecte locale en lecture seule.
2. Les deux peuvent partager des bibliothèques sans état, mais jamais un processus privilégié, une clé privée, un compte système, un socket IPC permissif ou un droit d'exécution.
3. Aucun agent n'authentifie l'opérateur ni ne décide de son autorisation. Authentication Service, Authorization Service, Session Broker et proxies gardent leurs responsabilités.
4. Aucun agent n'expose shell, exécution de commande arbitraire, transfert de fichiers générique, SOCKS ou routage réseau transparent.
5. L'indisponibilité du Security Agent ne désactive pas les contrôles PAM. L'indisponibilité du Network Agent empêche toute nouvelle connexion par ce chemin.
6. Les contrats sont versionnés sous proto/agent/v1. La v0.0.3 formalise l'architecture et les contrats ; elle ne déclare pas un agent de production disponible.

**Conséquences**

- (+) Une vulnérabilité du collecteur ne donne pas automatiquement accès au routage.
- (+) Les privilèges, tests et cycles de livraison sont séparables.
- (−) Deux binaires et profils de configuration augmentent le coût d'exploitation.
- (−) Les bibliothèques partagées restent une surface commune.
- (−) Ce framework n'est ni un EDR ni une garantie d'intégrité d'un hôte compromis.

**Alternatives envisagées**

- **Agent monolithique** : rejeté, rayon d'impact excessif.
- **Agent par protocole et par cible** : rejeté au départ ; les proxies centraux gardent la logique protocolaire.
- **Aucun agent** : ne résout pas les réseaux privés sans entrée réseau ni la télémétrie hôte.