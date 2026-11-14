# ADR-0107 — Le Security Agent collecte une télémétrie structurée en lecture seule

**Statut** Proposé · 14 novembre 2026

**Contexte**

Les proxies enregistrent les sessions, mais ne voient pas nécessairement les changements locaux hors session. La télémétrie hôte permet de corréler connexions, processus, élévations et modifications. Elle n'est pas une preuve indépendante : un hôte compromis peut falsifier ou supprimer ses événements.

**Décision**

1. Security Agent collecte en lecture seule via journald/auditd et sources Linux disponibles, Windows Event Log et ETW selon les permissions. eBPF reste optionnel.
2. Premières familles : authentification, élévation, processus, comptes, services, configuration SSH, intégrité de fichiers critiques et changements réseau.
3. Chaque événement porte identifiant, séquence monotone, horodatage observé, famille, version de schéma et payload structuré borné. Credentials, tokens, clés privées, secrets et contenus de session sont exclus.
4. Une file locale chiffrée et bornée absorbe une panne temporaire. À saturation, l'agent signale les pertes et séquences manquantes ; aucune perte n'est silencieuse.
5. Le serveur acquitte les séquences acceptées. Les doublons sont idempotents ; trous, retards, dérives d'horloge et absence de heartbeat deviennent des événements de santé.
6. La télémétrie est marquée source=host-agent avec classe de confiance distincte. Elle ne remplace jamais les événements du Broker, des proxies ou de l'Audit Service.
7. Les actions de réponse automatique (isolation, arrêt de processus, désactivation de compte) sont hors périmètre v0.0.3.

**Conséquences**

- (+) Les événements hors session peuvent être corrélés aux sessions PAM.
- (+) Les pertes de collecte sont visibles.
- (−) Les sources et privilèges varient selon OS et distribution.
- (−) Une télémétrie signée ne prouve pas la vérité d'un hôte compromis.
- (−) Les données personnelles exigent minimisation, contrôle d'accès et rétention.

**Alternatives envisagées**

- **Présenter l'agent comme EDR** : rejeté, périmètre limité à la télémétrie PAM/conformité.
- **Réponse automatique** : reportée, risque d'interruption sur faux positif.
- **Télémétrie comme preuve d'audit principale** : rejetée, source contrôlable par l'hôte.