# ADR-0110 — Les événements agent sont attribués et séparés de la preuve d'audit PAM

**Statut** Proposé · 14 novembre 2026

**Contexte**

Les agents enrichissent l'audit avec des observations locales, mais l'hôte observé peut être compromis. Il faut prouver quel agent a émis un événement et détecter les pertes sans donner à cette télémétrie le même niveau de confiance qu'une décision du Broker ou qu'un enregistrement de proxy. ADR-0025 à ADR-0028 définissent les garanties de la chaîne d'audit.

**Décision**

1. Chaque lot est attribué au certificat mTLS et porte identifiant d'événement, séquence monotone, version de schéma et horodatage observé. L'identité du corps ne remplace jamais celle du certificat.
2. Le serveur ajoute heure de réception, identité authentifiée, état de révocation, validation et référence au lot. L'horodatage agent est une observation, pas l'horloge de référence.
3. La télémétrie est stockée avec provenance et classe de confiance distinctes. Elle ne peut pas écrire directement dans la chaîne d'audit faisant autorité ni fabriquer session.*, vault.* ou authorization.*.
4. Les décisions d'accès, sessions, récupérations de credentials et résultats de proxies restent émis par leurs composants responsables.
5. Les lots sont idempotents par agent et séquence. Doublons acquittés sans duplication ; trous, retards, retours de compteur et pertes produisent des alertes de qualité.
6. mTLS protège le transport. Une signature applicative par événement pourra être ajoutée pour export hors ligne, mais ne rendra pas véridique un événement issu d'un hôte compromis.
7. Taille, fréquence, profondeur et cardinalité sont bornées ; les erreurs ne journalisent pas les payloads bruts.
8. Rétention, accès, export et suppression suivent les politiques de données personnelles. Contenus de session et secrets sont exclus.

**Conséquences**

- (+) Origine et lacunes de télémétrie traçables sans confondre observation et preuve.
- (+) La chaîne d'audit conserve ses émetteurs autorisés.
- (−) Root/SYSTEM compromis peut produire des observations fausses signées par l'agent.
- (−) Corrélation temporelle exige heure observée et heure de réception.
- (−) Volume et données personnelles augmentent les coûts de stockage et de gouvernance.

**Alternatives envisagées**

- **Écriture directe dans Audit Service comme émetteur de confiance** : rejetée, la télémétrie n'est pas une preuve indépendante.
- **Signature = événement infalsifiable** : rejetée, une clé compromise peut signer un mensonge.
- **Ignorer les pertes de collecte** : rejeté, une absence d'événement ne signifie pas absence d'activité.