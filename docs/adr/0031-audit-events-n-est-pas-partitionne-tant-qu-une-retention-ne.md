# ADR-0031 — `audit_events` n'est pas partitionné tant qu'une rétention ne garde pas la chaîne vérifiable


**Contexte**
`docs/architecture/data-architecture.md` §3 prévoit `audit_events` partitionné par mois (`PARTITION BY RANGE (ts)`), pour garder les index performants et pour archiver « par partition entière ». `001_init.sql` ne l'a jamais fait. ADR-0030 donnait enfin sa place à une migration non additive ; avant de l'écrire, j'ai mesuré sur PostgreSQL 16, dans un schéma jetable :

- **Plus d'unicité globale** : `UNIQUE (id)` et `PRIMARY KEY (seq)` sont refusés sur une table partitionnée par `ts` (« unique constraint on partitioned table must include all partitioning columns ») ; avec `UNIQUE (id, ts)`, **le même identifiant est accepté deux fois**, dans deux mois.
- **Une insertion hors de toute partition échoue** (« no partition of relation … found for row »). L'audit est fail-closed : une partition manquante arrêterait toute action auditée de la plateforme.
- **La conversion d'une table existante** : **41 s par million d'événements**, en une transaction, sous le verrou de migration — l'Audit Service, donc l'audit de toute la plateforme, est indisponible pendant ce temps.
- **Lire toute la chaîne** (`ORDER BY seq`, ce que fait `verify-chain`) : **1,0 s → 2,3 s** pour un million d'événements ; `Last` (`ORDER BY seq DESC LIMIT 1`) devient un `Merge Append` sur toutes les partitions, parce que `seq` n'est pas la clé de partition.
- **Le bénéfice attendu n'existe pas encore** : supprimer une vieille partition casse `verify-chain` (le premier événement restant a un `prev_hash` que plus rien ne justifie) et les ancres d'ADR-0028 qui nomment les événements supprimés. Partitionner ne sert à archiver qu'une fois une rétention qui garde la chaîne vérifiable conçue — ce qui manque.

Bony Kiss a choisi « la rétention d'abord ».

**Décision**
1. `audit_events` reste une table non partitionnée ; aucune migration de partitionnement n'est écrite.
2. La rétention est conçue d'abord (ADR-0032), sans dépendre du partitionnement.
3. Le partitionnement reviendra si un volume **mesuré** le justifie, avec ce que cet ADR a trouvé : unicité de l'identifiant gardée à part, partition par défaut ou partitions créées à l'avance, conversion hors du chemin de démarrage.

**Conséquences**
- (+) Aucune des quatre régressions mesurées.
- (−) `docs/architecture/data-architecture.md` §3 décrit un DDL cible qui n'est pas le schéma réel : il le dit maintenant.
- (−) Le volume d'`audit_events` n'est pas borné tant qu'ADR-0032 n'est pas implémenté.

**Alternatives envisagées**
- **Partitionner quand même** (clé `(seq, ts)`, table d'identifiants pour l'unicité, partition par défaut, partitions créées par le service) : écarté par le propriétaire — tout le coût, aucun bénéfice avant la rétention.
- **Partitionner par `seq`** : garderait `PRIMARY KEY (seq)` et `Last`, mais une partition par plage de numéros ne correspond à aucune durée de rétention.
