# Mise à jour de la plateforme

- Les contrats REST (`/api/v1`) et gRPC (`proto/`) évoluent de façon additive uniquement (`docs/api/grpc/README.md` §1) — une mise à jour mineure n'exige jamais de migration cliente.
- Procéder par `helm upgrade`, service par service si un déploiement fin est souhaité (les charts sont indépendants, `docs/development/repository-structure.md` §6).
- ~~Toujours mettre à jour PostgreSQL (migrations de schéma) avant les services applicatifs qui en dépendent, jamais l'inverse.~~ Depuis ADR-0030, **chaque service applique lui-même ses migrations au démarrage** : une fois chacune, en transaction, sous un verrou propre au service (des réplicas qui démarrent ensemble s'attendent, aucun ne tombe). Mettre à jour PostgreSQL lui-même (la version du serveur) reste un geste séparé, avant les services.
- **Lire la version du schéma d'une base** : `SELECT component, version, name, applied_at FROM schema_migrations ORDER BY component, version;`. Le journal de démarrage dit aussi « schema migrations [N…] applied, schema now at version N » quand il en applique.
- **Revenir à un binaire précédent** est possible : les migrations sont additives par défaut, le service démarre sur une base plus récente et le journal le dit (« WARNING the database has schema migrations […] that this binary does not know »). Il n'y a pas de migration descendante : revenir sur un schéma, c'est restaurer une sauvegarde.
- **Ne jamais modifier une ligne de `schema_migrations` ni un fichier de migration publié** : le service refuserait de démarrer (voir §10).
