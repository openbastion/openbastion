# ADR-0135 — Borner les pools PostgreSQL par service dans un budget de déploiement

**Statut** `Proposé` · 2026-11-23 · décision de dimensionnement à valider par le propriétaire du projet

**Contexte** — Les sept services qui ouvrent PostgreSQL utilisent chacun `SetMaxOpenConns(10)` et `SetMaxIdleConns(10)` : Authentication, Authorization, Session Broker, Audit Service, Password Vault, Command Recorder et Video Recorder. À une instance de chaque service, le plafond cumulé est donc de 70 connexions. `MaxIdleConns` borne les connexions conservées après usage ; il ne les ouvre pas toutes au démarrage et ne s'ajoute pas à `MaxOpenConns`.

Le benchmark ADR-0116 (PostgreSQL 16.15, deux Brokers, un Audit Service, mTLS TLS 1.3, même hôte WSL2) a ensuite montré une contention dominante à l'acquisition d'une connexion dans l'Audit Service. À 32 lecteurs, le profil block attribue 24,06 s d'attente à `database/sql.(*DB).conn` côté Audit ; `DB.Stats()` a relevé 7 669 attentes et 1 min 41 s cumulées sur une passe profilée. Les essais contrôlés montrent un gain à augmenter le pool Audit de 10 à 20, puis un gain supplémentaire côté Broker à 64 lecteurs. Mais sept services à 20 connexions chacun dépasseraient les 100 connexions par défaut de PostgreSQL avant même de compter les réplicas, migrations, outils et consommateurs externes.

Ces mesures locales ne sont ni un SLO ni une capacité de production. Elles justifient de rendre les limites configurables et de budgéter le cluster entier, pas d'augmenter aveuglément les constantes. Aucun pool de production n'a été modifié par l'incrément ADR-0116.

**Décision**

1. **Un pool par processus et par service.** Chaque processus qui possède un `*sql.DB` configure son propre pool. Le plafond `MaxOpenConns` est une capacité locale ; le plafond `MaxIdleConns` est inclus dans cette capacité, jamais additionné au budget global.
2. **Configuration locale explicite.** Les services PostgreSQL acceptent, lorsque `DATABASE_URL` est défini :
   - `DB_POOL_MAX_OPEN_CONNS` : entier décimal de 1 à 1 000 ; défaut `10` ; zéro (illimité dans `database/sql`), valeur négative, chaîne mal formée ou dépassement de borne = démarrage refusé ;
   - `DB_POOL_MAX_IDLE_CONNS` : entier décimal de 0 à `DB_POOL_MAX_OPEN_CONNS` ; défaut `min(DB_POOL_MAX_OPEN_CONNS, 10)` ; valeur explicite supérieure au plafond ouvert ou mal formée = démarrage refusé.
   Les variables ont le même nom dans les sept services mais sont définies séparément dans chaque conteneur/Deployment. Elles ne changent pas le défaut actuel de 10/10. Les réglages de pool sont lus dans `main.go`, puis transmis à `openPool` ; la bibliothèque d'infrastructure ne relit pas l'environnement.
3. **Budget global au niveau du déploiement.** Chaque cluster PostgreSQL possède un manifeste de capacité qui déclare `max_connections`, `reserved_connections` et, pour chaque service, `max_instances` et `max_open_per_instance`. `max_instances` inclut le maximum HPA, le `maxSurge` de mise à jour, les jobs concurrents et tout processus supplémentaire qui utilise la base. La condition obligatoire est :

   ```text
   application_connections = Σ(max_instances(service) × max_open_per_instance(service))
   application_connections + reserved_connections <= max_connections
   ```

   `reserved_connections` couvre tous les consommateurs qui ne sont pas les pools applicatifs déclarés : slots PostgreSQL réservés, administration, migrations, sauvegardes, supervision, maintenance et autres clients. Le budget est calculé par cluster, pas par base ou par service ; plusieurs bases du même serveur partagent le même `max_connections`.
4. **Exemple de référence, non universel.** Pour un PostgreSQL configuré à 100 connexions, sept services à une instance et 10 connexions ouvertes maximum chacun consomment une capacité de 70. Avec une réserve opérationnelle déclarée de 20, le total planifié est 90 et conserve 10 connexions de marge. Ce calcul ne vaut que pour cette topologie et cette réserve ; il ne constitue pas une valeur imposée à toutes les installations.
5. **Validation avant déploiement.** Un contrôle de configuration/CI vérifie le manifeste, les entiers, les doublons, les services connus, les bornes, les multiplications sans débordement et l'inégalité du budget. Pour Kubernetes, `max_instances` doit refléter les maxima réels, y compris les pointes de rollout ; une valeur égale au nombre de pods désirés n'est pas suffisante. Une configuration non vérifiable ou hors budget bloque le déploiement. Un processus isolé ne prétend pas vérifier le budget des autres services ou réplicas.
6. **Défauts inchangés jusqu'à mesure représentative.** Les sept services gardent `MaxOpenConns(10)` et `MaxIdleConns(10)` par défaut. Un opérateur peut régler un service au-dessus ou en dessous de 10 uniquement si le manifeste de son cluster reste valide. Aucun changement de valeur par défaut ne sera fait sur la seule base du benchmark mono-hôte.
7. **Pas d'allocation dynamique entre services.** Il n'y a ni coordinateur distribué, ni réservation au démarrage, ni réduction silencieuse d'un pool pour faire entrer un autre service dans le budget. Les limites sont statiques, versionnées et vérifiées avant déploiement. Une panne de validation bloque le déploiement, jamais une autorisation métier ou une lecture auditée déjà en cours.
8. **Mesure opérationnelle.** L'implémentation doit exposer, via l'observabilité existante et avec une cardinalité bornée par service, les valeurs de `DB.Stats()` : connexions ouvertes/en usage/inactives, maximum configuré, compteur d'attentes et durée cumulée d'attente. Ces métriques servent à réviser le dimensionnement ; elles ne modifient pas automatiquement les pools.
9. **PgBouncer reste une option séparée.** Il n'est pas introduit par cette décision. S'il est évalué, un ADR distinct devra distinguer le plafond de connexions clientes des pools de connexions serveur réellement ouverts vers PostgreSQL, et recalculer le budget à partir de ces derniers. Le budget ne doit jamais compter deux fois les connexions clientes et serveur.
10. **Aucune modification des contrôles d'intégrité.** La tête Audit d'ADR-0116 reste lue à chaque décision protégée ; aucun cache de tête, accès direct à la projection ou relâchement fail-closed n'est autorisé pour réduire la contention.

**Conséquences**

- (+) Les valeurs locales sont configurables sans modifier le code, et le plafond global prend en compte les réplicas et les consommateurs hors application.
- (+) Le dimensionnement par défaut actuel est explicite : 7 × 10 = 70 connexions applicatives maximales à une instance de chaque service ; avec 20 réservées sur un serveur à 100, il reste 10 de marge.
- (+) Les mesures ADR-0116 donnent une cause observée et un ordre de grandeur du bénéfice d'un pool Audit plus grand, sans transformer ces chiffres en SLO.
- (−) Le manifeste statique ne protège pas contre un administrateur qui modifie le nombre de réplicas ou les variables d'environnement hors du processus de déploiement contrôlé ; les permissions Kubernetes/Compose et la CI doivent empêcher ces divergences.
- (−) La réserve est une décision d'exploitation à renseigner selon les extensions, outils et opérations réels ; 20 n'est qu'un exemple pour `max_connections=100`.
- (−) Une hausse de pool peut déplacer le goulot vers CPU, I/O, verrous ou saturation PostgreSQL ; le budget garantit une borne de connexions, pas le débit ni la latence.
- (−) Les résultats actuels proviennent d'un seul hôte WSL2. Le benchmark multi-hôte reste différé à la demande de l'utilisateur ; aucune capacité de production n'en est déduite.
- (−) L'instrumentation des métriques et le validateur de manifeste ne sont pas encore implémentés ; cet ADR définit leur contrat.
- (−) PgBouncer, le dimensionnement des workers et la limite de connexions par rôle PostgreSQL restent hors de cette décision.

**Alternatives envisagées**

- **Augmenter les sept pools à 20.** Rejeté : 140 connexions pour une seule instance de chaque service dépassent déjà le défaut PostgreSQL de 100, sans réserve ni réplicas.
- **Conserver les constantes à 10 sans budget global.** Rejeté : deux réplicas de chaque service peuvent demander 140 connexions ; le plafond local ne prévient pas la saturation du cluster.
- **Un pool global partagé entre services.** Rejeté : il fusionnerait les frontières de cycle de vie, les identités PostgreSQL et les domaines de panne ; il ne convient pas aux services isolés.
- **Un coordinateur dynamique de connexions.** Rejeté pour cette étape : il ajoute un service critique, une dépendance de disponibilité et des courses de réservation ; le contrôle statique est plus simple et vérifiable.
- **PgBouncer immédiatement.** Différé : il peut réduire le nombre de connexions serveur, mais introduit une deuxième couche de pooling et des contraintes de mode transaction/session à valider séparément.
- **Un cache de la tête Audit.** Rejeté : il affaiblirait la détection de rollback définie par ADR-0116.

**Étapes d'implémentation proposées**

1. Ajouter un type de configuration commun sans dépendance externe, ses parseurs stricts et les tests de bornes ; brancher les sept `openPool` sans changer les défauts.
2. Ajouter le manifeste de capacité par cluster et un validateur déterministe exécuté en CI ; couvrir HPA/maxSurge et les jobs concurrents dans `max_instances`.
3. Publier les métriques `DB.Stats()` avec labels bornés, puis tester les réglages sur PostgreSQL 16 réel et sous `-race`.
4. Après déploiement d'une topologie représentative, mesurer la contention et proposer, dans un changement distinct, les valeurs de pool par service. Ne pas lancer de benchmark multi-hôte sans nouvelle autorisation.
