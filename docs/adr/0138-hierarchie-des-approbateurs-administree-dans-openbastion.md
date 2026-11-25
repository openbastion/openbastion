# ADR-0138 — La hiérarchie des approbateurs est administrée dans OpenBastion

**Statut** `Accepté` · 2026-11-24 · accepté par le propriétaire le 2026-11-24 ; contrats détaillés et acceptés dans `docs/architecture/workflow-approval-contracts.md` avant le démarrage de l'implémentation.

**Contexte** — L'approbation de session actuellement livrée (ADR-0067) repose sur une politique d'autorisation explicite et un approbateur distinct du demandeur. Elle ne fournit pas de source structurée pour résoudre le supérieur N+1. Le backlog v0.0.1 demande un Workflow / Approval Engine multi-étapes. Le propriétaire choisit une hiérarchie administrée directement dans OpenBastion, et non une relation `manager` importée depuis LDAP, Active Directory ou Entra ID.

La hiérarchie est une donnée de gouvernance OpenBastion ; elle ne doit ni devenir une identité parallèle, ni accorder implicitement un droit d'approbation. Les identités restent celles de l'Authentication Service et les décisions d'accès restent celles de l'Authorization Service (ADR-0010, ADR-0114). Le control plane ne reçoit aucun credential cible (ADR-0003).

**Décision**

1. **Source de vérité.** OpenBastion conserve et administre ses propres relations hiérarchiques entre utilisateurs. Les identifiants référencent les utilisateurs de l'Authentication Service ; aucun nom d'utilisateur, rôle, groupe ou identifiant de manager fourni par le demandeur d'accès n'est pris comme autorité. Les attributs de hiérarchie ne sont pas synchronisés depuis les annuaires et ne sont pas écrasés par une synchronisation d'identité.

2. **Modèle initial.** Une relation active relie un utilisateur subordonné à un seul approbateur direct (`manager_user_id`). Un utilisateur peut superviser plusieurs personnes. La hiérarchie est un graphe orienté acyclique ; l'auto-référence, les cycles et les utilisateurs inexistants/inactifs sont refusés. La résolution N+1 désigne exclusivement le supérieur direct, sans saut automatique de niveau ni recherche d'un approbateur de secours. Le modèle pourra évoluer vers plusieurs périmètres ou délégations par un ADR ultérieur.

3. **Administration protégée.** Les créations, changements et suppressions de relations sont des opérations administratives exposées exclusivement par l'API Gateway. Elles exigent une permission Authorization dédiée sur une ressource de hiérarchie, une identité issue du jeton vérifié, une validation serveur et un événement d'audit écrit avant la mutation. En cas d'indisponibilité de l'Authorization Service ou de l'Audit Service, la mutation échoue sans changement. Le navigateur n'accède jamais directement au Workflow Service ni à sa base.

4. **Contrôle de l'approbation.** La relation hiérarchique identifie un approbateur candidat ; elle ne lui confère aucun droit. Pour décider, le supérieur direct doit également satisfaire la politique Authorization applicable à la ressource et à l'action, être un utilisateur actif et être distinct du demandeur par identifiant d'utilisateur. Le corps de la requête ne peut choisir ni remplacer l'approbateur. Les décisions restent attribuées au principal vérifié par la Gateway.

5. **Stabilité des demandes.** À la création d'une demande N+1, le Workflow Service résout et enregistre l'identifiant du supérieur ainsi que la révision de la relation utilisée. Cette affectation est un instantané : modifier ensuite la hiérarchie ne réaffecte pas silencieusement une demande déjà en attente. Une réaffectation éventuelle est une action explicite, autorisée et auditée, qui fera l'objet d'un contrat séparé. Si aucun supérieur direct valide n'est configuré, la demande N+1 est refusée avant toute ouverture de session ; aucun approbateur implicite ou global n'est choisi.

6. **Concurrence et intégrité.** Les écritures de hiérarchie sont transactionnelles. Une contrainte d'unicité garantit au plus un supérieur direct par subordonné. La vérification de cycle et l'écriture sont sérialisées de façon à empêcher deux changements concurrents de créer un cycle entre réplicas. Les révisions sont monotones et les mises à jour conditionnelles ; une révision obsolète retourne un conflit sans écraser le changement concurrent.

7. **Audit.** Chaque création, remplacement ou suppression de relation, refus de validation, résolution N+1, décision et expiration est attribuée à l'acteur vérifié ou, pour une action système, à l'identité du service émetteur selon ADR-0136. L'audit ne contient pas de secret ; les événements sont écrits via l'Audit Service, jamais directement dans sa base. Une mutation de hiérarchie n'est jamais acceptée si son événement d'audit préalable ne peut pas être écrit.

8. **Périmètre de cette décision.** Cet ADR fixe la source et les garanties de la hiérarchie N+1. Il ne définit pas à lui seul le langage complet des workflows, les quorums, les étapes parallèles, les délégations temporaires, les remplaçants, les calendriers, les SLA, les callbacks Slack/Teams, ni la validation réelle des tickets ServiceNow/Jira. Ces capacités nécessitent des contrats et décisions complémentaires ; les notifications restent informatives et ne sont jamais une autorité d'approbation (ADR-0074, ADR-0126).

9. **Contrats à produire après acceptation.** Le lot d'implémentation devra spécifier les routes publiques Gateway de consultation et de gestion de la hiérarchie, les routes internes Workflow Service sous mTLS, les schémas OpenAPI et JSON internes, les événements d'audit, ainsi que les tables PostgreSQL et migrations versionnées. Les lectures de hiérarchie seront filtrées selon les permissions ; elles ne révéleront pas la structure globale à un utilisateur non autorisé. Les contrats sont additifs et testés contre les appelants mTLS autorisés (ADR-0050).

**Conséquences**

- (+) L'organisation d'approbation reste administrable même si l'annuaire ne fournit pas de relation hiérarchique ou si celle-ci est incomplète.
- (+) L'identité, la hiérarchie et l'autorisation demeurent trois responsabilités distinctes ; connaître son supérieur ne donne pas automatiquement le droit d'approuver.
- (+) L'instantané de l'approbateur et la révision de hiérarchie rendent une décision explicable après une réorganisation.
- (−) La hiérarchie doit être tenue à jour par les administrateurs OpenBastion ; une donnée obsolète peut retarder ou empêcher une demande.
- (−) Le modèle initial à un seul supérieur direct ne couvre pas les organisations matricielles, les délégations, les remplacements ni les périmètres multiples.
- (−) Sans supérieur valide, le workflow N+1 ne peut pas progresser ; il n'existe aucun contournement automatique.
- (−) La cohérence anti-cycle entre réplicas ajoute une transaction/coordination aux changements de hiérarchie ; la stratégie exacte de verrouillage et ses limites de contention seront validées pendant la conception détaillée.
- (−) Cet ADR ne livre aucune route, interface, table, notification ou capacité d'approbation supplémentaire ; les fonctions actuelles restent celles documentées par ADR-0067.

**Alternatives envisagées**

- **Importer `manager` depuis LDAP/AD/Entra ID** : écarté par le choix du propriétaire ; les annuaires ne sont pas toujours cohérents entre eux et la gouvernance d'accès ne doit pas dépendre d'un attribut externe non maîtrisé par OpenBastion.
- **Déduire le supérieur depuis les rôles ou les groupes** : écarté, car un rôle décrit des capacités et non une relation hiérarchique individuelle ; cela rendrait N+1 ambigu et pourrait élargir les droits.
- **Accorder automatiquement le droit d'approbation au supérieur** : écarté ; la hiérarchie ne remplace pas Authorization et ne doit pas devenir une élévation implicite.
- **Choisir un approbateur global de secours** : écarté ; cela masquerait une configuration incomplète et pourrait contourner la séparation des tâches.
