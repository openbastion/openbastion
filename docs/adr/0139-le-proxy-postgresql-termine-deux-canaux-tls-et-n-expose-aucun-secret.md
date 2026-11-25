# ADR-0139 — Le proxy PostgreSQL termine deux canaux TLS et n’expose aucun secret cible

**Statut** `Accepté` · 2026-11-25 · cadrage initial du Database Proxy, PostgreSQL en premier moteur

## Contexte

La roadmap v0.0.1 prévoit un Database Proxy pour PostgreSQL, MySQL, MSSQL, Oracle et MongoDB. Aucun de ces protocoles ne doit devenir un accès direct depuis un poste opérateur vers une cible. Le présent ADR cadre uniquement le premier incrément PostgreSQL ; il ne prétend pas définir un proxy SQL universel.

Les invariants existants s'appliquent sans exception :

- ADR-0003 : le Gateway, le Broker et le Workflow Service n'obtiennent jamais le secret cible ; le proxy protocolaire autorisé le récupère directement auprès du Vault par mTLS.
- ADR-0005 : le Password Vault détient les comptes privilégiés et le Secrets Manager les secrets applicatifs dynamiques. Le proxy consomme l'un ou l'autre selon le compte déclaré, sans fusionner leurs responsabilités.
- ADR-0006 : le cycle de vie commun est porté par `pkg/proxycore` ; le codec PostgreSQL ne possède que les détails du protocole.
- ADR-0008 : une session dont l'enregistrement obligatoire n'est pas disponible est refusée ; une opération ne doit pas atteindre la cible avant son acquittement d'enregistrement.
- ADR-0018 : terminer une session doit réellement couper toutes les connexions proxy associées avant que le Broker ne marque la session terminée.
- ADR-0029/0030/0135 : PostgreSQL est accédé par `database/sql`, migrations versionnées et pools bornés par service ; ces règles ne donnent aucun accès aux bases cibles au control plane.
- ADR-0114/0116/0136 : permissions ressource/action, métadonnées de session attestées et provenance de l'appelant mTLS restent applicables.

Un proxy qui ne ferait que relayer TCP/TLS de bout en bout ne pourrait ni contrôler le protocole, ni produire les événements SQL attendus. À l'inverse, terminer TLS sans définir deux authentifications indépendantes risquerait de transmettre le mot de passe de la cible au client ou de confondre le ticket OpenBastion avec un credential PostgreSQL.

## Décision

### 1. Périmètre initial

1. Le premier moteur livré est **PostgreSQL, protocole filaire v3**. Les autres moteurs, le protocole de réplication, les extensions propriétaires et les modes non validés sont hors de cet incrément.
2. Le proxy est un service Go autonome, propriétaire du codec PostgreSQL et consommateur de `pkg/proxycore`. Il est sélectionné par le Session Broker à partir du protocole enregistré dans la session, jamais à partir d'un choix libre transmis au moment de la connexion.
3. Le proxy est l'unique chemin réseau autorisé vers les ports PostgreSQL protégés. Les ACL/firewalls des zones cibles refusent les connexions depuis les postes opérateurs, le Gateway, le Broker et les autres services ; seule l'identité réseau du Database Proxy peut joindre les endpoints déclarés.
4. Le proxy ne fournit ni tunnel TCP générique, ni mode passthrough, ni fonction de port-forward. Une cible ou un mode non explicitement pris en charge est refusé.

### 2. Deux canaux TLS distincts

1. **Client → proxy.** Le proxy accepte l'`SSLRequest` PostgreSQL puis négocie TLS 1.2 au minimum, TLS 1.3 de préférence, avec un certificat serveur vérifiable par le client. Le mode clair est refusé ; l'option GSS Encryption Request est refusée dans le premier incrément. La configuration cliente doit vérifier le nom du proxy (`sslmode=verify-full` ou équivalent).
2. **Proxy → cible.** Le proxy ouvre une connexion TLS distincte vers PostgreSQL, vérifie la chaîne de confiance et le nom DNS de la cible, et n'accepte aucun mode de repli en clair. L'autorité de confiance et le nom attendu sont issus de la configuration de cible approuvée, jamais du client.
3. Le proxy termine les deux sessions TLS et interprète les messages PostgreSQL nécessaires à l'authentification, au relais et à l'enregistrement. Il ne transmet jamais un flux TLS opaque entre les deux côtés.
4. Les appels internes proxy → Vault, Recorder, Broker et Audit Service sont en mTLS avec identité de workload dédiée. Les certificats, secrets de service et paramètres de confiance ne sont pas partagés avec le processus opérateur.
5. Les versions TLS, suites cryptographiques et tailles de trames suivent la politique TLS commune du dépôt ; aucune option de compatibilité ne permet de désactiver la validation du certificat cible.

### 3. Ticket opérateur distinct du credential PostgreSQL

1. Le parcours est : **Gateway → Authentication/Authorization → Session Broker → Database Proxy → Vault → PostgreSQL**. Le Gateway authentifie l'opérateur et applique les permissions ; le Broker vérifie l'état, l'échéance et les approbations de la session, puis choisit le proxy.
2. À `connect`, le Broker crée un scope Vault à usage unique, limité au `session_id`, au compte privilégié, à l'identité `database-proxy`, à la cible et au TTL restant. Il remet ce scope directement au proxy par l'API interne mTLS. Le scope n'est jamais retourné au client ni transmis au Gateway.
3. Le proxy prépare un ticket de connexion opaque, à usage unique, court, non dérivé du mot de passe PostgreSQL et lié à la session, à l'opérateur, au proxy, à la cible et à son expiration. Seul ce ticket est remis au client par le Broker. Le ticket n'accorde aucun accès à une autre session ou cible.
4. Le client PostgreSQL présente le ticket comme valeur du champ password du protocole, uniquement après établissement du TLS vérifié vers le proxy. Le proxy le valide et le consomme atomiquement. Un ticket expiré, rejoué, d'une autre session ou destiné à un autre proxy est refusé avant toute récupération de credential.
5. Le proxy récupère le credential cible directement auprès du Password Vault, ou un secret dynamique auprès du Secrets Manager si le compte est explicitement configuré ainsi. Le Vault vérifie le scope et l'identité mTLS de l'appelant ; un proxy DB ne peut consommer un scope SSH/RDP, ni un scope d'un autre compte ou d'une autre cible.
6. Le proxy s'authentifie ensuite auprès de PostgreSQL avec le credential récupéré. Il ne transmet jamais ce credential au client et ne traite jamais le ticket opérateur comme un mot de passe PostgreSQL.
7. La durée de vie du ticket et du scope ne dépasse jamais celle de la session. Une reconnexion nécessite un nouveau ticket et un nouveau scope selon le cycle de vie défini par le Broker ; aucun ticket ne survit à la révocation de session.
8. Le nom du rôle PostgreSQL et le nom de la base sont résolus depuis le compte privilégié et la cible approuvés. Les valeurs `user` et `database` du StartupMessage doivent correspondre exactement à ces valeurs ; toute divergence est refusée. Le client ne peut pas changer de rôle, de base ou de cible par `options`, `replication`, paramètres de démarrage ou message ultérieur.

### 4. Limites du protocole et de l'authentification

1. Le premier incrément prend en charge le StartupMessage PostgreSQL v3, SSLRequest, l'authentification opérateur par ticket et les mécanismes d'authentification cible effectivement supportés par le client Go du proxy. La matrice de sortie doit nommer chaque mécanisme (au minimum SCRAM-SHA-256 et mot de passe selon les comptes de test) ; un mécanisme non pris en charge est refusé, jamais rétrogradé.
2. Le proxy est un terminateur protocolaire des deux côtés : les échanges d'authentification client/proxy et proxy/cible sont indépendants. Les messages d'authentification cible ne sont jamais relayés au client.
3. Les paramètres de démarrage sont fermés par défaut. Seuls les paramètres explicitement autorisés (par exemple `application_name`, borné en taille et nettoyé) sont acceptés ; les paramètres inconnus, `options`, `replication`, `fallback_application_name` non autorisés et tentatives de changement de rôle sont refusés.
4. Les requêtes préparées, Bind/Execute, transactions, erreurs et réponses sont relayés sans réécriture sémantique. Le proxy ne prétend pas être un pare-feu SQL ni un moteur de politique par instruction dans cet incrément.
5. Les messages spéciaux (CancelRequest, protocole de réplication, COPY, grandes valeurs binaires et extensions) doivent avoir un comportement documenté et testé avant d'être annoncés comme supportés. À défaut de support sûr, ils sont refusés explicitement ou entraînent la fermeture de la session ; ils ne sont jamais relayés hors du contrôle du proxy. La prise en charge de CancelRequest doit utiliser une correspondance de clés backend propre au proxy ou être déclarée indisponible : les identifiants backend réels ne sont pas exposés au client.

### 5. Enregistrement et audit des opérations SQL

1. L'enregistrement est `required` par défaut conformément à ADR-0008. Le proxy vérifie la disponibilité du Command Recorder avant de consommer le scope Vault, puis attend l'acquittement durable de chaque événement d'opération avant de transmettre à la cible le message qui déclenche cette opération. Une panne ou un acquittement ambigu ferme la session dans le sens sûr ; aucun tampon disque local ni mode silencieux n'est introduit.
2. Le Command Recorder reçoit des événements structurés de base de données : séquence, horodatage, session, cible logique, rôle autorisé, classe de commande/`CommandComplete` tag, empreinte HMAC de requête normalisée, durée, nombre de lignes lorsqu'il est fourni, état transactionnel observable et SQLSTATE en cas d'erreur.
3. **Le texte SQL brut et les valeurs Bind ne sont pas persistés par défaut.** Les valeurs de paramètres, secrets intégrés aux littéraux SQL, payloads COPY et données binaires ne sont jamais copiés dans les logs applicatifs ni dans les événements de commande. L'empreinte est calculée avec une clé de session afin d'éviter une empreinte globale triviale. Une future capture détaillée, si nécessaire, exigera un ADR distinct, une politique explicite, un chiffrement par session, une rétention bornée et des contrôles de lecture.
4. Les événements de connexion, refus, ticket consommé/rejoué, scope Vault, établissement TLS, authentification cible, début/fin de session, interruption, terminaison et perte d'enregistrement sont émis vers l'Audit Service avec `actor_id` issu de l'identité vérifiée et `emitter` issu du certificat mTLS de l'appelant immédiat (ADR-0136). L'Audit Service demeure l'unique propriétaire de la chaîne signée.
5. Les événements Recorder et Audit ne sont pas interchangeables : le premier décrit le flux opérationnel acquitté ; le second atteste les décisions et transitions de sécurité. Une session n'est pas déclarée complète si les deux preuves requises ne sont pas disponibles.
6. L'interface de recherche ne peut afficher que les métadonnées effectivement enregistrées. Aucune fonction de replay ne doit laisser entendre qu'elle restitue le texte SQL ou les valeurs Bind non capturés.

### 6. Révocation, concurrence et cycle de vie

1. Le proxy maintient un registre borné des connexions par session et ferme les connexions client et cible à l'expiration, à la révocation ou à la perte d'un invariant critique. Les tickets non consommés sont invalidés.
2. Une révocation réussie signifie que toutes les connexions PostgreSQL amont et aval de la session sont fermées. Le Broker ne marque la session terminée qu'après confirmation du proxy, conformément à ADR-0018.
3. Les tickets sont consommés atomiquement ; deux connexions concurrentes avec le même ticket ne peuvent pas toutes deux réussir. Les limites de connexions simultanées par session, opérateur, cible et instance sont explicites et configurables avec des bornes strictes.
4. Un redémarrage du proxy ne restaure aucune connexion ni aucun ticket consommé. Les sessions dont le propriétaire proxy disparaît échouent fermées ; le Broker ne réattribue pas une session active à une autre instance sans nouvelle autorisation.
5. Les secrets sont limités à la durée nécessaire à l'authentification upstream, protégés contre les core dumps, exclus des traces, erreurs, métriques et profils, puis effacés au mieux selon les primitives mémoire et règles d'ADR-0115. Aucun effacement mémoire ne doit être présenté comme une garantie contre un processus compromis avec les mêmes privilèges.

### 7. Configuration et données de cible

1. Une cible PostgreSQL déclare au minimum : adresse/port, nom DNS attendu pour TLS, référence de confiance CA ou empreinte approuvée, base autorisée, rôle/compte privilégié référencé dans le Vault, proxy autorisé, et limites de connexion/temps.
2. L'adresse réseau et le nom TLS proviennent d'une configuration administrée et autorisée. Le proxy ne résout ni ne contacte une adresse arbitraire fournie par l'opérateur ; les redirections DNS vers loopback, link-local, métadonnées cloud ou plages interdites sont refusées après résolution et lors de l'ouverture de connexion (protection SSRF).
3. La configuration est validée au moment de son écriture et revalidée au moment de la connexion. Un changement de cible ne modifie pas une session déjà établie ; une nouvelle session utilise la nouvelle version attestée.
4. Les valeurs de limite ont des bornes finies : délai de connexion, délai d'inactivité, taille maximale de trame, nombre de connexions, durée maximale de session et budget d'enregistrement. Les valeurs exactes seront fixées par l'implémentation et ses tests de charge avant activation en production ; zéro ne signifie jamais illimité.

### 8. Contrats et propriété des données

1. Les opérations publiques passent par l'API REST de la Gateway et réutilisent les contrats de session existants : découverte de capacité, création/demande, approbation, connexion et terminaison. Aucune route publique ne révèle le scope Vault ni le credential cible.
2. Le Broker appelle le Database Proxy via un contrat interne versionné et mTLS, analogue au contrat de contrôle des autres proxies : établissement avec `session_id`, cible/compte résolus, scope opaque, TTL et limites ; réponse avec endpoint proxy et ticket opérateur ; révocation idempotente par session.
3. Le proxy appelle le Vault/Secrets Manager et le Command Recorder par leurs contrats internes dédiés. Le proxy n'accède jamais directement aux bases PostgreSQL applicatives d'OpenBastion.
4. Les migrations du Database Proxy ne sont pas ajoutées aux bases métier des cibles. Les métadonnées de cible et de session restent dans les services propriétaires existants ; les événements de commande sont détenus par le Command Recorder et les événements de sécurité par l'Audit Service.
5. Les noms exacts des RPC/messages Protobuf, des routes internes, des tables et des migrations sont fixés dans les ADR de contrats et l'implémentation, après inventaire des contrats existants. Aucun schéma de données cible n'est modifié par le proxy.

## Conséquences

- (+) Le poste opérateur ne possède qu'un ticket OpenBastion éphémère ; le mot de passe, certificat ou secret dynamique PostgreSQL reste entre le Vault et le Database Proxy.
- (+) Deux sessions TLS vérifiées empêchent le passthrough opaque et permettent au proxy de contrôler le protocole sans confondre l'identité opérateur et l'identité PostgreSQL.
- (+) Les ACL réseau rendent l'interdiction d'accès direct vérifiable indépendamment du comportement de l'interface.
- (+) Les événements enregistrés permettent d'auditer les opérations sans stocker les valeurs Bind ni le SQL brut qui pourrait contenir des secrets.
- (+) Le cycle commun `pkg/proxycore`, l'acquittement du Recorder et la révocation du Broker réutilisent les invariants éprouvés des autres proxies.
- (−) Le proxy termine TLS et devient un composant de confiance critique : une compromission de son processus peut exposer temporairement des secrets et les données SQL en transit. Il doit être isolé, durci, observé et limité au réseau des cibles explicitement autorisées.
- (−) La terminaison TLS empêche le client de vérifier directement le certificat de la base cible ; la confiance cible est vérifiée par le proxy, et la chaîne de confiance doit être administrée et auditable.
- (−) Le support d'un protocole PostgreSQL complet est vaste. Les mécanismes d'authentification, CancelRequest, COPY, réplication, extensions et versions devront être déclarés précisément ; la compatibilité générale n'est pas garantie par le seul support de StartupMessage v3.
- (−) Sans SQL brut ni valeurs Bind, la preuve permet de retrouver la classe et l'empreinte d'une opération, pas de reconstruire exactement la requête ou ses résultats. Les données de résultat ne sont pas enregistrées.
- (−) L'acquittement avant transmission ajoute une latence par opération et fait du Command Recorder une dépendance de disponibilité de rang 1, conformément à ADR-0008.
- (−) La rotation du credential pendant une session ne change pas une authentification déjà établie ; les sessions suivantes doivent utiliser la version courante du Vault. La révocation immédiate d'une session n'est pas une rotation de compte.
- (−) Ce cadrage ne définit ni l'autorisation SQL par instruction, ni le masquage de résultats, ni l'export de données, ni les pools partagés ou PgBouncer.

## Alternatives envisagées

- **Tunnel TCP/TLS passthrough :** rejeté, car le proxy ne pourrait ni contrôler l'authentification, ni corréler les opérations, ni appliquer les garanties d'enregistrement au protocole.
- **Faire transmettre le mot de passe PostgreSQL par le client :** rejeté, car cela expose le secret à l'opérateur et rend le bastion dépendant de la sécurité du poste client.
- **Faire récupérer le credential par le Gateway ou le Broker :** rejeté par ADR-0003 ; le control plane ne doit jamais manipuler le secret cible.
- **Utiliser le ticket OpenBastion comme mot de passe PostgreSQL upstream :** rejeté, car cela confond une preuve d'autorisation de session avec une identité de base et lie la sécurité du compte cible au protocole du bastion.
- **Enregistrer le SQL brut et les paramètres Bind :** rejeté par défaut, car les littéraux et paramètres peuvent contenir des mots de passe, tokens, données personnelles ou secrets applicatifs ; une capture exhaustive nécessite une décision séparée.
- **Faire un proxy SQL générique dès le premier incrément :** rejeté, car les protocoles et mécanismes d'authentification diffèrent fortement ; PostgreSQL fournit une première surface testable sans prétendre couvrir les autres moteurs.
- **Laisser les clients accéder directement à la base en cas de panne du proxy :** rejeté, car cela contournerait le contrôle d'accès, le Vault, l'enregistrement et l'audit.

## Validation attendue avant implémentation

- Un client PostgreSQL standard se connecte à une cible PostgreSQL 16 réelle via le proxy, avec validation TLS côté client et côté cible ; aucun mot de passe de cible n'est configuré sur le poste client.
- Le ticket est à usage unique, lié à une session et à une cible ; replay, expiration, substitution de session, mauvais rôle, mauvaise base et concurrence sont refusés.
- Le proxy refuse TLS désactivé, certificat cible invalide, hostname incorrect, protocole non supporté, paramètre de démarrage interdit, destination SSRF et accès direct réseau depuis les zones opérateur/control plane.
- Les secrets cible ne figurent dans aucun message Gateway/Broker, réponse client, log, métrique, trace, profil ou événement Recorder ; des canaris secrets sont recherchés automatiquement dans ces sorties.
- La panne Recorder avant connexion refuse la session avant consommation du scope ; la panne ou réponse ambiguë pendant une opération empêche l'opération d'être transmise à PostgreSQL et ferme la session.
- Les requêtes préparées et transactions produisent des événements ordonnés acquittés ; valeurs Bind, SQL brut, COPY payload et résultats ne sont pas persistés.
- La révocation ferme toutes les connexions client et cible, invalide les tickets et empêche toute nouvelle requête d'atteindre PostgreSQL ; le Broker ne marque pas la session terminée si le proxy n'a pas confirmé la coupure.
- Le test de bout en bout utilise des processus réels, PostgreSQL 16, mTLS interne et une cible TLS vérifiée ; il couvre les redémarrages, pannes, courses, limites mémoire et `-race`.
- Le threat model STRIDE couvre au minimum usurpation de ticket, rejeu, SSRF/DNS rebinding, downgrade TLS, injection de paramètres Startup, désynchronisation de flux, épuisement mémoire/connexions, perte d'acquittement, révocation concurrente et compromission du proxy.

### Profil d'interopérabilité du premier incrément accepté

Les choix ci-dessous ferment le périmètre initial sans prétendre couvrir toutes les extensions PostgreSQL :

1. **Drivers client.** Le proxy émet `AuthenticationCleartextPassword` uniquement après TLS vérifié ; le client standard présente le ticket dans un `PasswordMessage`. Le ticket est donc compatible avec les drivers PostgreSQL v3 qui prennent en charge l'authentification `password` standard. Le mot de passe de la cible n'est jamais demandé au client. Le test de compatibilité de référence utilise le protocole libpq ; tout driver non conforme est hors support jusqu'à un test dédié.
2. **CancelRequest.** Le proxy émet des clés `BackendKeyData` aléatoires et opaques, conserve leur correspondance avec les clés amont et traduit les `CancelRequest` sans révéler le PID ni le secret PostgreSQL. Le paquet `CancelRequest` est l'exception protocolaire PostgreSQL : il arrive sur une nouvelle connexion TCP sans négociation TLS. Il ne transporte que cette capacité aléatoire, liée à l'adresse IP du pair client et à une session active ; aucune donnée SQL ni aucun secret de compte n'y transite.
3. **Authentification amont.** Le premier incrément accepte uniquement `SCRAM-SHA-256` vers la cible. MD5, `cleartext`, GSS et les mécanismes inconnus sont refusés sans rétrogradation. Les comptes de test et la matrice d'interopérabilité doivent utiliser PostgreSQL 16 configuré en SCRAM-SHA-256. Tant que le proxy ne fournit pas une préparation SASLprep Unicode complète, les mots de passe amont doivent être en ASCII imprimable ; les autres sont refusés sans repli.
4. **Limites initiales.** Défauts stricts : 256 connexions actives par instance, 32 par cible, 8 par acteur et 1 par session. Les limites sont configurables dans des bornes finies ; zéro, valeur absente invalide ou dépassement ne signifie jamais « illimité ».
5. **Événement Command Recorder.** Le contrat distingue `started` et `completed`, identifiés par un `operation_id` et une séquence monotone par session. `started` est acquitté durablement avant de transmettre l'opération à la cible ; `completed` est acquitté avant de transmettre au client la fin et les résultats de l'opération. L'événement ne contient que le tag de commande, une empreinte HMAC par session, la durée, le nombre de lignes, l'état transactionnel et le SQLSTATE. SQL brut, Bind, COPY et résultats ne sont jamais persistés. COPY est refusé dans le premier incrément.

Ces choix constituent le profil de compatibilité initial. Toute extension (autre mécanisme amont, capture COPY ou nouveau mode d'authentification client) exige des tests d'interopérabilité et, si elle modifie les garanties, un ADR complémentaire.
