# ADR-0014 — Une limitation de débit par identité sur les demandes de session, au Gateway


**Contexte**
ADR-0013 a consigné une limite que rien n'empêche : les refus ne sont pas limités en débit. Une requête `POST /sessions` refusée — plafond atteint, politique absente, justification trop courte — n'est pas gratuite : le Broker écrit une ligne `denied` dans `sessions` et un événement d'audit (Full Auditability, `docs/architecture/principles.md`), et interroge l'Authorization Service. Un détenteur de jeton, même sans aucun droit, peut donc faire écrire au Broker autant de lignes et d'événements que le réseau lui laisse envoyer.

Le Gateway limite déjà, par adresse IP. En lisant ce limiteur pour y adosser le nouveau, j'ai **mesuré** trois défauts (ils n'ont pas été supposés) :
1. **Les unités mentent.** `NewRateLimiter(60, time.Minute)` est une rafale de 60 puis **un** jeton par minute (le second paramètre est le temps pour accumuler *un* jeton) : 10 requêtes acceptées sur 10 minutes de requêtes régulières, et non « 60 par minute » comme l'écrit `main.go`. Le login, `(5, time.Minute)`, est une rafale de 5 puis une par minute, et non « 5 par minute ».
2. **Rien n'est jamais évincé.** Un seau par clé, gardé pour toujours : 100 000 clés distinctes laissent près de 98 000 seaux en mémoire, toujours là 48 heures plus tard. Sur `/auth/login`, public et dont la clé est l'IP, c'est une fuite de mémoire à la portée d'un attaquant.
3. **La clé est l'adresse du pair TCP.** Le listener public est en HTTP derrière Traefik, où le TLS se termine : `RemoteAddr` est alors celle du reverse proxy **pour tout le monde**. Tous les utilisateurs partagent un seau, et l'un d'eux peut en épuiser la rafale de login pour tous les autres.

Deux questions : (1) **quoi limiter, avec quelle clé**, pour borner les écritures du Broker sans donner à quiconque un moyen de bloquer les autres ; (2) **que faire du limiteur existant**, dont le nouveau dépend.

**Décision**
Sept règles.

1. **La clé est l'identité vérifiée, pas l'adresse.** Le budget de `POST /sessions` est celui de l'utilisateur — le `UserID` que rend la vérification du jeton —, appliqué **après** l'authentification. Ni l'IP (la même pour tous derrière l'arête), ni le corps (le demandeur l'écrit), ni le nom d'utilisateur. Un utilisateur ne peut pas épuiser le budget d'un autre.
2. **On compte les tentatives, pas les succès, et avant tout travail.** Chaque `POST /sessions` d'un jeton valide coûte un jeton du seau, acceptée ou non, corps lisible ou non : le contrôle précède la lecture du corps. Une requête refusée ici n'atteint jamais le Broker : **elle n'écrit ni ligne ni événement d'audit**.
3. **Un seau à jetons, des défauts stricts, pas d'« illimité ».** Rafale `SESSION_REQUEST_BURST` (défaut **10**, de 1 à 1000), débit soutenu `SESSION_REQUEST_RATE_PER_MINUTE` (défaut **6**, de 1 à 600). Une valeur invalide empêche le Gateway de démarrer, en nommant la variable. Un Gateway construit à la main applique les défauts (le zéro-valeur est strict). Au démarrage, le Gateway annonce ce qu'il applique.
4. **`429`, avec un `Retry-After` vrai.** Le délai est ce qui manque pour accumuler le prochain jeton, arrondi à la seconde supérieure, au moins 1. Le message est distinct de celui du plafond du Broker (ADR-0013) : un client sait si c'est le *débit* (réessayer dans quelques secondes) ou le *nombre en attente* (attendre une décision).
5. **Visible, mais borné : le journal, pas l'audit.** Un refus laisse une ligne dans le journal du Gateway — **une par épisode de refus et par utilisateur**, jamais une par requête refusée : identifiant et limite. Il ne laisse rien dans l'audit : le Gateway n'est pas un émetteur d'audit autorisé (ADR-0010), et un événement par tentative refusée recréerait ce qu'on cherche à borner.
6. **On répare le limiteur dont on dépend, sans jamais l'affaiblir.** (a) Les seaux inactifs depuis assez longtemps pour être pleins sont évincés : un seau plein équivaut à un seau neuf, donc aucune décision ne change, et la mémoire cesse de croître avec le temps. (b) Le limiteur des requêtes authentifiées reçoit les unités que son commentaire promettait (60 par minute, soutenu). (c) Le limiteur du login **garde** son comportement réel — rafale de 5, puis une par minute, plus strict que ce qui était écrit — et ce sont le commentaire et la documentation que l'on corrige : on ne relâche pas une protection contre la force brute pour qu'elle ressemble à son commentaire. (d) Les trois limiteurs disent leur vrai `Retry-After`.
7. **Par processus.** Le seau vit dans la mémoire du Gateway : N réplicas accordent N fois le budget. Un état partagé (Redis, `docs/architecture/system-overview.md`) est un autre sujet.

Réponses : `POST /sessions` ajoute le `429` du Gateway, avec `Retry-After`. Aucun changement du Broker ni du schéma.

**Conséquences**
- (+) Un détenteur de jeton, même sans droit, ne fait plus écrire au Broker que le débit de son seau : 10 lignes en rafale, puis 6 par minute (8 640 par jour au plus), au lieu de « ce que le réseau laisse passer ».
- (+) Le budget est celui de l'identité : le bruit d'un utilisateur ne retire rien aux autres, même derrière un reverse proxy qui masque toutes les adresses.
- (+) La mémoire du limiteur cesse de croître avec le temps, sans qu'aucune décision change.
- (+) **Mesuré** : 50 mutations du limiteur, du Gateway et de sa configuration, 50 détectées (clé sur l'adresse ou le corps, contrôle après la lecture du corps, refusé qui atteint le Broker, unités à l'envers, `Retry-After` faux, éviction trop précoce ou sans marge, login relâché…) ; 16 tests unitaires et 4 d'intégration sur processus réels ajoutés (450 unitaires avec base, 52 PostgreSQL, 33 d'intégration au total). Une de ces mutations est détectée par un dépassement de délai plutôt que par une assertion.
- (−) **Le titulaire légitime d'un jeton volé peut être privé de son budget** : si l'attaquant envoie sans arrêt, chaque jeton qui se reforme (un toutes les 10 secondes) va à qui arrive le premier. Le remède est de révoquer le jeton, pas de toucher au limiteur ; la ligne de journal par épisode est là pour le voir. Même nature que l'auto-verrouillage d'ADR-0013, en beaucoup plus court (10 secondes, pas 15 minutes).
- (−) **Seul `POST /sessions` est couvert.** `approve`, `reject`, `connect`, `terminate` et la liste des demandes en attente ne sont limités que par le limiteur par IP, qui n'est pas fait pour cela et n'est pas juste derrière une arête. À traiter. *(Traité par ADR-0016 pour `approve`, `reject` et `connect`, après mesure ; `terminate` et les lectures ne sont pas couverts, et ce choix est motivé là.)*
- (−) **Les refus de débit ne sont pas dans l'audit**, seulement dans le journal du Gateway.
- (−) **Plusieurs identités, plusieurs budgets** : K jetons compromis donnent K fois le budget. Et **par processus** : N réplicas, N fois.
- (−) **Le limiteur par IP reste faux derrière l'arête** : tous les utilisateurs partagent le seau de l'adresse de Traefik — et, avec les unités corrigées, ce sont 60 requêtes authentifiées par minute pour **toute la plateforme**. Le seau du login, une rafale de 5, peut être épuisé par un seul pour tous. Corriger demande de décider à qui faire confiance pour `X-Forwarded-For` (une confiance mal placée permet de forger sa clé) : décision à part, **non prise ici**, consignée — **prise par l'ADR-0015**.
- (−) Le correctif des unités des requêtes authentifiées **relâche en pratique** une limite qui, telle qu'elle était codée, se vidait en 60 requêtes pour ne plus laisser passer qu'une par minute. C'est ce que la documentation disait ; ce n'est pas ce que le code faisait.

**Alternatives envisagées**
- *Garder la clé par IP* : rejeté — derrière l'arête elle est la même pour tous : un seul utilisateur épuiserait le budget de tous, et la limite ne dirait rien de qui abuse.
- *Ne limiter que les refus* : rejeté — le Gateway ne sait pas ce que le Broker refusera ; et une limite qui ne compte que les refus laisse écrire autant de succès qu'on veut.
- *Un budget global pour `POST /sessions`* : rejeté — une arme : un utilisateur le viderait pour que les autres soient refusés, y compris en urgence.
- *Auditer chaque refus de débit* : rejeté — recrée le flux d'écritures qu'on veut borner, et le Gateway n'est pas un émetteur d'audit autorisé (ADR-0010).
- *Une fenêtre glissante exacte (journal des instants)* : rejeté — plus de mémoire par identité pour une précision sans objet ici ; le seau à jetons est déjà celui du Gateway.
- *Relâcher le limiteur du login pour qu'il fasse « 5 par minute »* : rejeté — cela affaiblirait une protection contre la force brute pour que le code ressemble à son commentaire.
- *Un état partagé (Redis) dès maintenant* : rejeté pour l'instant — un composant à déployer et à rendre disponible, pour un risque que le budget par processus borne déjà ; consigné.
