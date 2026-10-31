# ADR-0027 — La chaîne d'audit est à clé (HMAC), et chaque événement dit quel service l'a écrit


**Contexte**
ADR-0026 a déclaré la limite que rien n'écrivait jusque-là : *la chaîne n'a pas de clé — qui peut écrire dans `audit_events` peut recalculer toute la fin de la chaîne.* Bony Kiss a choisi de la fermer par **deux** mécanismes : une chaîne à clé (cet ADR) et un ancrage périodique hors de la base (ADR-0028). J'ai écrit le test d'abord, sur un processus réel et une vraie PostgreSQL, et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Une fin de chaîne recalculée passe.** L'attaquant modifie le `resource_id` d'un événement puis recalcule tous les hashes et liens suivants au format public v2 : `verify-chain` répond `200`.
- **Le service démarre avec une base et sans aucune clé**, et un changement de clé ne se voit pas (il n'y en a pas).
- **Le format est figé une fois écrit** (ADR-0026, règle 6) : tout ce qu'un événement doit couvrir se décide maintenant. L'attribution d'un événement au service qui l'a écrit — d'après son certificat mTLS — était la limite suivante (« événements non attribués par l'identité du certificat ») : elle entre dans le même format.

**Décision**
Huit règles.

1. **Format 3** : `HMAC-SHA256(clé, "openbastion.audit.event.v3" 0x00 ‖ L(prev_hash) ‖ L(id) ‖ L(actor_id) ‖ L(action) ‖ L(resource_type) ‖ L(resource_id) ‖ L(emitter) ‖ L(chain_key_id) ‖ success ‖ ts_ns)`, avec l'encadrement d'ADR-0026. **Seul le format 3 s'écrit**; 1 et 2 restent pour vérifier.
2. **La clé** : `AUDIT_CHAIN_KEY_HEX`, 32 octets en hexadécimal, **obligatoire avec `DATABASE_URL`** — l'Audit Service refuse de démarrer sans elle ou avec une valeur qui n'en est pas une, en nommant la variable et **jamais la valeur**. En mémoire, la chaîne meurt avec le processus : une clé aléatoire suffit, et l'annonce le dit. La clé n'est jamais stockée, journalisée ni renvoyée.
3. **Un identifiant de clé, pas la clé** : `chain_key_id` = les 8 premiers octets de `SHA-256("openbastion.audit.chain-key-id" 0x00 ‖ clé)`, stocké avec chaque événement et couvert par le HMAC.
4. **Rotation** : `AUDIT_CHAIN_PREVIOUS_KEYS_HEX` (séparées par des virgules) vérifient ce qu'elles ont signé et ne signent rien. Un événement signé par une clé que le service ne tient pas est un `409` qui nomme l'identifiant de la clé : le service ne peut pas s'en porter garant.
5. **L'émetteur** : le service que nomme le certificat mTLS de l'appelant (`mtls.CallerFrom`), jamais une valeur du corps ; vide quand `INTERNAL_TLS=disabled`. Borné (0 à 64 octets `[a-z0-9-]`) et couvert par le HMAC : passer un événement pour celui d'un autre service le casse.
6. **Les formats sans clé ne portent ni émetteur ni clé** : une ligne v1 ou v2 qui en porte n'a pas été écrite ainsi.
7. **Comparaison en temps constant** (`hmac.Equal`).
8. **Le contrat ne change pas** : `EmitEventRequest` n'a pas de champ émetteur (il vient du certificat) ; la table reçoit deux colonnes additives (`emitter`, `chain_key_id`, vides par défaut pour les lignes antérieures).

**Conséquences**
- (+) **Sans la clé, une fin de chaîne réécrite ne se vérifie pas**, quel que soit le format dans lequel l'attaquant la recalcule.
- (+) **Chaque événement dit quel service l'a écrit**, d'après une preuve et non une déclaration : un Recorder compromis écrit à son propre nom.
- (+) **Mesuré** : *Avant* (processus réel, vraie PostgreSQL, rouge) : une fin de chaîne réécrite et recalculée au format public v2 — `200` ; démarrage avec une base et sans clé ; changement de clé invisible. *Après*, sur processus réel : sans clé, avec une clé de 2 octets, une clé non hexadécimale, ou une clé précédente invalide, l'Audit Service refuse de démarrer en nommant la variable et sans jamais afficher la clé ; une fin de chaîne réécrite et recalculée sans la clé, étiquetée v2 ou v3, est un `409`, puis `200` une fois restaurée ; un redémarrage avec la même clé continue la chaîne et la vérifie ; une autre clé seule donne `409` « … does not hold » ; la même avec l'ancienne en clé précédente vérifie et signe avec la nouvelle ; le test mTLS de bout en bout (huit processus) passe avec l'émetteur tiré des certificats. En unitaire : lecture des clés (bornes, espaces, erreur qui ne répète aucune clé), identifiant stable, propre à chaque clé et qui ne révèle pas la clé, fin de chaîne recalculée sans clé en v2 et en v3 sous une autre clé, rotation, émetteur stocké, couvert et borné, émetteur du certificat et non du corps, ligne sans clé qui porte un émetteur ou une clé, vecteur v3 recalculé en Python (`hmac`). **22 mutations** (HMAC remplacé par une clé constante ; émetteur, identifiant de clé ou étiquette non couverts ; identifiant non dérivé de la clé ; longueur de clé non contrôlée ; clés précédentes ignorées ; erreur qui répète la clé ; événements écrits en v2 ; émetteur non stocké ou non contrôlé ; clé non tenue acceptée ; v3 vérifié sans clé ; ligne sans clé qui porte un émetteur acceptée ; v3 rendu inconnu ; émetteur du corps ; émetteur ou identifiant de clé non stockés en PostgreSQL ; clé non exigée avec une base, clés précédentes non lues, clé non utilisée) : 18 tuées d'emblée, **une survivante réelle** (l'émetteur non stocké en PostgreSQL, que rien ne relisait) **close par un test**, 2 réécrites pour compiler et tuées, **une équivalente** (`len(want) == 0`, inatteignable tant qu'une version inconnue est refusée avant) : 21 sur 21 hors équivalente. Tests : 602 unitaires sans base (47 ignorés), 649 avec ; 55 PostgreSQL ; 44 d'intégration sans base (8 ignorés), 52 avec ; `go test -race` propre.
- (−) **Une chaîne réécrite entièrement, depuis son premier événement, dans un format sans clé (1 ou 2) se vérifie** : rien dans la base ne dit qu'elle a déjà été à clé. **Refermé par ADR-0028** (une ancre hors de la base nomme un événement à clé que la réécriture fait disparaître).
- (−) **La troncature de la fin de la chaîne** (supprimer les derniers événements) n'est pas vue par la clé seule : refermé par ADR-0028 jusqu'à la dernière ancre.
- (−) **La clé est dans l'environnement du processus** : qui contrôle l'hôte de l'Audit Service la lit et peut tout re-signer. Un KMS/HSM qui ne livre jamais la clé est l'étape suivante, pas faite.
- (−) **Une clé perdue rend invérifiable, définitivement, l'histoire qu'elle a signée** : c'est une donnée à sauvegarder hors de la base, pour toute la rétention (guides Administrateur §8 et PRA §3).
- (−) **Un émetteur compromis écrit toujours n'importe quelle action**, à son nom : il n'y a pas encore de liste des actions permises par émetteur.
- (−) **Une opération de plus** (HMAC) par événement, négligeable.

**Alternatives envisagées**
- *Signer avec une clé asymétrique (Ed25519)* : repoussé — la vérification resterait dans le même service ; l'avantage (un vérificateur tiers sans pouvoir de signer) ne vaut qu'avec un vérificateur hors de l'Audit Service, qui n'existe pas encore.
- *Tirer une clé au démarrage quand aucune n'est donnée* : rejeté avec une base — l'histoire de la veille deviendrait invérifiable à chaque redémarrage, sans bruit.
- *Stocker la clé dans la base, chiffrée par la KEK* : rejeté — la clé doit être hors de ce que l'attaquant écrit.
- *Prendre l'émetteur dans le corps de la requête* : rejeté — c'est une déclaration ; le certificat est une preuve (ADR-0010).
- *Faire de l'émetteur une liste d'actions permises dans cet ADR* : repoussé — une décision d'autorisation distincte ; l'attribution d'abord.
