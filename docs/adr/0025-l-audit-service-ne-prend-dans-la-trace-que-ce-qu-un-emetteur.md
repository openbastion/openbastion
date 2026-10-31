# ADR-0025 — L'Audit Service ne prend dans la trace que ce qu'un émetteur peut vouloir dire


**Contexte**
ADR-0024 l'avait constaté en lisant le code : l'Audit Service ne borne ni le corps d'`emit-event`, ni aucun de ses champs. Les émetteurs le faisaient chacun de leur côté (le Recorder borne l'identifiant de session depuis ADR-0024), mais la trace signée est l'endroit où une valeur, une fois chaînée, reste pour toujours. J'ai écrit le test d'abord, sur un processus réel, et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Tout est pris.** Un corps de 1 Mio est chaîné (`200`) ; une action « session read » (avec une espace), une action en capitales, un identifiant avec un saut de ligne — une fausse ligne dans tout journal qui l'affiche —, un octet d'échappement de terminal, un identifiant de 257 octets : tous chaînés.
- **Les erreurs parlaient trop.** Un corps qui n'est pas du JSON recevait le message du décodeur (qui nomme la structure Go interne) ; une erreur du store était renvoyée telle quelle à l'émetteur (adresse de la base, nom de table).
- **La méthode n'était pas vérifiée** : hors mTLS, un `GET` était décodé (`400`, pas `405`).
- **Ce que les émetteurs écrivent vraiment** (relevé de tous les appels) : quinze actions, toutes en minuscules à points et soulignés (`session.breakglass_requested`, `recording.read`…), un seul type (`session`), des identifiants de session créés par le Broker ou bornés à 256 octets par le Recorder, un auteur qui est un identifiant d'utilisateur ou vide (le proxy).

**Décision**
Six règles.

1. **Chaque champ a une forme et une taille** : `action` de 1 à 64 octets dans `[a-z0-9_.]` ; `resource_type` de 1 à 64 octets dans `[a-z0-9_]` ; `resource_id` de 1 à 256 octets et `actor_id` de 0 à 256 octets (vide = action système), en UTF-8 valide **sans caractère de contrôle**. Les bornes sont plus larges que tout ce qui est émis aujourd'hui.
2. **Le corps est borné à 16 Kio** (le plus gros événement permis tient en moins de 2 Kio de JSON) : au-delà, `413`, sans le lire en entier.
3. **Validé avant de toucher la chaîne** : un événement refusé ne prend pas de verrou, ne lit pas le dernier hash, n'est pas ajouté.
4. **Un refus nomme le champ et la règle, jamais la valeur** (`400`) ; un corps qui n'est pas du JSON reçoit un message fixe ; une erreur du store est un `500` générique, sa cause au journal de l'Audit Service.
5. **`POST` seulement** (`405`), même hors mTLS.
6. **Les émetteurs ne changent pas de comportement** : pour eux, un `400` est un échec d'écriture comme une panne — fermé là où ils sont fermés (création de session, lecture servie…), au mieux ailleurs. Le Recorder refuse en amont (`400`, « not a session id ») un identifiant qui contient un caractère de contrôle, pour qu'aucune lecture servie ne bute sur l'audit avec un `503` incompréhensible.

**Conséquences**
- (+) La trace n'est plus un endroit où l'on stocke ce qu'on veut : forme et taille de chaque événement sont bornées, et aucun identifiant ne peut y forger une ligne de journal.
- (+) Un émetteur défaillant ou usurpé qui écrit hors de la forme est refusé et le dit dans son journal.
- (+) **Mesuré** : *Avant* (processus réel, rouge) : un corps de 1 Mio, une action « session read », une action en capitales, un identifiant avec un saut de ligne ou un échappement de terminal, 257 octets : tous chaînés (`200`) ; `GET` répondu `400`. *Après*, sur processus réel : les quinze actions émises aujourd'hui, avec et sans auteur, et un identifiant de 256 octets sont pris ; treize formes hors bornes sont des `400` qui ne répètent rien de ce qui a été envoyé ; 1 Mio est un `413` ; `GET` est un `405` ; la chaîne prend encore des événements et se vérifie. En unitaire : les bornes exactes sont acceptées, quinze formes refusées sans que l'erreur répète la valeur, ni brute ni échappée, et la chaîne n'en garde aucune ; en HTTP : `400` qui nomme le champ, corps non JSON ou mal typé sans citer le corps ni le code, 17 Kio `413` et 15 Kio `200`, `405` pour trois méthodes, erreur du store générique et journalisée. Le Recorder refuse en amont un identifiant avec un caractère de contrôle. **24 mutations distinctes** (validation absente ; longueur des noms et des identifiants absente ou décalée d'un ; capitales, tiret, point dans le type acceptés ; action, type ou identifiant vides acceptés ; auteur vide refusé ou auteur non contrôlé ; UTF-8 et caractères de contrôle non contrôlés ; valeur répétée dans l'erreur ; corps non borné, borne trop petite, `413` rendu `400` ; message du décodeur renvoyé ; événement invalide rendu `500` ; erreur du store renvoyée ou non journalisée ; toute méthode ; Recorder qui accepte un caractère de contrôle) : 19 tuées d'emblée, **2 survivantes réelles** (l'erreur qui répète la valeur sous sa forme échappée ; le message du décodeur, qui nomme la structure Go interne) **closes par deux tests**, 3 réécrites parce qu'elles ne compilaient pas (import devenu inutile) et tuées ; une vingt-cinquième, doublon de la première, retirée du compte. Tests : 586 unitaires sans base (46 ignorés), 632 avec ; 52 PostgreSQL ; 44 d'intégration sans base (6 ignorés), 50 avec ; `go test -race` propre sur l'Audit Service, le Recorder et les tests d'intégration concernés.
- (−) **Les bornes sont dans le code** ; un futur émetteur dont les valeurs sortent de la forme (une action avec un tiret, un identifiant de 300 octets) sera refusé — c'est voulu, et cela se lit dans son journal, mais il faudra élargir la règle dans l'Audit Service.
- (−) **Un émetteur compromis écrit toujours des événements vrais dans la forme, au nom de n'importe qui** : les événements ne sont pas attribués par l'identité du certificat (limite connue).
- (−) **Le hash de la chaîne concatène les champs sans séparateur ni longueur** (constaté en lisant `computeHash` pendant cet incrément) : un octet déplacé d'un champ au voisin laisse le hash inchangé. Les bornes ne le corrigent pas. **Objet d'ADR-0026.**

**Alternatives envisagées**
- *Laisser chaque émetteur borner* : rejeté — la trace dépend alors du moins soigneux, et d'un certificat d'émetteur volé.
- *Tronquer ou échapper au lieu de refuser* : rejeté — l'événement chaîné ne serait plus celui qui a été émis.
- *Refuser les champs inconnus du JSON* : rejeté — ils ne sont ni stockés ni hachés ; les refuser casserait un ajout de champ futur (le proto est additif).
- *Une liste fermée d'actions connues* : repoussé — plus strict, mais chaque nouvelle action demanderait de changer l'Audit Service en même temps que l'émetteur ; l'alphabet suffit à ce que la trace ne contienne rien d'arbitraire.
