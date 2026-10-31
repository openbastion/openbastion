# ADR-0028 — La tête de la chaîne d'audit est ancrée hors de la base, et la chaîne se vérifie contre ses ancres


**Contexte**
C'est le second des deux mécanismes demandés par Bony Kiss (le premier, la clé, est ADR-0027). ADR-0027 avait écrit ce que la clé seule ne ferme pas ; j'ai écrit le test d'abord, sur un processus réel et une vraie PostgreSQL, et constaté qu'il échouait. Ce qui a été **mesuré** :

- **Une chaîne réécrite entièrement, depuis son premier événement, au format sans clé v2** (que l'attaquant sait calculer) se vérifie : rien dans la base ne dit qu'elle a déjà été à clé — les règles d'ADR-0026 (une version ne recule pas) ne voient rien quand **toutes** les lignes reculent ensemble.
- **La fin de la chaîne coupée** (les derniers événements supprimés) se vérifie : la chaîne restante est cohérente.
- **Aucun fichier d'ancres n'est demandé ni écrit**, et la période n'est pas bornée (elle n'existe pas).
- **Un défaut de conception trouvé en écrivant l'ancrage** (avant de le livrer) : une ancre qui prend la tête *telle que la base la donne au moment d'ancrer* valide la base falsifiée entre deux ancres. L'ancre doit nommer **ce que le processus a écrit**.
- **Une limite préexistante, jamais écrite** : l'extension de la chaîne est sérialisée par un verrou *dans le processus* ; deux réplicas de l'Audit Service sur la même base feraient bifurquer la chaîne. L'ancrage ajoute la même contrainte.

**Décision**
Neuf règles.

1. **Une ancre** = `{event_id, hash, at, key_id, mac}` : le dernier événement écrit, son hash, la date de l'ancre, l'identifiant de la clé de chaîne, et `mac = HMAC-SHA256(clé, "openbastion.audit.anchor.v1" 0x00 ‖ L(event_id) ‖ L(hash) ‖ L(key_id) ‖ at_ns)` — l'étiquette empêche qu'un MAC d'ancre soit pris pour un MAC d'événement.
2. **L'ancre nomme `tip`**, le dernier événement que **ce processus** a ajouté, avec le hash qu'il a calculé ; la base n'est lue (`Last`) qu'avant le premier ajout du processus (un redémarrage), faute de mieux.
3. **Une ancre par période où la tête a avancé** : `AUDIT_ANCHOR_INTERVAL_SECONDS`, **60** par défaut, de 1 à 3600, hors bornes fatal. Pas de nouvelle ancre pour une tête déjà ancrée ; un échec d'écriture n'avance pas la mémoire de la dernière ancre (la même tête est réessayée).
4. **Où** : un fichier en ajout seul, `AUDIT_ANCHOR_FILE`, **absolu**, créé au démarrage (droits 0600) puis seulement complété, chaque ancre écrite avec `fsync` — **jamais recréé** : un fichier disparu, ce sont des ancres illisibles, pas une installation neuve. Volontairement pas une table : la base ne doit avoir aucun pouvoir sur ce qui la contredit. Le déploiement le met sur un autre volume, idéalement en ajout seul (WORM) et répliqué hors de l'hôte de la base.
5. **Obligatoire avec `DATABASE_URL`** (refus de démarrer sans lui, ou si son répertoire n'existe pas) ; en mémoire, pas d'ancrage (rien ne réécrit la chaîne derrière le processus), et l'annonce le dit.
6. **`verify-chain` vérifie la chaîne contre ses ancres** : chaque ancre est authentique (MAC, sous une clé tenue), son événement est **dans la chaîne avec le même hash**, et les ancres suivent l'ordre de la chaîne. Sinon `409`, qui dit laquelle et pourquoi.
7. **Des ancres illisibles ne sont pas un verdict** : `503` (« the chain cannot be vouched for »), jamais `200` ; le chemin reste dans le journal.
8. **L'ancrage ne bloque pas l'audit** : un échec d'écriture d'ancre est une ligne de journal par épisode ; les événements restent écrits et signés.
9. **L'Audit Service est en instance unique** (`docs/deployment/high-availability.md`), ce qui était déjà vrai de la chaîne.

**Conséquences**
- (+) **Une chaîne réécrite — même entièrement, dans un format sans clé — ou coupée avant la dernière ancre est trahie** par une ancre hors de la base.
- (+) **Une ancre ne valide jamais une base falsifiée entre deux ancres** (règle 2).
- (+) La limite « instance unique » de l'Audit Service est enfin écrite.
- (+) **Mesuré** : avant, une chaîne réécrite entièrement au format v2 → `200`, une fin coupée → `200`, aucun fichier d'ancres demandé ; après, les deux → `409` qui nomme l'ancre, une ancre modifiée dans le fichier → `409`, un fichier disparu → `503`, une seule ancre par tête. Audit Service : application +5 (22 → 27), infrastructure +4 (fichier d'ancres), interfaces +1 (4 → 5) ; un test d'intégration sur processus réel et vraie PostgreSQL. **26 mutations : 24 tuées, 1 survivante équivalente (chemin vide) close par un test renforcé, et l'`fsync` retiré n'est pas observable par un test** (il ne se prouve qu'en coupant le courant). 659 unitaires (612 sans base, 47 ignorés), 56 PostgreSQL, 53 d'intégration (44 sans base, 9 ignorés), `-race` propre.
- (−) **Ce qui a été écrit depuis la dernière ancre peut être tronqué sans être vu** : la période (60 s par défaut) est la fenêtre d'exposition.
- (−) **Quelqu'un qui écrit à la fois dans la base et dans le fichier d'ancres**, ou qui tient l'hôte de l'Audit Service (donc la clé), peut tout réécrire : la protection vaut ce que vaut la séparation des deux.
- (−) **Un fichier d'ancres vidé** (et non supprimé) ressemble à une installation neuve : seule une destination en ajout seul l'empêche.
- (−) **Seule une destination fichier est implémentée** : pas de stockage objet WORM ni de journal de transparence distant.
- (−) **Le `fsync` de chaque ancre n'est prouvé par aucun test** (il faudrait simuler une coupure de courant).
- (−) **`verify-chain` lit tout le fichier d'ancres**, comme il lit toute la chaîne : linéaire.
- (−) **Instance unique** (règle 9).

**Alternatives envisagées**
- *Une table d'ancres dans la même base* : rejeté — celui qui réécrit la chaîne réécrit les ancres.
- *Ancrer `store.Last` au moment de l'ancre* : rejeté (règle 2) — trouvé en écrivant le test unitaire, avant livraison.
- *Une ancre à chaque événement* : rejeté — une écriture hors base (et un `fsync`) par événement sur le chemin fermé des sessions ; la période borne le coût et dit la fenêtre.
- *Bloquer l'audit quand l'ancrage échoue* : rejeté — l'ancrage est une défense de la preuve passée, pas une condition pour en écrire de nouvelles.
- *Recréer le fichier s'il manque* : rejeté — ce serait renoncer en silence aux ancres passées.
- *Une destination distante (stockage objet WORM, journal de transparence)* : repoussé — dépendance réseau et SDK (bloqués dans le sandbox d'origine) ; le port `AnchorSink` est fait pour l'accueillir.
