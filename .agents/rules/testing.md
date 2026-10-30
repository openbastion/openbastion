# Tests

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

1. **Chaque comportement a un test ; chaque garantie de sécurité a un test d'attaque et une contre-épreuve.** Teste le cas heureux, le refus, le cas limite et l'attaque.
2. Niveaux : unitaire (à côté du code, hermétique) ; PostgreSQL (`TEST_DATABASE_URL`, se skippe sans base) ; intégration sur **processus réels** (`test/integration/`, binaires compilés par le test) ; Compose (`COMPOSE_TEST=1`, `make test-compose`) ; Admin UI (Vitest).
3. **Rouge d'abord** : un correctif ou une garantie nouvelle se mesure d'abord en rouge — un test qui échoue sur le code d'avant (dans un worktree de l'ancien commit si l'API a changé).
4. **Contre-épreuve (mutation)** : introduis la faute que la garantie prévient, lance le test, vérifie qu'il **échoue**, restaure depuis une sauvegarde **unique par fichier et par mutation**, vérifie avec `cmp`. Une mutation qui ne compile pas ne compte pas : réécris-la. Une survivante est un trou du test ou du code mort : corrige l'un ou l'autre. Consigne « N mutations, N tuées ».
5. Ports d'intégration : un bloc libre par fichier — `grep -ohE '"1[89][0-9]{3}"' test/integration/*.go | sort -u` — jamais un port d'un autre fichier.
6. Une assertion **négative** attend d'abord que le système ait eu le temps d'agir (`waitUntil`, un espion d'audit) ; jamais un `Sleep` nu dans une assertion positive.
7. Pas de test fragile : horloge injectable, pas d'ordre de map, identifiants uniques dans une base partagée, aucun `bytes.Buffer` partagé entre goroutines.
8. Réutilise les aides existantes (`buildBinary`, `startService`, `startAuditSpy`, `gatewayLogin`, `openssh`, `waitUntil`…) avant d'en écrire.
9. **Compter** : tests de premier niveau = `go test -v … | grep -c '^--- PASS'`, avec et sans `TEST_DATABASE_URL` ; n'écris que des nombres que tu viens de mesurer.
