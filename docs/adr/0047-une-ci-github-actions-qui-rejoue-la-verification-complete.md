# ADR-0047 — Une CI GitHub Actions qui rejoue la vérification complète, sur des actions et une image épinglées par empreinte

**Contexte**
Aucune porte automatique ne protège `main` : la vérification complète (`.agents/tasks/releases/full-verification.md`) n'est lancée que par la personne ou l'agent qui livre, sur sa machine, et ses chiffres ne sont vérifiables que par sa parole et `NOTES_SANDBOX.md`. `.agents/settings/ci-cd.yaml` disait ce qu'une CI devrait lancer, et `exists: false`. Le dépôt est hébergé sur GitHub (`github.com/openbastion/openbastion`).

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « Go pour le point 5 », et le choix « actions officielles épinglées » parmi les deux proposés ; la forme est renversable)*

1. **Un workflow, `.github/workflows/ci.yml`**, sur chaque `push` vers `main` et chaque `pull_request` ; une exécution en cours sur la même référence est annulée par la suivante.
2. **Cinq jobs, la vérification complète sans le test Compose** :
   - `go` : `make build vet`, `gofmt -l` sur **tout** le dépôt (vide, sinon échec), `make test` sans base ;
   - `race` : `go test -race` sur tous les modules du `Makefile` ;
   - `integration` : `make test-integration` sans base ;
   - `postgres` : PostgreSQL 16 en service du job ; tests unitaires avec base (purgée avant), `make test-postgres`, puis l'intégration avec base (purgée avant) ;
   - `ui` : `make ui-test ui-build` (`npm ci` sur les lockfiles).
3. **Les dépendances du workflow sont épinglées par empreinte**, jamais par une étiquette qu'on peut déplacer : `actions/checkout`, `actions/setup-go`, `actions/setup-node` (maintenues par GitHub) par empreinte de commit, l'étiquette en commentaire ; l'image `postgres:16` par son empreinte d'index. Les versions de Go (1.27.1) et de Node (24.21.0) sont celles où la vérification locale a été mesurée.
4. **Le moindre privilège** : `permissions: contents: read` pour tout le workflow ; `persist-credentials: false` au checkout (le jeton ne reste pas dans `.git/config` pendant que les tests tournent) ; aucun secret du dépôt n'est lu. La PKI et les clés dont les tests ont besoin sont générées dans le job et meurent avec lui.
5. **Le test Compose** (`make test-compose`, ADR-0033) n'est pas dans la CI : il construit les images et monte la pile entière ; il reste une vérification avant un jalon.

**Conséquences**
- (+) **Mesuré, première exécution** (run `41212800565`, commit `cf95a4f`, 31 octobre 2026) : les cinq jobs verts, en parallèle, 8 min 24 s de bout en bout.
  | Job | Durée | Résultat |
  |---|---|---|
  | `ui` | 31 s | Vitest 25 tests, construction verte |
  | `go` | 1 min 55 s | build, vet, `gofmt -l` vide, 32 paquets de tests unitaires `ok` sans base |
  | `race` | 2 min 23 s | 32 paquets `ok` sous `-race` |
  | `integration` | 3 min 35 s | 50 tests sur processus réels, sans base |
  | `postgres` | 8 min 24 s | 32 paquets unitaires `ok` avec base, `make test-postgres` 76, intégration avec base 74 |

  Les comptes d'intégration et de PostgreSQL sont ceux de la vérification locale du même jour (50, 76, 74).
- (−) La CI dit ce qui casse ; elle n'empêche rien tant qu'une règle de protection de `main` n'exige pas ses jobs. Poser cette règle est un réglage du dépôt sur GitHub, qui revient au propriétaire.
- (−) Les empreintes épinglées ne se mettent pas à jour seules : une version corrigée d'une action ou de l'image PostgreSQL attend qu'on change l'empreinte.
- (−) Les tests à délai fixe (une vingtaine de scénarios sur processus réels, dont celui d'ADR-0034 vu échouer une fois sous charge) peuvent échouer sur un runner lent ; un échec isolé se relance, et sa sortie se garde.
- (−) Pas de test Compose, pas d'analyse de vulnérabilités des dépendances (`govulncheck`, `npm audit`), pas de construction d'images : à décider.
- (−) Les actions ont accès au code du dépôt pendant le job ; c'est le prix de les utiliser, réduit par l'épinglage et les permissions en lecture seule.

**Alternatives envisagées**
- **Aucune action tierce** (checkout par git, Go et Node du runner) : aucune dépendance, mais des versions d'outils qui changent avec l'image du runner, sans que le dépôt le sache. Écartée par Bony Kiss.
- **Étiquettes (`@v7`) plutôt qu'empreintes** : une étiquette se déplace ; une action compromise atteindrait la CI sans changement du dépôt.
- **Un seul job séquentiel** : plus simple, mais un échec de l'UI masquerait celui de PostgreSQL, et la durée serait la somme de tout.
- **GitLab CI** (évoqué par l'arborescence initiale) : le dépôt est sur GitHub.
