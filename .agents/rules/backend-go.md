# Go (services, bibliothèques, CLI)

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

1. `go 1.22` dans chaque `go.mod`. Code formaté par `gofmt`, `go vet` propre.
2. **Bibliothèque standard d'abord.** Pas de framework web, pas d'injection de dépendances, pas de framework de mocks : des interfaces étroites et des fakes écrits à la main.
3. `context.Context` en premier paramètre de toute opération qui peut bloquer ou appeler le réseau ; jamais stocké dans une struct.
4. Erreurs : renvoie-les, ne les avale pas ; `fmt.Errorf("verbe objet: %w", err)` ; messages en minuscules, sans point final ; erreurs sentinelles (`ErrX`) pour ce que l'appelant distingue (`errors.Is`).
5. Concurrence : tout état partagé est protégé ou confiné ; teste avec `-race` ce que tu touches ; pas de goroutine sans condition d'arrêt claire. Un fake de test partagé entre goroutines est protégé aussi.
6. Pas de variable globale mutable, pas d'`init()` à effet de bord, pas de `panic` hors erreur de programmation détectée au démarrage (table de règles mal formée).
7. Configuration : lue dans `main.go` seulement ; défaut strict ; hors bornes ou inconnue = `log.Fatalf` au démarrage ; le mode faible s'annonce (`settings/security.yaml`).
8. Un secret en mémoire est purgé après usage ; jamais dans une erreur ni un journal.
9. Une boucle de fond (balayage, rotation, archivage) a un intervalle borné, un délai par passage, et s'arrête avec le contexte du processus.
