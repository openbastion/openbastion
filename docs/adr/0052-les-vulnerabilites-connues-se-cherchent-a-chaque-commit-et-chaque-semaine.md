# ADR-0052 — Les vulnérabilités connues se cherchent à chaque commit et chaque semaine, sur les modules sous leur vrai nom

**Contexte**
Demande de Bony Kiss (31 octobre 2026) : un contrôle des vulnérabilités avant la feuille de route v0.0.1. Rien ne le faisait jusque-là (ADR-0047 le notait : « pas de `govulncheck` ni de `npm audit` »). Le premier passage de `govulncheck` v1.9.0 (base du 27 octobre 2026), en mode symboles, sur les 17 modules du `go.work`, a trouvé :

- **12 vulnérabilités de la bibliothèque standard de Go 1.27.1 dont le code est appelé** (serveur et client HTTP/2, `net/http`, `crypto/tls`, `crypto/x509`, `net/textproto`), corrigées en 1.27.2 et 1.27.3 ;
- **1 dans `github.com/golang-jwt/jwt/v5` v5.2.1**, appelée par l'Authentication Service (allocation excessive à la lecture d'un en-tête, GO-2025-3553), corrigée en v5.2.2 ;
- **et rien sur `golang.org/x/crypto` v0.24.0 — à tort.** Les modules le remplaçaient par un miroir (`replace golang.org/x/crypto => github.com/golang/crypto`), posé quand le réseau du bac à sable ne joignait pas `golang.org`. Sous ce nom, `govulncheck` ne reconnaît pas le module. La même version, sous son vrai nom, a **21 vulnérabilités** publiées avec un correctif (et un paquet signalé abandonné, `openpgp`), dont une dizaine touchent un serveur SSH — ce qu'est le proxy : paniques (GO-2026-5013, GO-2026-5015), blocages et dénis de service (GO-2026-5016, -5017, -5018, -5020, -6354, -6355, GO-2025-3487, GO-2025-4134), et un **contournement des restrictions de certificat** (GO-2026-5014), qui touche directement la vérification d'ADR-0048.

`npm audit` : rien sur l'Admin UI ; **1 vulnérabilité de gravité faible** dans la bibliothèque d'icônes (`web/openbastion-icons`) : `esbuild` 0.27.7, dépendance de construction de `tsup`, dont le serveur de développement laisse lire des fichiers sous Windows (GHSA-g7r4-m6w7-qqqr, versions 0.27.3 à 0.28.0). Un premier relevé l'avait manquée : j'avais mal lu la sortie.

**Décision** *(demande de Bony Kiss du 31 octobre 2026 : « fais un check sur les vulnérabilités » ; la forme est renversable)*

1. **Corriger** : `esbuild` ramené à 0.27.2 par `npm audit fix` (hors de la plage vulnérable ; la 0.28.2 est hors de la plage de `tsup`) ; Go 1.27.3 (CI, images de construction épinglées par empreinte, ADR-0051) ; `golang.org/x/crypto` v0.58.0 (v0.56.0 suffit pour tout ce qui est publié ; la dernière, prise une fois) et `x/sys` v0.49.0 qu'elle entraîne ; `jwt/v5` v5.3.1. `x/crypto` v0.58.0 exige Go 1.26 : les modules qui en dépendent, et `go.work`, déclarent désormais `go 1.26.0` au lieu de 1.22. Aucune dépendance nouvelle.
2. **Retirer le miroir** : `golang.org` est joignable ; les modules sont tirés sous leur vrai nom (le `Makefile` garde `GOPROXY=direct`, `go.sum` fait foi). Un remplacement d'un module externe par un autre chemin rend le scan aveugle : il n'en est plus posé sans ADR.
3. **Chercher à chaque fois** : `make vuln` lance `govulncheck` (épinglé en v1.9.0) sur chaque module du `go.work` et `npm audit` sur les deux lockfiles ; un job de CI (`vulnerabilities`) la lance à chaque `push` et chaque pull request, **et chaque lundi** — une vulnérabilité publiée sans commit de notre part fait échouer la CI de la semaine. Une vulnérabilité dont le code est appelé fait échouer le job ; une vulnérabilité de module sans appel est rapportée, sans échec.

**Conséquences**
- (+) **Mesuré, après** : `make vuln` sous Go 1.27.3 — 17 modules, **0 vulnérabilité appelée** ; npm, 0 sur les deux lockfiles. Contre-épreuve : `jwt` remis en v5.2.1, le scan trouve GO-2025-3553 et sort en échec.
- (+) **La vérification complète passe sur la nouvelle chaîne** (Go 1.27.3, `x/crypto` v0.58.0) : unitaires 778 sans base, 838 avec ; `make test-postgres` 78 ; intégration 54 sans base, 79 avec ; Admin UI 25 ; `gofmt` vide ; `-race` sur 34 paquets, aucune course ; **`make test-compose` vert** (172 s) sur les images en Go 1.27.3.
- (+) **Trouvé en chemin** : sous `-race`, `TestStrictRecording_ASessionIsRefusedBeforeTheCredentialIsFetched` échouait environ une fois sur vingt : le proxy refuse la session (enregistreur indisponible) et ferme le canal avant que le client ait reçu la réponse à sa demande de shell, qui lit alors `EOF`. Le comportement du proxy est le bon ; c'est l'aide du test qui tenait cette réponse pour acquise. Elle accepte désormais cet `EOF` et lit ce que l'opérateur a reçu ; le test passe 100 fois de suite sous `-race`.
- (−) Le scan ne voit que ce qui est publié dans la base de Go et dans celle de npm ; les images (paquets d'Alpine, de Debian, de Node) ne sont pas analysées.
- (−) Les modules déclarent `go 1.26.0` : un développeur avec un Go plus ancien ne compile plus. La CI, les images et le développement sont en 1.27.3.
- (−) Une mise à jour de `x/crypto` sur onze versions mineures change du code SSH sous le proxy et la rotation : ce sont les tests (unitaires, processus réels, OpenSSH, `make test-compose`) qui le couvrent.
- (−) Le job du lundi échoue sur une vulnérabilité nouvelle sans que personne n'ait rien changé : c'est voulu, et quelqu'un doit le lire.
- (−) `GO-2026-5932` (`x/crypto/openpgp` abandonné) reste signalé au niveau du module ; le dépôt n'importe pas ce paquet, et il n'a pas de correctif.

**Alternatives envisagées**
- **Garder le miroir et lancer le scan quand même** : le scan dirait « rien » sur la bibliothèque la plus exposée du projet.
- **`x/crypto` v0.56.0, la version minimale** : aussi valable ; la dernière a été prise pour ne pas repasser demain.
- **Un scanner d'images** (Trivy, Grype) : un outil tiers de plus ; à décider à part — **décidé par ADR-0060** (Trivy, binaire vérifié contre son empreinte).
- **Dependabot** : ouvrirait des pull requests de lui-même (la policy demande d'en décider) ; à décider à part.
