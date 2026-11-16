# ADR-0115 — Réduire la durée de vie des secrets en mémoire et interdire les core dumps

**Statut** `Accepté` · 2026-11-16 · accepté par le propriétaire du projet pour l'incrément SI-05.

**Contexte** — Le coffre remet des credentials en `[]byte` aux proxies. Le cycle `Credential.Purge` efface déjà le buffer principal, mais plusieurs chemins créent des représentations temporaires : corps JSON base64, chaînes immuables exigées par `x/crypto/ssh`, et buffers de commande de rotation. Le proxy SSH validait les octets en les convertissant en `string`. Les processus `password-vault`, `ssh-proxy` et `rdp-vnc-proxy` n'interdisaient pas eux-mêmes les core dumps ni le ptrace ordinaire. Un dump mémoire ou un outil de diagnostic privilégié peut donc exposer des secrets avant leur purge.

Les invariants touchés sont ADR-0003 (le secret n'est livré qu'au proxy), ADR-0010 (TLS interne), ADR-0037/0039 (rotation et identité de cible), ADR-0097 (injection directe, sans presse-papiers ni enregistrement), et la politique de minimisation des données.

**Décision**

1. Les processus Linux qui détiennent ou déchiffrent des credentials — `password-vault`, `ssh-proxy` et `rdp-vnc-proxy` — appliquent `HardenSecretProcess()` avant d'ouvrir leurs listeners. La fonction fixe et vérifie `RLIMIT_CORE=0`, puis `PR_SET_DUMPABLE=0` / `PR_GET_DUMPABLE=0` via l'API syscall de la bibliothèque standard. Si l'une des opérations ou vérifications échoue, le processus refuse de démarrer.
2. Le durcissement est sans interrupteur de contournement en production. Il interdit les core dumps du processus et le ptrace ordinaire ; il ne prétend pas résister à un noyau compromis, à un hyperviseur hostile ou à un acteur disposant de `CAP_SYS_PTRACE` dans le bon espace de noms.
3. `securemem.Zero([]byte)` centralise l'écrasement best-effort avec `clear` et `runtime.KeepAlive`. `Credential.Purge` l'utilise puis abandonne sa référence au buffer. Cette primitive ne promet ni mémoire verrouillée, ni absence de swap, ni effacement des copies déjà créées par le runtime ou une bibliothèque.
4. Les clients HTTP du Vault effacent les buffers JSON de requête (scope token) et de réponse (base64 du credential), imposent `Cache-Control: no-store`, bornent la réponse à 1 MiB et effacent tout buffer décodé en cas d'erreur. Les bytes décodés restent la propriété du `Credential` et sont purgés après l'authentification.
5. Le proxy SSH valide les caractères UTF-8 directement sur `[]byte`, sans matérialiser une chaîne. La rotation SSH réduit la durée de vie de la chaîne temporaire exigée par `ssh.Password`, retire les références à l'issue du handshake et efface le buffer `chpasswd` à la sortie.
6. Les journaux, événements d'audit, marqueurs vidéo, enregistrements et traces ne reçoivent jamais le contenu du credential. Les tests doivent vérifier la purge, les limites HTTP, le durcissement Linux dans un sous-processus et l'absence de régression des flux SSH/RDP/VNC.

**Conséquences**

- (+) Les trois processus échouent fermés si le système ne peut pas désactiver les core dumps ou le dumpability.
- (+) Aucun nouveau module externe n'est ajouté : les appels Linux utilisent `syscall` de la bibliothèque standard.
- (+) Les buffers sous le contrôle d'OpenBastion sont effacés de manière uniforme ; les buffers JSON du transport ne persistent plus volontairement après décodage.
- (+) Le proxy SSH n'alloue plus de copie `string(secret)` pour la validation des caractères.
- (−) Go ne fournit pas de garantie générale d'effacement de toutes les copies : chaînes immuables, GC, buffers TLS, allocations internes et mémoire du noyau restent hors de portée de `securemem.Zero`.
- (−) Le mot de passe transmis à `x/crypto/ssh` doit encore être représenté temporairement en `string`; la référence est raccourcie, mais l'allocation ne peut pas être écrasée de façon sûre via l'API publique.
- (−) `PR_SET_DUMPABLE=0` complique le débogage avec ptrace et certains collecteurs de crash. Le diagnostic de production doit s'appuyer sur les métriques, logs expurgés et traces sans payload.
- (−) Cette décision ne protège pas contre un processus déjà compromis, un administrateur hôte disposant de capacités noyau, ni une copie volontaire du secret par le protocole cible.

**Alternatives envisagées**

- **Dépendre uniquement de `ulimit -c 0` dans Docker Compose** : insuffisant pour Kubernetes et les exécutions hors conteneur ; le durcissement doit être appliqué et vérifié par le processus.
- **Désactiver le GC ou verrouiller toute la heap avec `mlockall`** : trop large, fragile avec les limites mémoire des conteneurs et ne supprime pas les copies déjà créées. Cela ne donne pas une garantie d'effacement Go.
- **Introduire une bibliothèque de mémoire sécurisée tierce** : non retenu à ce stade ; la surface d'intégration et les contraintes de pages verrouillées ne sont pas justifiées par une preuve de besoin. Réévaluer si un HSM ou un agent de secrets impose une mémoire dédiée.
- **Promettre une purge cryptographiquement vérifiable de la mémoire Go** : impossible avec les garanties du runtime et des bibliothèques actuelles ; la documentation doit rester explicite sur cette limite.

**Critères de validation**

- Tests Linux en sous-processus : `RLIMIT_CORE` soft/hard à zéro et `PR_GET_DUMPABLE` égal à zéro après durcissement.
- Tests unitaires : `securemem.Zero` efface le backing array ; `Credential.Purge` reste idempotent et interdit tout accès ultérieur.
- Tests clients Vault : corps limité, `no-store`, réponse malformée et erreurs avec purge des buffers ; le credential livré reste utilisable jusqu'à la fin de l'authentification.
- Tests SSH : validation Unicode sans conversion en chaîne et rotation sans secret dans argv/logs.
- `go test`, `go test -race`, `go vet`, build des trois services et `git diff --check`.
