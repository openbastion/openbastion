# ADR-0033 — Un déploiement `docker-compose` reproductible, sous mTLS, une base par service, et le premier outil du CLI


**Contexte**
Le MVP a trois critères de sortie (`docs/roadmap.md` §2) ; le troisième, « déploiement reproductible via `docker-compose/` en environnement de développement », n'avait **rien** dans le dépôt : ni `deploy/`, ni image, ni fichier Compose. Les huit services ne tournaient qu'en processus lancés à la main (`make run-*`) ou par les tests. En le préparant, j'ai constaté deux manques qui empêchent une installation de démarrer seule :

- **Aucun moyen de créer le premier utilisateur** sans écrire une requête mTLS à la main : `POST /auth/v1/users` n'accepte que l'identité `admin-cli` (ADR-0010), et aucun outil ne la porte. Le CLI est au périmètre du MVP (`docs/roadmap.md` §2, `docs/development/repository-structure.md` : `cli/openbastion-cli/`) et n'existe pas.
- **L'amorce de démonstration de l'Authentication Service** (`demo-dba` / `demo-password`, faute de `SKIP_DEMO_SEED`) est un mot de passe connu dans une installation qui en a une base.

Mesuré dans cet environnement : Docker Compose v5, les images `golang:1.23-alpine`, `gcr.io/distroless/static-debian12:nonroot` et `postgres:16` se tirent, et un build multi-étapes résout les modules Go dans le conteneur (le service Authorization se construit). Les certificats de `make pki` portent par défaut le nom du service comme nom DNS (`pkg/mtls/pki`), ce qui suffit à la vérification du nom d'hôte quand chaque conteneur porte le nom de son service.

**Décision** *(acceptée sur la consigne de Bony Kiss du 30 octobre 2026 de continuer l'implémentation du MVP ; renversable)*
1. **`deploy/docker-compose/`** : un `Dockerfile` multi-étapes unique (`golang:1.23-alpine` → `distroless/static-debian12:nonroot`, utilisateur 65532, binaire statique `CGO_ENABLED=0 -trimpath`), un `docker-compose.yml`, un `init.sh`.
2. **mTLS obligatoire** (`INTERNAL_TLS=required`, ADR-0010) : les certificats sont produits par l'outil du dépôt (`openbastion-pki all`) par un service Compose ponctuel (`pki`), à chaque `up` (l'autorité est gardée, les certificats des services renouvelés, 720 h par défaut). **L'autorité et sa clé restent dans le volume `pki-ca`, monté par ce seul service** ; chaque service ne monte, en lecture seule, que **son** sous-répertoire du volume `pki` (son certificat, sa clé, le certificat de l'autorité). Aucun mode « développement sans TLS » dans ce fichier.

   *Trouvé en le concevant* : monter tout le répertoire de certificats dans chaque service, comme `make pki` le produit, aurait donné à chacun la clé de l'autorité et les clés des autres — de quoi se fabriquer n'importe quelle identité.
3. **Une base par service** (ADR-0002) : un PostgreSQL 16, six bases et six rôles, chaque rôle propriétaire de sa seule base, mots de passe distincts.
4. **Les secrets** (six mots de passe de base, `KMS_KEY_HEX` du Vault et celui du Recorder — distincts —, `TOKEN_SIGNING_KEY_HEX`, `AUDIT_CHAIN_KEY_HEX`) sont tirés par `init.sh` dans `deploy/docker-compose/.env`, droits 0600, **jamais commité** ; `init.sh` **refuse d'écraser** un `.env` existant (des clés perdues rendent la chaîne et les secrets illisibles).
5. **Volumes séparés** : base, certificats, ancres de la chaîne (ADR-0028), archives (ADR-0032) — ancres et archives jamais dans le volume de la base.
6. **Seuls deux ports sont publiés**, sur `127.0.0.1` par défaut : l'API publique de la Gateway et le port SSH du proxy. Les routes internes ne sortent pas du réseau Compose.
7. **Pas d'amorce de démonstration** : `SKIP_DEMO_SEED=1` partout. Le premier administrateur se crée avec le CLI.
8. **`cli/openbastion-cli`**, premier outil : `user create` et `audit verify-chain`, avec l'identité `admin-cli` (certificat du volume `pki`), mot de passe lu sur l'entrée standard, jamais en argument. Il tourne dans le réseau Compose (`docker compose run --rm cli …`).
9. **Une cible SSH de démonstration** (profil `demo`) : un petit serveur SSH en Go (un shell qui répond à chaque ligne), pour exercer le parcours sans dépendre d'une image tierce.
10. **Le critère de sortie est un test** : `test/integration/compose_test.go`, sous `COMPOSE_TEST=1` (il construit et démarre la pile réelle) — premier administrateur par le CLI, politiques, compte, session, connexion SSH à travers le proxy, relecture des commandes par un auditeur, chaîne vérifiée, **le secret de la cible absent des journaux de la Gateway et du Broker**, puis redémarrage de la pile et tout est encore là.

**Conséquences**
- (+) **Mesuré** : `TestCompose_TheMVPJourneyOnARealDockerComposeStack` (`make test-compose`) passe en 58 s sur la pile réelle — premiers utilisateurs par le CLI, politiques, compte, session, connexion SSH par le port publié, `whoami` et `id` relus par un auditeur, chaîne vérifiée par le CLI, trace en base exactement `session.create,session.connect,recording.read`, aucun secret (clés, mots de passe de base, mot de passe de la cible, ticket) dans les journaux, chaque service seul avec ses trois fichiers, le rôle du Broker n'ouvre aucune autre base, pas de compte de démonstration ; après `restart`, la trace, l'enregistrement et le compte sont là. **11 contre-épreuves sur le déploiement, 11 tuées** : Recorder, Vault ou Audit en mémoire ; clé de l'autorité donnée aux services ; Authentication publié ; Gateway sans mTLS ; amorce de démonstration revenue ; bases ouvertes à tous les rôles ; publication sur toutes les interfaces ; `init.sh` qui écrase ; `.env` lisible par tous.
- (+) Le troisième critère de sortie du MVP a une preuve exécutable.
- (−) Le PostgreSQL du Compose parle en clair sur le réseau Compose (`sslmode=disable`) : acceptable pour un hôte unique, pas pour des bases sur un autre hôte.
- (−) Les images ne sont pas épinglées par empreinte (`@sha256:`) : « reproductible » vaut ici pour le code (`go.sum`), pas pour les images de base.
- (−) Une seule instance de chaque service : ce fichier n'est pas une installation HA (`docs/deployment/high-availability.md`).
- (−) Le CLI ne fait que l'amorçage ; les comptes, politiques et sessions passent encore par l'API publique (`curl`).
- (−) Deux défauts trouvés en le faisant tourner : `authorization` est un mot réservé de PostgreSQL (identifiants maintenant entre guillemets) ; un test qui sondait la disponibilité par des connexions épuisait le budget de connexion par adresse (ADR-0014) — il attend maintenant les lignes « listening ».
- (−) **Dans le codespace de développement**, deux conteneurs d'un même réseau Compose ne se joignaient pas (une table `iptables-legacy` en `FORWARD DROP`) ; le test n'y a tourné qu'avec une règle temporaire posée sur autorisation explicite de Bony Kiss, puis retirée (`.agents/settings/environments/local.yaml`).

**Alternatives envisagées**
- **Binaires construits sur l'hôte puis copiés** : plus rapide, mais l'image dépendrait de la chaîne d'outils de l'hôte.
- **`INTERNAL_TLS=disabled` dans Compose** : plus simple, mais le fichier serait copié tel quel en production ; un invariant (identité tirée du certificat) ne doit pas avoir de mode faible par défaut.
- **Une image SSH tierce comme cible** : une dépendance externe de plus pour une démonstration ; un serveur de 100 lignes sur `x/crypto/ssh`, déjà dans le dépôt, suffit.
