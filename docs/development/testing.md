# Tests

| Niveau | Emplacement | Commande |
|---|---|---|
| Unitaire | à côté du code, `*_test.go` dans chaque `internal/` | `make test SERVICE=<nom>` |
| Intégration | `test/integration/` (Testcontainers) | `make test-integration` |
| End-to-end | `test/e2e/` | `make test-e2e` |
| Performance | `test/performance/` (k6) | `make test-perf` |
| Sécurité | `test/security/` | `make test-security` |

Les tests d'intégration actuels du dépôt (`test/integration/*_test.go`) tournent en mode `INTERNAL_TLS=disabled`, stipulé dans `buildEnv` ; `mtls_flow_test.go` et `mtls_lifecycle_test.go` font tourner les huit services sous mTLS requis avec une PKI générée par test (`mtls_helpers_test.go`), et attaquent le réseau avec des identités de toute sorte.

Un service qui touche à la couche proxy ou au Vault (`docs/development/contributing.md`, « Ajouter un nouveau protocole de proxy » ; `docs/security/secrets-management.md`, `docs/security/secure-development.md`, `docs/security/session-security.md`) n'est pas mergeable sans passage vert de `test-security` — ce n'est pas laissé à l'appréciation du relecteur.

## Cible VNC réelle (ADR-0071)

Les refus de `pkg/vnc` se prouvent contre le serveur factice de ses tests ; l'interopérabilité, contre un vrai serveur. `test/integration/testdata/vnc/target.sh` démarre un TigerVNC réel sans Docker et sans rien installer (paquets Debian/Ubuntu dépaquetés dans un répertoire de travail, espace de noms utilisateur non privilégié) :

```sh
test/integration/testdata/vnc/target.sh /tmp/vnc-target X509Plain &   # ou X509Vnc
eval "$(test/integration/testdata/vnc/target.sh /tmp/vnc-target --env)"
go test ./pkg/vnc/ -run TestRealTarget -count=1 -v
```

`TestScreenFlow_VNC…` (`test/integration/screen_flow_test.go`, `TEST_DATABASE_URL` requis) rejoue tout le parcours sur processus réels, contre un serveur factice et, si `OPENBASTION_VNC_TARGET` est posé, contre cette cible, dans le mode où elle a été lancée (`X509Plain` ou `X509Vnc`). Un TigerVNC ne dit pas ce qu'il a reçu : contre lui, le test prouve l'image, la coupure (relais TCP témoin) et le refus d'un mauvais mot de passe ; le clavier est témoigné par le serveur factice seul.

`TestCompose_AVNCSession…` (`test/integration/compose_screen_test.go`, lancé par `make test-compose`, Docker requis) fait le même parcours sur la pile `deploy/docker-compose` avec ses profils `recording` et `rdp-vnc` : vraies images, vrai SeaweedFS. La cible factice reste sur l'hôte, jointe par la passerelle du réseau Compose. Le Video Recorder y utilise une clé locale (override du test), pas Transit, couvert par `transit_flow_test.go`.

Sans `OPENBASTION_VNC_TARGET`, `TestRealTarget` se saute. Il complète les serveurs factices, il ne les remplace pas.
