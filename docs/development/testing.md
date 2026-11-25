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

## Workflow N+1 réel (ADR-0138)

`TestADR0138WorkflowApproval_MTLSPostgres` (`test/integration/adr0138_workflow_approval_mtls_postgres_test.go`) lance Authentication, Authorization, Vault, Workflow Service, Session Broker, Audit Service et API Gateway comme processus indépendants. Les appels inter-services utilisent la PKI de test et mTLS ; Workflow, Broker et Audit ont chacun une base PostgreSQL isolée. Si Chromium est disponible (`CHROME` ou `google-chrome`/`chromium` dans `PATH`) et si `web/admin-ui/dist` existe, le test pilote également le véritable Admin UI via Chrome DevTools Protocol : affectation du supérieur, lecture de la file, confirmation de l'approbation. Sans navigateur ou build UI, le parcours API/PostgreSQL/mTLS reste exécuté et la partie navigateur est sautée.

Préparer trois bases dédiées (ne pas réutiliser la base partagée `TEST_DATABASE_URL`, les services possèdent chacun leur historique de migrations) puis lancer :

```sh
export ADR0138_WORKFLOW_DATABASE_URL='postgres://USER:PASS@127.0.0.1:5432/adr0138_workflow_e2e?sslmode=disable'
export ADR0138_BROKER_DATABASE_URL='postgres://USER:PASS@127.0.0.1:5432/adr0138_broker_e2e?sslmode=disable'
export ADR0138_AUDIT_DATABASE_URL='postgres://USER:PASS@127.0.0.1:5432/adr0138_audit_e2e?sslmode=disable'
make ui-build
CHROME=/path/to/chrome go test ./test/integration -run TestADR0138WorkflowApproval_MTLSPostgres -count=1 -v
```

Le test vérifie aussi le snapshot immuable de l'approbateur après changement de hiérarchie, le refus d'une décision par le demandeur ou le nouveau supérieur, l'achèvement de l'outbox durable, les événements Workflow signés et la vérification de la chaîne d'audit. Le job PostgreSQL CI crée ces trois bases éphémères avant la suite d'intégration.

## Cible VNC réelle (ADR-0071)

Les refus de `pkg/vnc` se prouvent contre le serveur factice de ses tests ; l'interopérabilité, contre un vrai serveur. `test/integration/testdata/vnc/target.sh` démarre un TigerVNC réel sans Docker et sans rien installer (paquets Debian/Ubuntu dépaquetés dans un répertoire de travail, espace de noms utilisateur non privilégié) :

```sh
test/integration/testdata/vnc/target.sh /tmp/vnc-target X509Plain &   # ou X509Vnc
eval "$(test/integration/testdata/vnc/target.sh /tmp/vnc-target --env)"
go test ./pkg/vnc/ -run TestRealTarget -count=1 -v
```

`TestScreenFlow_VNC…` (`test/integration/screen_flow_test.go`, `TEST_DATABASE_URL` requis) rejoue le parcours sur processus réels, contre un serveur factice et, si `OPENBASTION_VNC_TARGET` est posé, contre TigerVNC (`X509Plain` ou `X509Vnc`). L'observateur X11 indépendant `xev` lit les véritables `KeyPress` reçus par le serveur, sans se fier aux télémétries du proxy. Le job PostgreSQL CI utilise un mot de passe PAM aléatoire court (128 caractères hexadécimaux) ; le relais SI-02 limite les lectures à 64 octets et retient le flux restant après les premières frappes observées.

Le sous-test SI-02 ajoute un relais TCP de test qui transmet des tranches de 64 octets jusqu'à ce que `xev` observe les premières frappes, retient les octets TLS restants, puis attend la fermeture du flux par le proxy. Il vérifie que la cible a reçu un préfixe réel, que le Broker acquitte la révocation après fermeture du relais et qu'aucun nouvel événement X11 n'arrive pendant la fenêtre d'observation post-acquittement. Les octets retenus par le relais sont chiffrés ; le test ne déchiffre ni n'enregistre le secret.

`TestCompose_AVNCSession…` (`test/integration/compose_screen_test.go`, lancé par `make test-compose`, Docker requis) fait le même parcours sur la pile `deploy/docker-compose` avec ses profils `recording` et `rdp-vnc` : vraies images, vrai SeaweedFS. La cible factice reste sur l'hôte, jointe par la passerelle du réseau Compose. Le Video Recorder y utilise une clé locale (override du test), pas Transit, couvert par `transit_flow_test.go`.

Sans `OPENBASTION_VNC_TARGET`, `TestRealTarget` se saute. Il complète les serveurs factices, il ne les remplace pas.
