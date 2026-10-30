# Arborescence réelle du dépôt

Où se trouve quoi. Quand ce fichier et le dépôt divergent, le dépôt fait foi : corrige ce fichier dans le même commit.

```
go.work                          workspace Go : un module par composant (ADR-0002)
Makefile                         build, vet, test, test-integration, test-postgres, test-compose, pki, run-*
NOTES_SANDBOX.md                 journal des écarts, découvertes, limites, état des tests — à tenir à jour
README.md
AGENTS.md                        point d'entrée des agents IA
.agents/                         instructions des agents, par thème — décrivent le projet tel qu'il est :
  architecture/ personas/ policies/ rules/ settings/ tasks/ skills/<nom>/SKILL.md
pkg/
  proxycore/                     pipeline proxy commun (listener, credential fetcher, tap, terminator) — ADR-0006
  mtls/                          identité par certificat, Guard, rechargement, PKI de dev — ADR-0010
  migrate/                       migrations de schéma versionnées, sous verrou, une fois, checksum figé (six magasins PostgreSQL) — ADR-0030 ; stdlib seulement
  refusalbudget/                 seau à jetons par identité des refus écrits dans l'audit (Broker, Recorder) — ADR-0020, ADR-0024 ; stdlib seulement
    pki/  mtlstest/  cmd/openbastion-pki/
services/
  access/
    api-gateway/                 seul point d'entrée public ; écrase l'identité revendiquée par le client
    authentication/              Argon2id, JWT
    authorization/               RBAC deny-by-default, un deny explicite l'emporte
    session-broker/              orchestrateur ; ne voit jamais un secret
  proxy/ssh-proxy/               premier proxy réel (golang.org/x/crypto/ssh) ; sshcodec/
  vault/password-vault/          comptes, secrets (chiffrés), scopes à usage unique
  recording-audit/
    audit-service/               journal chaîné par hash, signé
    command-recorder/            replay texte, chiffrement enveloppe AES-256-GCM
proto/                           contrats Protobuf (doc 07) — la forme des messages
cli/openbastion-cli/             outil d'exploitation sous l'identité admin-cli : user create, audit verify-chain (ADR-0033) ; stdlib + pkg/mtls
web/admin-ui/                    Admin UI React + TypeScript + Vite, servie par la Gateway sous /ui/ (ADMIN_UI_DIR) ; API publique seulement ; jeton en mémoire — ADR-0036
deploy/docker-compose/           Dockerfile (une image, tous les binaires, distroless non root), docker-compose.yml (mTLS, une base par service, 2 ports sur 127.0.0.1), init.sh (secrets → .env 0600, jamais écrasé), pki.sh, postgres-init.sh — ADR-0033
test/integration/                scénarios sur processus réels (binaires compilés, ports 18xxx) ; compose_test.go sous COMPOSE_TEST=1 ; cmd/demo-ssh-target (cible SSH de démonstration)
docs/
  architecture/                  docs 00–07 numérotés ; les ADR sont consolidés dans le doc 03
  api/                           OpenAPI (doc 05)
  guides/                        administrateur, développeur, sécurité, HA, PRA/PCA, utilisateur
deploy/                          docker-compose, helm, k8s (squelettes)
```

`docs/adr/` est vide : tant que les ADR ne sont pas éclatés en fichiers, **ils vivent dans `docs/architecture/OpenBastion_03_ADR.md`**.
