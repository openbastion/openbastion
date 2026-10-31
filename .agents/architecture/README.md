# architecture — la structure technique d'OpenBastion

Lis ce dossier avant de toucher au code. Quand il diverge du code, **le code fait foi** : corrige le fichier concerné dans le même commit.

## Le produit

OpenBastion est un PAM (Privileged Access Management) open source, cloud-native, en Go, sous licence Apache 2.0, entièrement original. Il centralise les accès privilégiés : l'opérateur n'a **jamais** le mot de passe de la cible, toutes les connexions passent par un proxy, toutes les sessions sont enregistrées, tout est audité.

Ce qui est implémenté aujourd'hui (MVP, un seul protocole : SSH) : Authentication, Authorization (RBAC), Session Broker, Password Vault, SSH Proxy, Audit Service (chaînage de hash), Command Recorder (replay texte chiffré au repos), API Gateway, mTLS interne, Admin UI (React, ADR-0036), connexion fédérée OIDC (ADR-0035), migrations versionnées (ADR-0030), déploiement docker-compose (ADR-0033). Le reste du périmètre (RDP, Workflow/Approval Engine, SDK…) est décrit dans `docs/roadmap.md` et **n'existe pas encore** : ne fais pas comme si.

## Les fichiers de ce dossier

| Fichier | Il te dit |
|---|---|
| [`invariants.md`](invariants.md) | les propriétés que tu ne dois jamais casser, ADR par ADR, et où elles sont tenues |
| [`repository-layout.md`](repository-layout.md) | où se trouve quoi dans le dépôt |
| [`service-pattern.md`](service-pattern.md) | la forme d'un service Go (couches, ports par défaut) |
| [`service-identities.md`](service-identities.md) | qui appelle qui, sous quelle identité mTLS |
| [`transport-and-contracts.md`](transport-and-contracts.md) | HTTP/JSON à la place de gRPC, TLS 1.3 mutuel, contrats additifs |
| [`data.md`](data.md) | PostgreSQL, migrations numérotées, secrets de démarrage |
| [`known-gaps.md`](known-gaps.md) | les écarts assumés entre la cible et le code |

## Où est la vérité

| Question | Fichier |
|---|---|
| Pourquoi cette décision ? | `docs/adr/` |
| Quelle API publique ? | `docs/api/rest/openapi.yaml` |
| Quel message entre services ? | `docs/api/grpc/README.md` + `proto/` |
| Quelle table ? | `docs/architecture/data-architecture.md` |
| Qu'est-ce qui est fait, quelles limites, quels écarts ? | `NOTES_SANDBOX.md` (le plus à jour) |
| Quelle feuille de route ? | `docs/roadmap.md` |
| Comment installer, administrer, sécuriser ? | `docs/deployment/`, `docs/administration/`, `docs/security/` (plan : `docs/README.md`) |
