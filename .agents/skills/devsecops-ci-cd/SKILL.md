---
name: devsecops-ci-cd
description: Construction, dépendances, PKI de développement, déploiement docker-compose et portes de qualité d'OpenBastion — à utiliser pour le Makefile, go.mod/go.sum, package-lock.json, deploy/, la PKI ou un futur pipeline de CI.
---

# DevSecOps, CI/CD

Réglages : `settings/ci-cd.yaml`, `settings/quality-gates.yaml`, `settings/environments/`. Policies : `policies/dependencies-and-supply-chain.md`, `policies/secrets-management.md`.

## État réel

- **Pas de CI** dans le dépôt : les portes se lancent à la main (`tasks/releases/full-verification.md`). Une CI à créer reprend `settings/ci-cd.yaml`.
- Déploiement de référence : `deploy/docker-compose` (ADR-0033) — une image distroless non root, mTLS obligatoire, une base par service, ports sur `127.0.0.1`, secrets tirés par `init.sh`. Prévisualisation : `deploy/base44` (le dépôt tel quel, valeurs de développement).
- PKI : `make pki` (`.pki/`, jamais commitée) ; en Compose, le job `pki` garde l'autorité dans son propre volume.

## Gestes

- Une variable ajoutée à un service : dans les deux fichiers compose si elle y est nécessaire, et dans le guide Administrateur.
- Le test Compose : `tasks/devsecops/compose-test.md` (règle de pare-feu temporaire, posée puis retirée dans la même commande).
- Aucune valeur de `deploy/base44` ne devient un défaut ailleurs.
