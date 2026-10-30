---
name: go-reliability-testing
description: Tests Go fiables et probants dans OpenBastion (unitaires, PostgreSQL, processus réels, rouge avant, mutations, -race, comptage) — à utiliser pour écrire, corriger ou évaluer des tests Go.
---

# Tests Go fiables

Règles : `rules/testing.md`. Portes : `settings/quality-gates.yaml`.

## Niveaux

- Unitaire hermétique, à côté du code ; fakes à la main.
- PostgreSQL : se skippe sans `TEST_DATABASE_URL`.
- Intégration : `test/integration/`, binaires compilés (`buildBinary`), services lancés (`startService`, `startServiceWithExtraPort`), espion d'audit (`startAuditSpy`), vrais clients OpenSSH (`openssh`, `opensshIn`) ; un bloc de ports par fichier.

## Prouver

- **Rouge avant** : `git worktree add --detach <dir> <commit précédent>`, le test d'attaque adapté à l'ancienne API, lancé et lu ; `git worktree remove --force`.
- **Mutations** : un fichier JSON de mutations (fichier, ancien texte, nouveau texte, commande), un script qui sauvegarde sous un nom unique, applique, lance, restaure et vérifie avec `cmp` ; une mutation qui ne compile pas se réécrit ; une survivante se corrige.
- **`-race`** sur les modules touchés : un `bytes.Buffer` partagé entre les deux goroutines d'un relais est une race de **test** (déjà rencontrée).

## Pièges

- Un client qui coupe trop tôt (`sftp -b` désactive le mot de passe ; `CombinedOutput` attend une sortie gardée ouverte : `cmd.WaitDelay`).
- Une assertion qui passe pour une autre raison (un `409` qui vient d'un autre refus) : exige le motif.
- Compter : `grep -c '^--- PASS'` sur `go test -v`, avec et sans base.
