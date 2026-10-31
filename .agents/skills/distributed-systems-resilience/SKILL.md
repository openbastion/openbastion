---
name: distributed-systems-resilience
description: Résilience des services distribués d'OpenBastion (fail-closed, dépendances en panne, réplicas, boucles de fond, révocation, reprise) — à utiliser pour toute interaction entre services, tout balayage ou tout comportement sous panne.
---

# Résilience des systèmes distribués

## Principes du projet

- **Fail-closed** pour la sécurité : Authorization, Audit ou Recorder en panne ⇒ refus, jamais acceptation. La disponibilité cède devant la sécurité (`docs/deployment/high-availability.md`).
- **Idempotence et comparer-échanger** : rejouer un appel ne double rien (`SaveIfStatus`, version en attente unique, `ExpireDue`).
- **Réplicas** : ce qui doit être unique est tenu par la base (verrous, `SKIP LOCKED`, index uniques), jamais par la mémoire d'un processus — sauf ce qui est écrit comme instance unique (Audit Service, `architecture/known-gaps.md`) ; le proxy SSH tient ses tickets en mémoire, et c'est le Broker qui fait révoquer chez toutes ses instances (ADR-0046).
- **Boucles de fond** : intervalle borné, délai par passage, reprise au passage suivant après un échec, sans tempête ; ce qui n'a pas pu être écrit à l'audit attend et s'écrit plus tard, dans l'ordre (ADR-0034).
- **Coupure** : terminer une session coupe la connexion avant de changer l'état (ADR-0018) ; une poignée de main se coupe aussi (`context.AfterFunc`).

## Vérifie

1. Pour chaque dépendance : ce qui se passe quand elle est lente, en panne, ou répond deux fois.
2. Ce que l'opérateur lit, et ce que l'audit garde.
3. Le test de la panne, sur processus réels si le comportement traverse des services.
4. La mise à jour de `docs/deployment/high-availability.md` et de `docs/deployment/disaster-recovery.md`.
