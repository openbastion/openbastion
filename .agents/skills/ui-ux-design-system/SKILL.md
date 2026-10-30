---
name: ui-ux-design-system
description: Système visuel et règles d'ergonomie de l'Admin UI d'OpenBastion — à utiliser pour concevoir ou modifier un écran, un tableau, un formulaire ou un message de l'interface d'administration.
---

# Design system et ergonomie (Admin UI)

Les compétences génériques de mise en forme (`better-ui`, `better-layout`, `better-colors`, `better-typography`, `better-accessibility`, `better-writing`) s'appliquent ; ce fichier dit ce qui est propre à OpenBastion.

## Système

- Variables CSS dans `web/admin-ui/src/app/styles.css` (`--brand`, `--ink-*`, `--surface*`, `--line*`, `--danger*`, `--radius-*`) ; aucune couleur codée en dur dans un composant.
- Composants de base : `.card`, `.page`, `.page-head` + `.hint`, `table` dans `.table-wrap`, `.badge` (et `.badge.warn` pour un état qui bloque l'usage), `.fields` (grille de formulaire, `.wide` pour une ligne entière), `.form-actions`, `button.primary`, `button.danger`.
- Messages : `Notice` (succès en `role="status"`, erreur en `role="alert"` avec le code et le motif de l'API).

## Ergonomie propre à un PAM

- Un geste qui change qui reçoit un secret (épingler une clé d'hôte, renouveler un secret, désactiver un compte) dit ce qu'il engage **avant** d'agir.
- Un état qui empêche l'usage (« non épinglée ») se voit dans la liste, pas seulement dans un détail.
- Un secret saisi n'est jamais réaffiché ; le formulaire se vide après envoi.
- Libellés en français, phrases courtes, sans jargon interne ; le motif d'un refus de l'API reste visible tel quel.
