---
name: ui-ux-design-system
description: Système visuel et règles d'ergonomie de l'Admin UI d'OpenBastion — à utiliser pour concevoir ou modifier un écran, un tableau, un formulaire ou un message de l'interface d'administration.
---

# Design system et ergonomie (Admin UI)

Les compétences génériques de mise en forme (`better-ui`, `better-layout`, `better-colors`, `better-typography`, `better-accessibility`, `better-writing`) s'appliquent ; ce fichier dit ce qui est propre à OpenBastion.

## Système

- Tokens CSS canoniques dans `web/packages/design-tokens/tokens.css` (`--ob-color-*`, thèmes clair/sombre, typographie, espacements, rayons et mouvement). `web/packages/ui/styles.css` porte les primitives visuelles génériques ; `web/admin-ui/src/app/styles.css` ne contient que les styles applicatifs et des alias de compatibilité ; aucune couleur codée en dur dans un composant.
- Composants de base : `.card`, `.page`, `.page-head` + `.hint`, `table` dans `.table-wrap`, `.badge` (et `.badge.warn` pour un état qui bloque l'usage), `.fields` (grille de formulaire, `.wide` pour une ligne entière), `.form-actions`, `button.primary`, `button.danger`.
- Messages : `Notice` (succès en `role="status"`, erreur en `role="alert"` avec le code et le motif de l'API).
- Icônes : utiliser les composants React officiels exportés par `@openbastion/icons` (package source : `web/openbastion-icons`) lorsqu'un pictogramme correspondant existe ; ne pas redessiner ces icônes ni introduire un autre jeu d'icônes. Importer uniquement les composants nécessaires par leur nom. Avant de les importer dans l'Admin UI, vérifier que le package est déclaré comme dépendance et que son lockfile est à jour ; importer `@openbastion/icons/styles.css` une seule fois au point d'entrée.
- Icônes et accessibilité : utiliser `size` pour les dimensions et laisser la couleur principale hériter de `currentColor` ; réserver `ariaLabel` aux icônes autonomes qui portent une information. Une icône décorative reste sans libellé (elle est masquée aux technologies d'assistance par défaut) ; un bouton icon-only porte son nom accessible sur le bouton.

## Ergonomie propre à un PAM

- Un geste qui change qui reçoit un secret (épingler une clé d'hôte, renouveler un secret, désactiver un compte) dit ce qu'il engage **avant** d'agir.
- Un état qui empêche l'usage (« non épinglée ») se voit dans la liste, pas seulement dans un détail.
- Un secret saisi n'est jamais réaffiché ; le formulaire se vide après envoi.
- Libellés en français, phrases courtes, sans jargon interne ; le motif d'un refus de l'API reste visible tel quel.
