# OpenBastion — Guide Utilisateur

**Version** 0.1 · **Statut** Draft de travail
**Public visé** L'opérateur qui demande et utilise une session privilégiée au quotidien — aucune connaissance d'administration ou d'architecture requise pour ce guide.
**Document précédent** `OpenBastion_Doc_Administrateur.md`

---

## 1. Ce que fait OpenBastion pour vous

Vous avez besoin d'un accès administrateur à un serveur, le temps d'une tâche. OpenBastion vous ouvre cet accès **sans jamais vous montrer le mot de passe du compte cible** — ce n'est pas une limitation technique temporaire, c'est le principe même du système : personne, pas même un administrateur OpenBastion, ne voit ce mot de passe. Tout ce que vous faites pendant la session est enregistré et horodaté.

## 2. Se connecter

Vous vous connectez avec les identifiants habituels de votre organisation (single sign-on) — OpenBastion ne vous demande pas de créer un mot de passe séparé.

*Limite connue du périmètre actuel* : il n'existe pas encore de portail web dédié aux opérateurs (prévu en v1.0). En attendant, vous demandez vos sessions via la ligne de commande (§3) ou l'interface qui vous a été fournie par votre administrateur.

## 3. Demander une session

```sh
openbastion session request \
  --account prod-db-01-root \
  --protocol ssh \
  --justification "Investigation incident INC-4821" \
  --duration 60
```

- `--account` est le nom du compte cible, communiqué par votre administrateur (vous ne choisissez pas un serveur au hasard — seuls les comptes pour lesquels vous avez un droit vous seront acceptés).
- `--justification` est obligatoire et doit être utile à la relecture — « accès » n'aide personne, « Investigation incident INC-4821 » si.
- `--duration` est en minutes ; demandez ce dont vous avez réellement besoin, pas une marge large « au cas où ».

Dans le périmètre actuel, l'accès est accordé immédiatement si vous en avez le droit — il n'y a pas encore d'étape de validation par un tiers (elle arrive en v1.0 pour les accès les plus sensibles).

## 4. Se connecter à la session

```sh
openbastion session connect <session-id>
```

Cette commande ouvre votre connexion SSH normalement — vous retrouvez votre terminal habituel. Le mot de passe ou la clé du compte cible a été injecté automatiquement par OpenBastion ; vous n'avez rien à saisir pour ça.

## 5. Pendant la session

- Chaque commande que vous tapez est enregistrée avec son horodatage.
- La session s'arrête automatiquement à l'expiration que vous avez demandée (§3).
- Rien de tout cela n'est caché ni annoncé en cours de session — c'est le comportement normal du système, cohérent du premier au dernier jour d'utilisation.

## 6. Terminer une session

Si vous avez fini avant l'expiration prévue, terminez-la plutôt que d'attendre :

```sh
openbastion session terminate <session-id>
```

Une session ouverte plus longtemps que nécessaire n'apporte rien et complique la relecture d'audit pour votre équipe sécurité.

## 7. Consulter votre historique

```sh
openbastion session list --mine
```

Affiche vos sessions passées et actives, leur statut et leur justification — utile pour retrouver une session lors d'un audit ou d'une revue d'incident.

## 8. Questions fréquentes

**Ma demande a été refusée, pourquoi ?**
Vous n'avez probablement pas de politique vous donnant droit à ce compte précis. Contactez votre administrateur — ce n'est pas quelque chose que vous pouvez contourner ou forcer depuis votre côté, par conception.

**Puis-je voir le mot de passe du compte cible ?**
Non, jamais, pour personne — pas même pour un administrateur. C'est le principe fondateur du système (Zero Standing Privilege), pas un bug ni une restriction qu'on pourrait lever sur demande.

**Ma session a expiré en plein milieu de mon travail, que faire ?**
Redemandez une session (§3). C'est volontaire : une session à durée illimitée serait un accès permanent déguisé, exactement ce qu'OpenBastion existe pour éviter.

**Est-ce que quelqu'un me surveille en temps réel ?**
Votre session est enregistrée pour être rejouable en cas de besoin (audit, incident), pas nécessairement regardée en direct. Les modalités précises de revue relèvent de la politique de votre organisation, pas d'OpenBastion lui-même.

## 9. Bonnes pratiques

- Une justification claire vous protège autant qu'elle protège l'organisation en cas de question ultérieure.
- Demandez la durée dont vous avez besoin, pas plus.
- Terminez une session dès que le travail est fait.

---
*Ce document clôt la documentation initialement demandée : architecture, ADR, C4, arborescence, feuille de route, OpenAPI, modèle de données, interfaces inter-services, guides sécurité/HA/PRA-PCA, et documentation développeur/administrateur/utilisateur.*
