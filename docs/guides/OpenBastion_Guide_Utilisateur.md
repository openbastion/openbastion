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

Dans le périmètre actuel, l'accès est accordé immédiatement si vous en avez le droit — il n'y a pas d'étape de validation par un tiers pour un accès ordinaire (elle arrive en v1.0 avec le moteur de workflow). **Une exception : l'accès d'urgence « break-glass »**, qui attend l'accord d'une autre personne (voir la FAQ §8).

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

**La connexion est refusée avec « recording unavailable », que faire ?**
Le système d'enregistrement des sessions est momentanément indisponible, et OpenBastion refuse par principe une session qu'il ne pourrait pas enregistrer. Rien n'a été consommé : renouvelez votre demande dans quelques instants. Si c'est une urgence d'incident qui ne peut pas attendre, demandez à votre administrateur si un accès d'urgence (« break-glass ») est prévu pour votre rôle sur ce compte : il est désactivé par défaut, exige une justification précise, **l'accord d'une seconde personne** (vous ne pouvez pas approuver votre propre demande, et vous seul pouvez ensuite ouvrir la connexion), dure peu de temps — la durée compte à partir de l'accord —, et laisse une trace d'audit qui sera relue après coup. Sans réponse dans le délai (15 minutes par défaut), la demande expire : il faudra la refaire. Une session d'urgence est enregistrée au mieux, pas garantie.

**Je dois approuver une demande d'accès d'urgence : où la trouver ?**
Si l'administrateur a configuré un canal d'alerte, il vous a prévenu (le message nomme le compte, le demandeur et l'échéance, pas la justification). Dans tous les cas, la liste de ce que vous pouvez décider est `GET /sessions?status=pending_approval` : vous n'y voyez que les demandes que **vous** avez le droit d'approuver, jamais les vôtres, avec la justification. Une liste vide veut dire que rien ne vous attend — ou que vous n'avez pas ce droit ; si vous attendez une demande, vérifiez avec votre administrateur que votre rôle a l'autorité d'approuver ce compte. Une erreur 503 ne veut pas dire « rien à décider » : réessayez. Approuvez ou rejetez avec `POST /sessions/<id>/approve` ou `/reject`.

**Ma demande d'accès d'urgence est refusée avec « too many break-glass requests are waiting for a decision » (429) : pourquoi ?**
Vous avez déjà plusieurs demandes d'urgence en attente d'une décision — trois par défaut, votre administrateur peut avoir changé ce nombre (le message le dit). C'est une protection : personne ne peut noyer la liste de ses approbateurs, et le plafond est **le vôtre** — il n'empêche personne d'autre de demander. Une place se libère dès qu'une de vos demandes est approuvée, rejetée ou expirée (15 minutes par défaut) ; si l'une d'elles est devenue inutile, demandez à votre approbateur de la rejeter plutôt que d'attendre. La tentative refusée est tracée dans l'audit, comme toute demande.

**Ma session s'est coupée à l'heure indiquée, même en pleine commande ?**
Oui : OpenBastion coupe toute session à son échéance, sans attendre. Redemandez-en une si le travail n'est pas fini (§3).

**Est-ce que quelqu'un me surveille en temps réel ?**
Votre session est enregistrée pour être rejouable en cas de besoin (audit, incident), pas nécessairement regardée en direct. Les modalités précises de revue relèvent de la politique de votre organisation, pas d'OpenBastion lui-même.

## 9. Bonnes pratiques

- Une justification claire vous protège autant qu'elle protège l'organisation en cas de question ultérieure.
- Demandez la durée dont vous avez besoin, pas plus.
- Terminez une session dès que le travail est fait.

---
*Ce document clôt la documentation initialement demandée : architecture, ADR, C4, arborescence, feuille de route, OpenAPI, modèle de données, interfaces inter-services, guides sécurité/HA/PRA-PCA, et documentation développeur/administrateur/utilisateur.*
