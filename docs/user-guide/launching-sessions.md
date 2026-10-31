# Ouvrir, utiliser et terminer une session

## Se connecter à la session

```sh
openbastion session connect <session-id>
```

Cette commande ouvre votre connexion SSH normalement — vous retrouvez votre terminal habituel. Le mot de passe ou la clé du compte cible a été injecté automatiquement par OpenBastion ; vous n'avez rien à saisir pour ça.

## Pendant la session

- Chaque commande que vous tapez est enregistrée avec son horodatage.
- La session s'arrête automatiquement à l'expiration que vous avez demandée ([Demander une session](requesting-access.md)).
- Rien de tout cela n'est caché ni annoncé en cours de session — c'est le comportement normal du système, cohérent du premier au dernier jour d'utilisation.

## Terminer une session

Si vous avez fini avant l'expiration prévue, terminez-la plutôt que d'attendre :

```sh
openbastion session terminate <session-id>
```

Une session ouverte plus longtemps que nécessaire n'apporte rien et complique la relecture d'audit pour votre équipe sécurité.

**Qui peut terminer une session ?** Vous, pour **vos** sessions, sans rien demander à personne. Les sessions des autres, seulement si votre organisation vous en a donné le pouvoir pour ce compte (une politique « terminer », distincte de celle qui permet d'approuver une urgence). Sans ce pouvoir, la commande répond « refusé » et le refus est enregistré à votre nom. Terminer une session **la coupe sur le champ** (ADR-0018) : la connexion ouverte se ferme avec le message « session ended because it was terminated. » (sans dire qui l'a décidé), et la session ne peut plus être utilisée. Si le message de la commande est « 503 … la session n'a pas été terminée », la session **reste ouverte** : réessayez dans un moment, la commande est sans danger à répéter ; si l'urgence ne peut pas attendre, prévenez l'administrateur.

**Qui peut lire une session ?** Vous, pour **vos** sessions (celles que vous avez demandées), sans rien demander à personne. Une demande d'urgence que **vous** avez approuvée ou rejetée, vous pouvez la relire. Les sessions des autres, seulement si votre organisation vous a donné le pouvoir de les lire pour ce compte (une politique « lire », distincte de celles qui permettent d'approuver une urgence ou de terminer une session). Sans ce pouvoir, la lecture répond « refusé » et ne vous dit **rien** de la session — ni son demandeur, ni son compte, ni sa justification : être approbateur ne suffit pas, vous voyez les demandes que vous pouvez décider dans la liste des demandes en attente. **Ce refus est noté dans l'audit, à votre nom** (pas à celui du demandeur de la session) : essayer de lire une session qu'on ne peut pas lire laisse une trace, et votre équipe sécurité peut la relire. **Quand vous lisez une session qui n'est pas la vôtre grâce à ce pouvoir, cette lecture est notée elle aussi, à votre nom, avant de vous être servie** : si le journal d'audit est indisponible, la lecture vous répond « service indisponible » plutôt que de vous la servir sans trace — réessayez dans un instant. Lire **vos** sessions, ou celle que vous avez décidée, n'est pas noté et ne dépend pas de l'audit. Si la réponse est « service indisponible », réessayez dans un instant : ce n'est pas que la session n'existe pas. Lire une session ne montre pas ce qui s'y est tapé ; cela relève du rôle d'audit.
