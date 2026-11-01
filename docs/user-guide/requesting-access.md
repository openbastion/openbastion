# Demander une session

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

Dans le périmètre actuel, l'accès est accordé immédiatement si vous en avez le droit — il n'y a pas d'étape de validation par un tiers pour un accès ordinaire (elle arrive en v0.0.1 avec le moteur de workflow). **Une exception : l'accès d'urgence « break-glass »**, qui attend l'accord d'une autre personne (voir la FAQ §8).
