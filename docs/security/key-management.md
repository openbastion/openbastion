# Gestion des clés de chiffrement

Le Password Vault scelle chaque secret, et le Command Recorder protège chaque enregistrement, sous une clé maîtresse. Cette clé peut être tenue de deux façons (ADR-0049) :

| | Clé locale (`KMS_KEY_HEX`) | Transit (OpenBao ou HashiCorp Vault) |
|---|---|---|
| Où est la clé | Dans la mémoire du processus, venue d'une variable d'environnement | Dans le serveur Transit ; elle n'en sort jamais |
| Ce que le service envoie | Rien | Une clé de données de 32 octets à envelopper ou désenvelopper, liée à des données associées ; jamais un secret ni une commande |
| Qui lit tout avec la base | Qui lit la variable (environnement, disque, sauvegarde de la configuration) | Qui tient le jeton **pendant qu'il est valable**, et peut joindre Transit |
| Révoquer | Impossible : la clé se copie | Révoquer le jeton ; chaque usage est dans l'audit d'OpenBao |
| Rotation de la clé maîtresse | Non | `bao write -f transit/keys/<clé>/rotate` : rien de ce qui existe n'est invalidé |
| Disponibilité | Celle du service | Transit devient une dépendance de tier 0 : sans lui, aucun secret n'est livré ni aucun enregistrement écrit |

## Mettre Transit en place

Sur OpenBao (les mêmes commandes avec `vault` pour HashiCorp Vault), une clé et un jeton **par service** :

```sh
bao secrets enable transit
bao write -f transit/keys/openbastion-vault type=aes256-gcm96
bao policy write openbastion-vault - <<'EOF'
path "transit/encrypt/openbastion-vault" { capabilities = ["update"] }
path "transit/decrypt/openbastion-vault" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
EOF
bao token create -policy=openbastion-vault -no-default-policy -period=24h -field=token > vault-transit.token
chmod 600 vault-transit.token
```

Faites de même pour le Command Recorder avec sa propre clé (`openbastion-recorder`) et son propre jeton. **Créez la clé avant** : avec un jeton plus large que cette politique, Transit crée une clé inconnue au premier chiffrement, au lieu de refuser.

Puis, pour chaque service :

| Variable | Rôle |
|---|---|
| `TRANSIT_ADDR` | `https://openbao.example:8200` ; `http` seulement vers une adresse de bouclage (développement). Ni identifiants, ni chemin. |
| `TRANSIT_KEY` | Le nom de la clé (`openbastion-vault`, `openbastion-recorder`). |
| `TRANSIT_TOKEN_FILE` | Le fichier du jeton, lisible par son seul propriétaire (`0600` ou `0400`) : un fichier lisible par le groupe ou les autres est refusé. Le jeton n'est jamais pris dans une variable d'environnement, ni écrit dans un journal. |
| `TRANSIT_MOUNT` | Le montage, `transit` par défaut. |
| `TRANSIT_CA_FILE` | Facultatif : l'autorité qui signe le certificat du serveur Transit. |

Les trois premières vont ensemble. Au démarrage, le service enveloppe puis désenveloppe une valeur d'essai : une adresse injoignable, un jeton refusé, une clé absente ou interdite au jeton, et le service **refuse de démarrer**, en disant pourquoi sans répéter le jeton. Il annonce ensuite la clé utilisée (`transit:<montage>/<clé>`) et l'hôte, jamais le jeton.

**Le jeton se renouvelle de lui-même** (ADR-0053) : le service lit sa durée de vie au démarrage et le renouvelle à mi-vie, puis à mi-vie de chaque nouvelle durée ; un échec est retenté au quart du temps restant (au moins toutes les 5 s) et écrit au journal. Il lui faut les deux derniers chemins de la politique ci-dessus. Un jeton sans fin (racine) ou non renouvelable n'est pas renouvelé, et le démarrage le dit. Un jeton qui a atteint sa durée maximale (`explicit_max_ttl`), ou révoqué, ne se renouvelle plus : remplacez-le dans le fichier et redémarrez le service — le fichier n'est pas relu à chaud, et il n'y a pas encore d'AppRole.

## Passer de la clé locale à Transit

Rien de ce qui a été chiffré avant ne devient illisible, à condition de garder la clé locale le temps qu'il faut :

1. Configurez Transit **et gardez `KMS_KEY_HEX`**. Les nouveaux secrets et les nouveaux enregistrements vont à Transit ; ceux d'avant se lisent avec la clé locale, qui ne scelle plus rien. Le démarrage le dit (« still read (KMS_KEY_HEX); nothing new is sealed under it »).
2. Chaque ligne nomme la clé qui l'a protégée (`vault_secrets.encryption_key_id`, `session_recording_keys.kek_id`) : `local-dev-key-v1` et `local-recorder-kek-v1` pour la clé locale.
3. Retirez `KMS_KEY_HEX` seulement quand plus aucune ligne utile ne la nomme. Une ligne qui nomme une clé que le service ne tient plus est refusée (`503` à qui la demande, la cause au journal du service) ; elle redevient lisible dès qu'on redonne la clé.

Il n'y a pas de ré-enveloppement en masse : une rotation d'un secret le scelle à nouveau sous Transit ; un enregistrement reste sous la clé qui l'a protégé.

## Quand Transit ne répond pas

Rien n'est scellé ni ouvert sous Transit : `fetch-credential` et l'enregistrement d'un compte répondent `503`, une session ne s'ouvre pas, une commande ne s'enregistre pas — et, comme le Command Recorder est une dépendance de toute session (ADR-0008), aucune session ne s'ouvre. Ce qui a été scellé sous une clé locale encore tenue reste lisible. Revenu, tout reprend sans redémarrage.
