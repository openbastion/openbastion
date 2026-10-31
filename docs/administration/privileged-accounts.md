# Gestion des comptes privilégiés (Vault)

Onboarder un compte SSH cible :

```sh
curl -X POST https://bastion.example.com/api/v1/vault/accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-db-01-root",
    "targetHost": "10.0.4.12:22",
    "protocol": "ssh",
    "rotationPolicy": "post_use",
    "hostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…"
  }'
```

**La clé d'hôte de la cible est obligatoire (ADR-0039).** C'est la seule chose qui empêche une machine placée à l'adresse de la cible (ARP, DNS, route, machine arrêtée remplacée) de recevoir le mot de passe : le proxy et la rotation n'envoient le secret qu'au serveur qui présente **exactement** cette clé.

- **Relevez-la sur la cible elle-même** (console, outil de gestion de configuration, image qui l'a générée), pas par le réseau que l'épinglage doit protéger. Exemple sur la cible : `cat /etc/ssh/ssh_host_ed25519_key.pub`, et vérifiez son empreinte avec `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Une ligne de `known_hosts` est acceptée aussi : les noms d'hôtes sont retirés.
- `ssh-keyscan` depuis le bastion donne la clé que **le réseau** présente : c'est acceptable seulement si vous en comparez l'empreinte à celle relevée sur la cible.
- Le bastion négocie le type de clé épinglé : si la cible a plusieurs clés (`ed25519`, `ecdsa`, `rsa`), épinglez-en une, de préférence `ed25519`.
- `GET /vault/accounts/{id}` rend la clé et son empreinte (`hostKeyFingerprint`) ; l'Admin UI les affiche dans la liste des comptes.

**Ou une autorité de certificats SSH (ADR-0048).** Si votre organisation signe les clés d'hôte de ses serveurs (`ssh-keygen -s ca_hôtes -h -I cible -n cible.example -V +4w ssh_host_ed25519_key.pub`, puis `HostCertificate` dans `sshd_config`), un compte peut reconnaître sa cible par cette autorité plutôt que par sa clé : `hostKey` reçoit alors une ligne `@cert-authority <nom> <clé publique de l'autorité>`, par exemple `@cert-authority cible.example ssh-ed25519 AAAA…`. Une cible réinstallée et re-certifiée garde ses sessions, sans ré-épinglage.

- **Un compte a une clé ou une autorité, jamais les deux.** Passer de l'une à l'autre est un ré-épinglage (`PUT …/host-key`), réservé aux administrateurs du compte et audité.
- **Le nom** est celui que le certificat doit porter (`-n` de `ssh-keygen`) : un seul nom d'hôte ou une seule adresse, sans `*`, `?`, `!`, liste ni port. Ce n'est pas l'adresse de connexion : une cible jointe par `10.0.0.9:22` peut être certifiée `cible.example`.
- **Refusés** : un certificat d'utilisateur, d'une autre autorité, sans ce nom, avec une liste de noms vide (« tout hôte » pour OpenSSH), expiré ou pas encore valable, **sans date de fin**, ou avec une option critique ; une clé nue. Rien n'est envoyé, et l'audit écrit `session.host_key_mismatch`.
- **L'empreinte rendue** (`hostKeyFingerprint`) est celle **de l'autorité**.
- **Révoquer une clé d'hôte certifiée** (ADR-0054) : si la clé privée d'hôte d'une cible a pu être volée, ajoutez sous la ligne d'autorité une ligne `@revoked * <clé publique d'hôte>` (ou `@revoked <nom du compte> …`), par le même `PUT …/host-key`. Cette clé est refusée même avec un certificat valable ; les autres continuent de passer. Jusqu'à 64 lignes par compte ; révoquer l'autorité elle-même est refusé (ré-épinglez une autre autorité). Exemple :
  ```
  @cert-authority cible.example ssh-ed25519 AAAA…autorité
  @revoked * ssh-ed25519 AAAA…clé-volée
  ```
- **Ce que vous acceptez** : qui détient la clé privée de l'autorité peut se faire passer pour toutes les cibles qui lui font confiance. La révocation porte sur une clé d'hôte, compte par compte, pas sur un numéro de série de certificat. Préférez des certificats de courte durée, et une autorité réservée aux hôtes.

**Changer la clé** (réinstallation de la cible, rotation de ses clés d'hôte) — l'ancienne refuse les sessions jusque-là :

```sh
curl -X PUT https://bastion.example.com/api/v1/vault/accounts/{accountId}/host-key \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"hostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…"}'
# -> {"hostKeyFingerprint":"SHA256:…"}
```

Réservé aux administrateurs du compte, et écrit dans l'audit avant d'avoir lieu (`vault.host_key_set`, sous votre nom) ; le journal du Vault garde l'ancienne et la nouvelle empreinte. **Celui qui change une clé décide du serveur qui reçoit le secret** : une demande de changement non prévue est un incident, pas un ticket.

**Mise à jour vers ADR-0039** : les comptes enregistrés avant n'ont pas de clé. La migration `003_host_key.sql` les laisse vides, et ils n'ouvrent **aucune session** et ne sont **pas renouvelés** tant que vous ne les avez pas épinglés (`PUT …/host-key` ci-dessus, ou le bouton « Épingler la clé d'hôte » de l'Admin UI, qui les marque « non épinglée »). Épinglez-les avant la mise à jour si les sessions ne doivent pas s'interrompre.

`rotationPolicy` accepte `manual`, `post_use` ou `scheduled` (`docs/architecture/data-architecture.md` §3). ~~**Attention — limite constatée le 30 octobre 2026** : aujourd'hui, une rotation ne change le secret que dans le Vault, pas sur la cible…~~ **Refermé par ADR-0037** : une rotation **change le mot de passe sur la cible**, par le **compte de réconciliation** du compte (`reconciliationAccountId` à l'enregistrement : un autre compte du Vault, **de la même cible**, `root` ou autorisé à `sudo chpasswd`). Le Vault pose le nouveau secret par SSH, **se connecte avec lui**, et seulement alors le rend courant ; la cible refuse : rien ne change. Un compte **sans** compte de réconciliation ne peut pas être renouvelé (`409`). `post_use` : le secret est renouvelé quand une session accordée se termine (terminaison ou expiration). ~~`scheduled` : enregistré, **exécuté par rien** (pas de Scheduler de rotation).~~ **Refermé par ADR-0040** : `scheduled` demande `rotationIntervalDays` (1 à 365) et un compte de réconciliation ; le Vault balaie toutes les `ROTATION_SWEEP_SECONDS` (300 par défaut, 1 à 86 400) et fait tourner chaque compte échu — son intervalle après sa dernière rotation, ou sa création —, au plus 20 par passage, comme une action du système dans l'audit (acteur vide). Plusieurs Vaults sur la même base : un seul prend un compte donné. Un échec est retenté une heure plus tard ; la réponse du compte donne `nextRotationAt`. À la mise à jour, les comptes `scheduled` existants reçoivent 30 jours et tournent au premier passage s'ils sont plus anciens. Le Vault ouvre des connexions SSH vers les cibles (à autoriser au pare-feu) et **ne vérifie pas leur clé d'hôte** (comme le proxy). Une rotation manuelle se déclenche via :

```sh
curl -X POST https://bastion.example.com/api/v1/vault/accounts/{accountId}/rotate \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Rappel** : l'API ne renvoie jamais le secret lui-même, à aucun moment, pour aucun rôle — cohérent avec ADR-0003. Un administrateur configure des comptes, il n'en consulte jamais les mots de passe.

## Transferts de fichiers : SFTP et SCP (ADR-0038)

Le proxy accepte, à côté du shell, le sous-système **SFTP** (et donc `scp` d'OpenSSH ≥ 9, qui passe par SFTP) et l'**ancien protocole SCP** (`scp -O`). Le ticket de connexion sert de mot de passe, comme pour le shell :

```sh
sftp -P 2222 operator@bastion        # puis le ticket
scp -P 2222 rapport.pdf operator@bastion:/srv/depot/
```

**Chaque transfert est enregistré avant d'être transmis**, dans l'enregistrement de la session (le même que les commandes, relu par `GET /sessions/{id}/recording`) : l'ouverture d'un fichier (`sftp open "…" for writing`), chaque modification (`remove`, `rename`, `mkdir`, `rmdir`, `setstat`, `symlink`, `hardlink`, requêtes étendues), et à la fermeture le sens, la taille et le **SHA-256** du contenu (`sftp upload "…" (n bytes, sha256 …)`). Le **contenu n'est pas gardé**. Si le Command Recorder n'acquitte pas, le paquet n'est pas transmis et la session s'arrête. Toute autre commande (`ssh bastion id`, `rsync`…) est refusée.
