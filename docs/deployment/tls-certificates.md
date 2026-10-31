# Identité des services (mTLS interne)

Tous les appels entre services sont en TLS 1.3, avec certificat des deux côtés (ADR-0010). Chaque service lit son identité dans des fichiers PEM :

| Variable | Rôle |
|---|---|
| `INTERNAL_TLS` | `required` (défaut) ou `disabled`. **Un service sans certificat refuse de démarrer.** `disabled` supprime toute authentification entre services : développement uniquement, avertissement à chaque démarrage. Toute autre valeur est une erreur fatale. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Certificat (chaîne, feuille en premier) et clé privée **du service**. |
| `TLS_CA_FILE` | Autorités de confiance (un ou plusieurs certificats). |
| `TLS_TRUST_DOMAIN` | Domaine de confiance, `openbastion.local` par défaut. Le même pour tous les services. |
| `TLS_RELOAD_INTERVAL` | Fréquence maximale de relecture des fichiers, `5s` par défaut. |

**Forme de l'identité.** Le certificat de chaque service porte **un seul SAN URI**, `spiffe://<domaine>/<service>`, avec pour `<service>` l'un de : `api-gateway`, `authentication`, `authorization`, `session-broker`, `ssh-proxy`, `password-vault`, `audit-service`, `command-recorder`, et `admin-cli` pour l'outillage opérateur (qui n'a accès qu'à la création d'utilisateurs et à la vérification de la chaîne d'audit). Il doit servir et authentifier un client (`serverAuth` et `clientAuth`) et porter, comme noms DNS ou adresses IP, ceux sous lesquels les autres services le joignent : ils vérifient l'adresse qu'ils composent. **Un service refuse le certificat d'un autre service**, même valide. Avec SPIRE, enregistrer les identités sous cette forme (un seul segment de chemin).

**Petit site ou développement : `openbastion-pki`.**

```sh
make pki                                   # autorité + une identité par service, dans .pki/
# ou, sans make :
openbastion-pki all -dir /etc/openbastion/pki -trust-domain bastion.example.com -ttl 168h
openbastion-pki issue -dir … -service password-vault -dns vault.openbastion.svc -ip 10.0.0.12 -ttl 24h
```

Chaque service reçoit `<dir>/<service>/cert.pem` et `key.pem` (clé en 0600) et la même `<dir>/ca.pem`. La clé de l'autorité (`ca-key.pem`) **ne doit atteindre aucun service** : elle reste sur la machine qui émet. Les certificats durent 7 jours par défaut : relancer la commande les **renouvelle** sans redémarrage (voir ci-dessous) et conserve l'autorité.

**Renouveler un certificat.** Remplacer les fichiers du service (clé d'abord, puis certificat — `openbastion-pki issue` et cert-manager le font). Le service les reprend au plus tard après `TLS_RELOAD_INTERVAL`, sans redémarrage, et journalise `mtls: reloaded the identity of <service>`. Un fichier invalide (autre autorité, autre service, clé qui ne correspond pas) est **refusé** — `mtls: NOT reloading … keeping the current one` — et le service garde son identité actuelle : renouveler avec une erreur ne casse pas un service qui tourne, mais il faut lire le journal pour s'en apercevoir.

**Surveiller l'échéance.** Un certificat expiré est une panne : les pairs refusent le service. Le service journalise `mtls: the certificate of <service> expires at … — renew it` quand il reste 20 % de sa durée de vie, et `… EXPIRED …` à l'échéance. Alerter sur ces deux messages, **et** sur l'échéance des fichiers eux-mêmes (par exemple `openssl x509 -enddate -noout -in cert.pem`), car un service qui ne tourne plus ne journalise rien.

**Remplacer l'autorité** (compromission, ou fin de vie de l'autorité) — dans cet ordre, sans interruption :

1. Créer la nouvelle autorité ; mettre **les deux** certificats d'autorité dans le fichier `TLS_CA_FILE` de chaque service. Chaque service accepte immédiatement les certificats de l'une et de l'autre.
2. Réémettre l'identité de chaque service depuis la nouvelle autorité.
3. Retirer l'ancienne autorité du bundle. **Un service refuse de retirer l'autorité qui a signé son propre certificat** (`does not chain to the CA bundle`) : l'étape 2 doit être faite avant. À cet instant, tout certificat de l'ancienne autorité — y compris un certificat volé — cesse d'être accepté. C'est le remplacement de l'autorité, pas une liste de révocation, qui répond à une compromission.

**La Gateway** garde son listener public en HTTP (le TLS se termine chez Traefik) : elle a une identité pour ses appels vers les autres services, pas pour ceux qu'elle reçoit.

**Sondes Kubernetes.** Les sondes HTTP du kubelet ne présentent pas de certificat client : utiliser des sondes `tcpSocket` sur les ports internes (la santé applicative se vérifie par la supervision, avec une identité de service). Voir le `docs/deployment/high-availability.md`.
