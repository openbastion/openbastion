# Installation

**Kubernetes (référence de production)** :

```sh
helm repo add openbastion https://charts.openbastion.io
helm install openbastion openbastion/openbastion \
  --namespace openbastion --create-namespace \
  -f values.yaml
```

Extrait `values.yaml` minimal pour un déploiement MVP :

```yaml
postgresql:
  external: true
  host: postgres.internal
oidc:
  issuerUrl: "https://idp.example.com/realms/company"
  clientId: "openbastion"
  clientSecretRef: "openbastion-oidc-secret"
sshProxy:
  replicas: 3
vault:
  kmsKeyRef: "arn:aws:kms:eu-west-3:xxx:key/xxx"   # ou équivalent HSM on-premise
```

**Docker Compose (petit site on-premise, développement)** : `deploy/docker-compose/` (ADR-0033, mode d'emploi dans son `README.md`) — non recommandé pour un environnement de production au-delà d'un pilote. **C'est aujourd'hui le seul déploiement qui existe dans le dépôt** : les charts Helm ci-dessus sont la cible, pas encore écrits.

```sh
deploy/docker-compose/init.sh       # une fois : tire les secrets dans deploy/docker-compose/.env (0600) ; refuse d'écraser
docker compose -f deploy/docker-compose/docker-compose.yml up -d --build --wait
echo "$MOT_DE_PASSE" | docker compose -f deploy/docker-compose/docker-compose.yml run --rm -T cli \
  user create -authn https://authentication:8086 -username alice -roles platform-admin,vault-admin
```

**L'Admin UI** est servie par la Gateway sous `http://127.0.0.1:8080/ui/` (ADR-0036) : connexion locale ou fédérée, comptes privilégiés, création de politiques, demandes d'urgence à décider, sessions, relecture des enregistrements. Le jeton reste en mémoire : recharger la page déconnecte. Pour la connexion fédérée, déclarer chez le fournisseur l'URL de retour `https://<gateway>/ui/oidc/callback` (`OIDC_REDIRECT_URL`).

Ce que la pile garantit, et que `make test-compose` vérifie : mTLS entre tous les services ; une base et un rôle par service, aucun rôle n'ouvre la base d'un autre ; chaque service ne voit que son certificat et sa clé, **jamais la clé de l'autorité** (volume `pki-ca`, monté par le seul job `pki`) ; seuls l'API publique et le port SSH du proxy sont publiés, sur `127.0.0.1` (`OB_BIND` pour changer) ; aucun compte de démonstration ; aucun secret dans les journaux. **Le fichier `.env` est à sauvegarder hors de l'hôte** : ses clés rendent lisibles la chaîne d'audit, le Vault et les enregistrements. Les certificats des services sont renouvelés à chaque `up` (720 h par défaut, `OB_CERT_TTL`).
