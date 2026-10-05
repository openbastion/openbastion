# OpenBastion — Documentation Administrateur

**Version** 0.1 · **Statut** Draft de travail
**Public visé** Administrateurs de la plateforme OpenBastion (déploiement, configuration, exploitation courante)
**Document précédent** `OpenBastion_Doc_Developpeur.md`
**Portée** Ce document ne couvre que le périmètre MVP (doc 04 §2) : authentification OIDC, RBAC simple, SSH Proxy, Password Vault, Audit. Les sections marquées *v1.0* anticipent des fonctionnalités pas encore livrées.

---

## 1. Prérequis de déploiement

| Composant | Rôle |
|---|---|
| Kubernetes / K3s / OpenShift, ou Docker Compose pour un petit site on-premise | Orchestration (doc 00 §10) |
| PostgreSQL 15+ | Métadonnées, politiques, comptes (doc 06) |
| Redis | Cache, état de session |
| MinIO | Stockage des enregistrements (v1.0 pour la vidéo) |
| NATS, Kafka | Bus temps réel / audit durable (ADR-0001) |
| Keycloak | IdP de plateforme (ADR-0007) |
| Un fournisseur OIDC accessible | Fédération d'identité en périmètre MVP (doc 04 §2) |

## 2. Installation

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

**Docker Compose (petit site on-premise, développement)** : voir `deploy/docker-compose/docker-compose.yml` (doc 02 §6) — non recommandé pour un environnement de production au-delà d'un pilote.

## 3. Configuration initiale

1. **Bootstrap du premier compte administrateur** — créé automatiquement à l'installation si `bootstrapAdmin` est renseigné dans `values.yaml` ; désactivé après première connexion.
2. **Vérifier la fédération OIDC** : `GET /api/v1/auth/me` après une connexion de test doit renvoyer `identitySource: "oidc"` et le mapping correct de `username`/`displayName` (doc 05 §2, schéma `User`).
3. **Créer les premiers rôles** (§5).

## 4. Gestion des comptes privilégiés (Vault)

Onboarder un compte SSH cible :

```sh
curl -X POST https://bastion.example.com/api/v1/vault/accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-db-01-root",
    "targetHost": "10.0.4.12",
    "protocol": "ssh",
    "rotationPolicy": "post_use"
  }'
```

`rotationPolicy` accepte `manual`, `post_use` ou `scheduled` (doc 06 §3). Une rotation manuelle immédiate se déclenche via :

```sh
curl -X POST https://bastion.example.com/api/v1/vault/accounts/{accountId}/rotate \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Rappel** : l'API ne renvoie jamais le secret lui-même, à aucun moment, pour aucun rôle — cohérent avec ADR-0003. Un administrateur configure des comptes, il n'en consulte jamais les mots de passe.

## 5. Gestion des politiques RBAC

Une politique lie un rôle à un motif de ressource (doc 06 §3). Exemple : autoriser le rôle `dba` à ouvrir des sessions sur les comptes préfixés `prod-db-` :

```sh
curl -X POST https://bastion.example.com/api/v1/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dba-prod-db-access",
    "role": "dba",
    "resourcePattern": "vault:account:prod-db-*",
    "effect": "allow"
  }'
```

Le comportement est **deny-by-default** (Guide Sécurité §5) : un rôle sans politique associée n'ouvre l'accès à rien. Il n'existe pas de politique implicite « administrateur = accès total » — elle doit être créée explicitement si souhaitée.

## 6. Fédération d'identité

**Périmètre MVP — OIDC uniquement.** La connexion à un fournisseur OIDC se configure via `oidc.issuerUrl`, `oidc.clientId` et `oidc.clientSecretRef` (§2). Le mapping des claims vers `username`/`displayName` suit la convention standard OIDC (`preferred_username`, `name`) — personnalisable via `oidc.claimsMapping` si votre IdP diverge.

*v1.0* — LDAP, Active Directory, Entra ID, SAML et SCIM seront configurables via des sections dédiées de `values.yaml`, chacune correspondant à son connecteur (doc 00 §4.7). Ce document sera mis à jour à leur livraison.

## 7. Supervision et audit courant

- **Dashboards** : Grafana préconfiguré (doc 00 §10) expose l'activité par service, le taux d'échec d'authentification, le nombre de sessions actives.
- **Consultation de l'audit** :

```sh
curl "https://bastion.example.com/api/v1/audit/events?actor=jdupont&dateFrom=2026-08-01T00:00:00Z" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

- **Terminer une session active** en cas de doute :

```sh
curl -X DELETE https://bastion.example.com/api/v1/sessions/{sessionId} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Cette terminaison génère elle-même un événement d'audit (`action = "session.terminate"`, `actor` = l'administrateur qui a agi) — un arrêt forcé n'est jamais silencieux.

## 8. Sauvegardes

| Donnée | Où | Fréquence recommandée |
|---|---|---|
| PostgreSQL (comptes, politiques, sessions, audit) | Snapshot + WAL continu | Continu |
| MinIO (enregistrements, *v1.0*) | Réplication de bucket | Continu |
| Clé KMS/HSM | **Jamais dans la même sauvegarde que les données chiffrées** | Selon la politique du KMS externe |

La procédure complète de bascule en cas de sinistre, y compris la question de savoir si un site sauvegardé doit être traité comme potentiellement compromis, est couverte par `OpenBastion_Guide_PRA_PCA.md` (§4) — ce document ne couvre que la sauvegarde courante, pas la reprise.

## 9. Mise à jour de la plateforme

- Les contrats REST (`/api/v1`) et gRPC (`proto/`) évoluent de façon additive uniquement (doc 07 §1) — une mise à jour mineure n'exige jamais de migration cliente.
- Procéder par `helm upgrade`, service par service si un déploiement fin est souhaité (les charts sont indépendants, doc 02 §6).
- Toujours mettre à jour PostgreSQL (migrations de schéma) avant les services applicatifs qui en dépendent, jamais l'inverse.

## 10. Dépannage courant

| Symptôme | Cause probable | Action |
|---|---|---|
| Session bloquée en `pending_approval` alors qu'aucun workflow n'est attendu | Périmètre MVP : l'octroi devrait être immédiat après RBAC (doc 04 §2) — signale un dysfonctionnement de l'Authorization Service | Vérifier `Authorization.CheckAccess` (doc 07 §8) dans les traces OpenTelemetry |
| `POST /sessions` renvoie `403` de façon inattendue | Politique manquante ou `resourcePattern` mal formé (§5) | Lister les politiques du rôle concerné via `GET /policies` |
| Rotation d'un compte reste indéfiniment en cours | KMS/HSM externe indisponible (Guide Sécurité §6) | Vérifier la connectivité du Password Vault vers le KMS configuré en `values.yaml` |

## 11. Prochaine étape

Le **guide utilisateur** s'adresse à l'opérateur final — celui qui demande et utilise une session — sans les concepts d'administration de ce document.

---
*Document suivant : `OpenBastion_Guide_Utilisateur.md`*
