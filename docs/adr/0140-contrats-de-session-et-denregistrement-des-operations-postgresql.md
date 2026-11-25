# ADR-0140 — Les contrats PostgreSQL séparent l'établissement de session et l'acquittement des opérations

**Statut** `Proposé` · 2026-11-25 · contrats d'intégration du Database Proxy après ADR-0139

## Contexte

L'ADR-0139 est accepté et le premier incrément du Database Proxy est fusionné. Il fournit le noyau `pgwire`, les tickets, le registre de révocation et les routes internes d'établissement/révocation. Il ne fournit pas encore un proxy opérationnel.

L'inventaire du code existant révèle trois écarts concrets :

1. Le Password Vault stocke `Username`, `TargetHost`, `Protocol`, le nom TLS (`TargetDomain`) et l'empreinte TLS, mais aucun nom de base PostgreSQL. Sa réponse `fetch-credential` ne peut donc pas fournir au proxy l'identité complète de la cible.
2. Le contrat générique `SessionBroker → Proxy` transporte `target_host` et `target_user`. Il ne porte pas le nom de base, et ne doit pas devenir une source d'autorité concurrente du Vault pour l'identité de la cible.
3. Le Command Recorder stocke aujourd'hui des `CommandEntry` destinées aux commandes de terminal (`session_id`, horodatage, texte). Son RPC `StreamCommandEntries` ne peut pas représenter les événements structurés `started`/`completed` d'une opération SQL sans détourner le champ `command`, ni garantir une idempotence par opération.

Ces lacunes doivent être fermées avant le listener PostgreSQL et le relais vers une cible réelle : sinon le proxy ne pourrait pas vérifier complètement le StartupMessage, ni prouver durablement chaque opération avant transmission.

## Décision

### 1. Autorité sur l'identité de la cible PostgreSQL

1. Le Password Vault reste l'autorité sur le compte privilégié. Pour un compte `protocol=postgresql`, il stocke un champ `database_name` obligatoire, borné à 63 octets UTF-8 et validé selon les règles d'identifiant PostgreSQL retenues par le service. Pour les autres protocoles, ce champ reste vide et n'a aucun effet.
2. `database_name` est ajouté de manière additive à `PrivilegedAccount`, à la réponse de métadonnées du compte, à la réponse `fetch-credential` et à leurs contrats REST/JSON. La migration PostgreSQL du Vault est additive, idempotente et ne réécrit aucune donnée existante. Aucun compte existant n'est converti implicitement en compte PostgreSQL.
3. Pour une cible PostgreSQL, le Vault exige également un nom DNS TLS attendu (`TargetDomain`) et une empreinte de certificat épinglée (`TLSCertificateSHA256`). Le proxy vérifie la chaîne avec les racines CA explicitement configurées, le nom DNS et l'empreinte épinglée ; une information absente ou invalide refuse la connexion. Aucun `InsecureSkipVerify`, repli clair ou nom fourni par le client n'est accepté.
4. Le Session Broker transmet au Database Proxy uniquement `session_id`, le scope Vault à usage unique et le TTL restant. Il ne transmet ni mot de passe ni copie de l'identité cible. Le scope lie déjà le compte, la session et l'identité mTLS `database-proxy` ; le proxy récupère directement du Vault l'adresse, le rôle, la base, le nom TLS, l'empreinte et le credential.
5. La réponse `fetch-credential` du Vault inclut également `account_id`, issu du scope consommé, afin d'attribuer les événements sans accepter un identifiant fourni par l'opérateur. Le proxy conserve ces valeurs dans un contexte de session immuable. Le `user` et le `database` du StartupMessage doivent correspondre exactement au rôle et à la base renvoyés par le Vault. Toute divergence, option de changement de rôle ou tentative de sélection d'une autre cible ferme la connexion avant l'ouverture amont.
6. Le contrat interne dédié est `POST /internal/v1/database-sessions` avec `{session_id, vault_scope_token, ttl_seconds}`. La réponse est `{proxy_endpoint, connection_ticket}`. La révocation réutilise `POST /internal/v1/revoke-session` et reste idempotente. Seul `session-broker` peut appeler ces routes, par mTLS ; le proxy refuse les autres identités.
7. Le Broker sélectionne le Database Proxy à partir du protocole du compte déjà résolu et autorisé. Aucun endpoint, hôte, rôle ou nom de base fourni par l'opérateur ne peut influencer la destination réseau.

### 2. Contrat d'enregistrement des opérations SQL

1. Les opérations SQL ne réutilisent pas `CommandEntry` ni `StreamCommandEntries`. Le Command Recorder expose un contrat dédié `DatabaseRecording.RecordDatabaseOperation(DatabaseOperationEvent) returns (DatabaseOperationAck)`.
2. Le transport de référence est gRPC/mTLS. Tant que le code généré et le transport gRPC ne sont pas intégrés au module, l'adaptateur HTTP/JSON de compatibilité expose `POST /recorder/v1/database-operations` avec les mêmes champs Protobuf en `snake_case`. Ce transport temporaire n'introduit aucune sémantique différente.
3. Le contrat d'événement contient exclusivement : `session_id`, `operation_id` (UUID aléatoire), `sequence` (entier positif strictement croissant pour chaque nouvel événement `started` de la session ; `completed` reprend la séquence de son `started`), `phase` (`started` ou `completed`), `occurred_at`, `account_id` opaque renvoyé par le Vault, `database_name`, `role_name`, `command_class`, `command_tag` (facultatif, seulement pour `completed`), `query_fingerprint`, `duration_ms`, `rows_affected`, `transaction_state` (`idle`, `in_transaction`, `failed`) et `sqlstate` facultatif.
4. `query_fingerprint` est un HMAC-SHA-256 calculé par le proxy avec une clé propre à la session sur la forme SQL normalisée. Le texte SQL brut, les valeurs Bind, les résultats, les payloads COPY, les données binaires, les secrets et les paramètres de connexion ne font jamais partie du message. `command_class` est une classification descriptive bornée, calculée avant transmission ; si le proxy ne peut pas classer sans ambiguïté, il utilise `other` et ne prend aucune décision d'autorisation sur cette valeur.
5. `started` est persisté et acquitté durablement avant que le proxy transmette au serveur PostgreSQL le message qui déclenche l'opération. Pour le protocole simple `Query`, le premier profil accepte une seule instruction non vide par message et refuse les requêtes multi-instructions ; pour le protocole étendu, `Parse` enregistre un état préparé borné, `Bind` ne persiste aucune valeur et chaque `Execute` crée une opération distincte. `completed` est persisté et acquitté durablement avant que le proxy transmette au client la fin de l'opération et ses réponses finales. Une erreur ou un acquittement ambigu ferme la session ; aucun retry de l'opération SQL vers la cible n'est effectué.
6. L'idempotence est portée par `(session_id, operation_id, phase)`. Une répétition strictement identique après perte de réponse renvoie le même acquittement ; le même identifiant avec un contenu différent est un conflit et ferme la session. Le Recorder refuse une séquence non positive, réordonnée ou réutilisée par une autre opération de la même session.
7. Le stockage est append-only et distinct de `session_command_entries`, dans le schéma propriétaire du Command Recorder. La migration est additive. Les événements `started` et `completed` restent consultables comme métadonnées structurées ; ils ne sont pas présentés comme un replay du SQL ou des résultats.
8. Seule l'identité mTLS `database-proxy` peut écrire ces événements. L'acteur utilisateur n'est jamais accepté depuis le corps de l'événement : il est associé à la session côté services de confiance. L'Audit Service continue de recevoir les transitions de sécurité (connexion, refus, révocation, perte Recorder) ; les opérations SQL détaillées restent la responsabilité du Command Recorder.
9. `GET /readyz` du Command Recorder est vérifié avant admission d'une session Database Proxy. L'indisponibilité ou la non-écriture du Recorder entraîne un refus fail-closed ; aucun tampon local ni mode dégradé silencieux n'est permis.

### 3. Modèle de données du Command Recorder

La nouvelle table `database_operation_events` appartient exclusivement au Command Recorder :

| Colonne | Type logique | Règle |
|---|---|---|
| `id` | `bigserial` | Clé primaire technique |
| `session_id` | `text` | Identifiant de session, sans FK inter-service |
| `operation_id` | `uuid` | Identifiant stable d'une opération |
| `sequence` | `bigint` | Positif ; croissant pour chaque `started`, repris par son `completed` |
| `phase` | `text` | `started` ou `completed` |
| `occurred_at` | `timestamptz` | Horodatage UTC fourni par le proxy, borné contre les valeurs absurdes |
| `account_id` | `text` | Identifiant opaque du compte privilégié renvoyé par le Vault |
| `database_name` | `text` | Nom autorisé, jamais une valeur arbitraire client |
| `role_name` | `text` | Rôle autorisé résolu par le Vault |
| `command_class` | `text` | Classe fermée (`read`, `write`, `ddl`, `transaction`, `other`), déterminée avant transmission |
| `command_tag` | `text` nullable | Tag `CommandComplete`, présent uniquement pour `completed` ; jamais le texte SQL |
| `query_fingerprint` | `bytea` | HMAC-SHA-256, exactement 32 octets |
| `event_hash` | `bytea` | SHA-256 du message canonique, exactement 32 octets ; vérifie l'identité d'un retry |
| `duration_ms` | `bigint` nullable | Présent uniquement pour `completed`, borné |
| `rows_affected` | `bigint` nullable | Présent uniquement si fourni par PostgreSQL |
| `transaction_state` | `text` | Valeur de l'énumération fermée |
| `sqlstate` | `text` nullable | Cinq caractères alphanumériques majuscules |

Contraintes uniques : `(session_id, operation_id, phase)` et `(session_id, sequence, phase)`. Une table `database_operation_cursors(session_id PRIMARY KEY, last_sequence)` détient le dernier numéro `started` validé. La transaction verrouille ce curseur : un nouveau `started` exige `sequence = last_sequence + 1` et fait avancer le curseur atomiquement ; `completed` réutilise exactement la séquence de son `started` et n'avance pas le curseur. Une opération `completed` doit référencer un `started` déjà durable ; sinon elle est refusée. Le hash canonique permet de distinguer un retry identique d'un conflit de contenu. Les contraintes et la transaction empêchent deux écrivains concurrents de valider une séquence incohérente.

### 4. Contrats Protobuf proposés

Ajouter sans modifier les numéros existants dans `proto/recording/v1/recording.proto` :

```proto
service DatabaseRecording {
  rpc RecordDatabaseOperation(DatabaseOperationEvent) returns (DatabaseOperationAck);
  rpc CheckDatabaseRecorderReadiness(CheckDatabaseRecorderReadinessRequest)
      returns (CheckDatabaseRecorderReadinessResponse);
}

message DatabaseOperationEvent {
  string session_id = 1;
  string operation_id = 2;
  int64 sequence = 3;
  DatabaseOperationPhase phase = 4;
  google.protobuf.Timestamp occurred_at = 5;
  string account_id = 6;
  string database_name = 7;
  string role_name = 8;
  string command_class = 9;
  optional string command_tag = 10;
  bytes query_fingerprint = 11;
  optional int64 duration_ms = 12;
  optional int64 rows_affected = 13;
  DatabaseTransactionState transaction_state = 14;
  string sqlstate = 15;
}

enum DatabaseOperationPhase {
  DATABASE_OPERATION_PHASE_UNSPECIFIED = 0;
  DATABASE_OPERATION_PHASE_STARTED = 1;
  DATABASE_OPERATION_PHASE_COMPLETED = 2;
}

enum DatabaseTransactionState {
  DATABASE_TRANSACTION_STATE_UNSPECIFIED = 0;
  DATABASE_TRANSACTION_STATE_IDLE = 1;
  DATABASE_TRANSACTION_STATE_IN_TRANSACTION = 2;
  DATABASE_TRANSACTION_STATE_FAILED = 3;
}

message DatabaseOperationAck {
  string operation_id = 1;
  DatabaseOperationPhase phase = 2;
  int64 sequence = 3;
  bool persisted = 4;
}

message CheckDatabaseRecorderReadinessRequest {}
message CheckDatabaseRecorderReadinessResponse { bool ready = 1; }
```

Les enums `phase` et `transaction_state` sont validés côté serveur ; `UNSPECIFIED` et toute valeur inconnue sont refusés. `duration_ms` est absent pour `started` et obligatoire pour `completed`. `rows_affected` est optionnel et sa présence est distincte de zéro. Le champ `persisted` n'est vrai qu'après commit durable.

### 5. Validation obligatoire avant le runtime

- Tests de contrat Vault : un compte PostgreSQL exige `database_name`, `TargetDomain` et l'empreinte ; les comptes SSH/RDP/VNC existants gardent leur comportement.
- Tests Session Broker : le scope transmis au proxy est opaque, limité au compte et à la session ; aucune identité de cible n'est fournie par l'opérateur.
- Tests Database Proxy : le rôle et la base du StartupMessage sont comparés aux métadonnées Vault ; divergence et options interdites sont refusées avant toute connexion cible.
- Tests Recorder sur processus réel et PostgreSQL 16 : acquittement après commit, idempotence après perte de réponse, conflit de payload, ordre de séquence, `completed` sans `started`, panne avant opération et panne entre `started`/`completed`.
- Tests canaris : aucune valeur SQL, valeur Bind, réponse, credential cible ou scope ne figure dans les événements, logs, traces, métriques ou profils.
- Tests `-race` sur les séquences concurrentes et la révocation pendant une opération ; toute ambiguïté ferme la session et ne rejoue jamais l'opération côté cible.

## Conséquences

- (+) L'identité de base est désormais définie par le propriétaire du compte (Vault), pas par le client ni par une copie de métadonnées transmise par le control plane.
- (+) Le contrat d'enregistrement distingue les opérations SQL des commandes shell et exprime les deux barrières de durabilité nécessaires avant transmission.
- (+) L'idempotence rend récupérable une perte d'acquittement du Recorder sans répéter une opération SQL sur la cible.
- (−) Cette décision ne rend pas encore le Database Proxy opérationnel ; listener, TLS entrant, connexion amont, SCRAM relay et tests libpq/PostgreSQL 16 restent à implémenter.
- (−) L'ajout de `database_name` requiert une migration additive du Vault et une évolution coordonnée du contrat Session Broker / Database Proxy.
- (−) Le stockage append-only des événements augmente le volume PostgreSQL du Command Recorder ; rétention, archivage et recherche dédiée restent à cadrer avant une volumétrie de production.
- (−) Le contrat ne capture ni SQL brut, ni Bind, ni résultats ; il permet une recherche par métadonnées et empreinte, pas une reconstitution de requête.

## Alternatives envisagées

- **Réutiliser `CommandEntry.command` pour y placer le tag SQL ou un JSON** : rejeté, car ce champ est le contenu textuel d'une commande shell et son stockage/chiffrement/recherche ont une sémantique différente.
- **Faire envoyer `target_host`, `target_user` et `database_name` par le Broker** : rejeté comme source d'autorité ; le proxy doit obtenir l'identité cible du Vault à partir du scope et vérifier le StartupMessage contre cette réponse.
- **Écrire les événements SQL uniquement dans l'Audit Service** : rejeté, car la chaîne d'audit atteste les décisions de sécurité, tandis que le Command Recorder assure le flux opérationnel et son acquittement synchrone.
- **Tamponner les opérations en mémoire ou sur disque si le Recorder est indisponible** : rejeté par ADR-0008 ; l'opération cible est refusée plutôt que livrée sans preuve durable.
- **Envoyer un événement unique après la réponse PostgreSQL** : rejeté, car une opération pourrait atteindre la cible sans preuve durable préalable.
