# ADR-0050 — Le transport entre services reste HTTP/JSON sous mTLS, avec les noms des messages de `proto/`, et un test empêche les deux de diverger

**Contexte**
La conception initiale prévoyait gRPC entre les services (`docs/api/grpc/README.md`, `proto/`). Le dépôt parle HTTP/JSON sous mTLS depuis le premier jour, d'abord parce que le réseau du bac à sable ne laissait pas tirer `google.golang.org/grpc` ; c'était consigné comme un « écart » (`.agents/architecture/transport-and-contracts.md`), et le point 8 du backlog proposait de le refermer. Mesuré le 31 octobre 2026 :

- `proto/` décrit 6 contrats et 19 RPC ; le code sert 29 routes internes dans 8 services, et 29 fichiers de tests d'intégration les appellent ;
- `google.golang.org/grpc` v1.85.0 apporte `protobuf`, `genproto`, `x/net` et `x/text`, et exige **Go 1.26** dans les modules (ils déclarent 1.22) ; il demande `x/sys` v0.48, que les services forcent aujourd'hui en v0.21 par un miroir ;
- aucun générateur (`protoc`, `buf`) n'est installé ;
- `pkg/mtls` garde les routes HTTP ; gRPC demanderait des intercepteurs, et une seconde implémentation des règles par route.

Rien de ce que le MVP garantit ne dépend du transport : l'identité vient du certificat (ADR-0010), chaque route a sa liste d'appelants, les secrets ne passent que par `fetch-credential`. Mais les routes ont dérivé des messages sans que rien ne le voie : des durées (`ttl_seconds`) là où le proto dit une échéance, un auteur à plat là où le proto dit un `RequestContext`, une révocation qui répond par des compteurs.

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « clore par un ADR », parmi un pilote, la migration complète et le report)*

1. **HTTP/JSON sous mTLS est le transport entre services**, une décision et non plus un écart. `proto/` reste la description des contrats — les noms des messages et des champs — sans code généré.
2. **Les routes internes portent les champs de leur message** (`snake_case`), et **un test le prouve** (`test/integration/contract_test.go`), dans les deux sens : un champ JSON absent du message, ou un champ du message que la route ne porte pas, fait échouer le test **à moins d'être déclaré avec sa raison**. Une raison déclarée qui ne correspond plus à rien le fait échouer aussi : elle cacherait la prochaine dérive.
3. **Aucune structure interne n'échappe au test** : toute structure aux champs JSON en `snake_case` de `internal/interfaces` ou `internal/infrastructure` est soit dans la table des contrats, soit déclarée sans contrat, avec sa raison (le contrat d'Authorization, décrit en §8 mais pas encore dans `proto/` ; les revendications d'un jeton OIDC ; deux formats de fichier de l'audit).
4. **Les divergences d'aujourd'hui sont déclarées, et voulues** :
   - pas de `RequestContext` : l'appelant est celui du certificat, l'auteur un champ à plat (`actor_id`) ;
   - des durées (`ttl_seconds`) plutôt que des échéances (`expires_at`) : l'horloge de l'appelé décide de la fin ;
   - pas de `signature` sur `EmitEvent` : la chaîne signe elle-même chaque événement (ADR-0027) ; pas de `ts` dans la réponse ;
   - pas de `valid_until` sur `fetch-credential` : le secret vaut pour une connexion ;
   - `revoke-session` porte la durée de la mémoire de révocation et répond par ce qu'il a coupé ; le `200` dit « terminé » (ADR-0018).
5. **Quand y revenir** : un flux réel (`StreamVideoFrames`, `StreamHealth`), des clients dans un autre langage que Go, ou une mesure de performance qui le demande. Ce jour-là, le pilote commence par `AuditIngestion.EmitEvent`, HTTP gardé à côté.

**Conséquences**
- (+) **Mesuré** : 17 paires route ↔ message vérifiées dans les deux sens, et 7 structures déclarées sans contrat (l'Authorization, les revendications OIDC, deux formats de fichier) ; tout le reste des structures internes est couvert.
- (+) **6 mutations, 6 tuées** : un champ JSON renommé, un champ ajouté à un message, un champ retiré d'une réponse, une divergence déclarée retirée, une divergence fictive déclarée, une nouvelle structure interne non déclarée.
- (+) **Trouvé en écrivant le test** : j'avais déclaré `reason` comme champ de `ProxyControl.TerminateSessionRequest` non porté ; il n'existe que dans `SessionOrchestration.TerminateSessionRequest`. Le contrôle des déclarations périmées l'a refusé.
- (−) Pas de code généré : chaque client et chaque serveur écrit ses structures à la main ; le test vérifie leurs noms, pas leurs types (une durée en secondes et une en millisecondes portent le même nom).
- (−) Les clients qui construisent leur corps par une `map` ne sont pas vérifiés, seules les structures le sont : le Broker vers le proxy (`establish-session`, `revoke-session`), le proxy vers le Vault (`fetch-credential`) et vers l'audit, le Vault vers l'audit, le Vault et le Recorder vers l'Authorization. Leurs serveurs, eux, le sont : un champ mal nommé côté client y est un champ inconnu, ignoré, que les tests d'intégration voient comme une valeur manquante.
- (−) Pas de flux : l'enregistrement des commandes passe par lots en HTTP, et la santé des proxys n'est pas poussée.
- (−) `buf breaking` ne garde pas les numéros de champs : `proto/` n'est pas compilé.

**Alternatives envisagées**
- **Migration complète vers gRPC** : la mesure du contexte ; plusieurs incréments longs, une montée de version de Go dans tous les modules, et du risque dans le maillage interne pour aucune garantie de sécurité nouvelle.
- **Un pilote sur `EmitEvent`** : aurait donné des chiffres ; écarté pour l'instant, et c'est par là que la reprise commencerait.
- **Garder l'« écart » sans test** : les routes continueraient de dériver en silence.
