# ADR-0079 — Entra ID est un profil OIDC lié à un tenant déclaré

**Statut** `Accepté` · 7 novembre 2026 · accepté explicitement par le propriétaire du projet

**Contexte** — ADR-0035 fournit le protocole OIDC et ADR-0076 permet plusieurs fournisseurs simultanés, chacun avec son identifiant et ses rôles propres. L'Authentication Service ne distingue toutefois pas un fournisseur Microsoft Entra ID d'un fournisseur OIDC générique. La feuille de route v0.0.1 annonce un connecteur Entra ID, mais créer un second moteur d'authentification ferait diverger deux implémentations du même protocole et multiplierait les chemins de validation des jetons.

Entra ID apporte néanmoins une contrainte utile à exprimer explicitement : une configuration d'entreprise doit être liée à un tenant déterminé, et non accepter implicitement des autorités multi-tenant ou personnelles. Le contrôle d'émetteur d'ADR-0078 protège déjà chaque fournisseur OIDC contre un changement non déclaré ; il ne remplace pas la vérification du tenant revendiqué par le jeton.

**Décision**

1. **Pas de protocole ni de service d'authentification supplémentaire.** Entra ID utilise le flux OIDC existant (Authorization Code + PKCE), le stockage des fournisseurs d'ADR-0076, les contrôles de jeton d'ADR-0035 et le verrou d'émetteur d'ADR-0078. Le profil Entra est une variante explicitement déclarée d'un fournisseur OIDC.
2. **Tenant obligatoire et explicite.** Un fournisseur de profil `entra` déclare un `tenant_id` GUID. Son émetteur doit être exactement l'émetteur v2 du tenant déclaré : `https://login.microsoftonline.com/<tenant_id>/v2.0`. Les autorités génériques `common`, `organizations` et `consumers`, les émetteurs non HTTPS et les tenants implicites sont refusés au démarrage.
3. **L'identité reste cloisonnée par fournisseur.** Le compte OpenBastion est dérivé de l'identifiant du fournisseur et du `sub`, comme pour les autres entrées OIDC. Le claim `tid` doit être présent et égal au `tenant_id` configuré ; une absence ou une différence refuse la connexion avant toute création ou reprise de compte. Le contrôle standard `iss`, `aud`, `exp`, `nonce`, signature et état reste obligatoire.
4. **Les rôles restent décidés localement.** Seuls les groupes présents dans le claim de groupes déclaré et dans la table de correspondance propre à ce fournisseur peuvent attribuer des rôles. Aucun nom de rôle, rôle applicatif ou claim `roles` reçu du fournisseur n'est accepté comme autorité implicite.
5. **Dépassement de groupes : refus fermé.** Si le jeton signale que la liste des groupes est incomplète ou remplacée par une référence de récupération, la connexion est refusée sans créer de compte ni émettre de jeton. La première version ne suit pas de référence vers Microsoft Graph et ne demande aucune permission Graph applicative.
6. **Configuration explicite et compatible.** Le fichier multi-fournisseurs porte un discriminant de profil `entra` et le `tenant_id` associé ; les entrées `oidc` existantes gardent leur comportement. Les variables OIDC historiques ne deviennent pas implicitement des fournisseurs Entra. Les secrets restent dans des fichiers protégés, jamais dans le fichier de fournisseurs, les journaux ou l'audit.
7. **Audit et erreurs.** Les refus de configuration sont explicites sans révéler de secret. Les échecs d'authentification suivent les événements et budgets existants ; les détails de jeton, les claims complets et les identifiants sensibles ne sont jamais journalisés.

**Preuve attendue** (tests automatisés, sans dépendance à un tenant Microsoft réel en CI) :

- configuration Entra valide avec tenant GUID, émetteur exact, audience et secret client corrects ;
- refus au démarrage des autorités multi-tenant, d'un tenant non GUID, d'un émetteur d'un autre tenant et d'une URL non HTTPS ;
- jeton signé avec `tid` absent ou différent : refus, aucune ligne de compte, aucun jeton de session ;
- jeton valide avec groupes déclarés : rôles calculés uniquement depuis la table propre au fournisseur ;
- groupe inconnu ou claim de groupes absent : aucun rôle implicite, accès refusé ;
- indicateurs de dépassement ou référence de récupération de groupes : refus fermé, aucun appel réseau sortant vers une URL issue du jeton ;
- changement d'émetteur non déclaré refusé selon ADR-0078 ; changement déclaré toujours audité avant mise à jour ;
- deux fournisseurs Entra dans deux tenants distincts : mêmes `sub` ne donnent jamais le même compte ;
- contre-épreuves par mutations sur le contrôle du tenant, l'émetteur, le mapping de rôles et le dépassement de groupes.

**Conséquences**

- (+) Le connecteur Entra réutilise le chemin OIDC éprouvé ; pas de deuxième implémentation de validation cryptographique ni de nouvelle surface de protocole.
- (+) Le tenant est une frontière de confiance explicite, vérifiée à la configuration et à chaque connexion.
- (+) Aucun droit Microsoft Graph n'est demandé dans cette première tranche ; pas de récupération de groupes par URL fournie dans un jeton.
- (−) **Groupes nombreux** : les utilisateurs dont Entra ID omet les groupes du jeton ne peuvent pas se connecter tant qu'une décision distincte sur Graph ou une autre stratégie de résolution n'est pas prise.
- (−) **Pas de provisionnement SCIM** : la création et la mise à jour des comptes restent à la connexion, comme aujourd'hui.
- (−) **Pas de multi-tenant ouvert** : chaque tenant doit être déclaré séparément ; les comptes invités B2B ne sont pas automatiquement acceptés au titre de leur tenant d'origine.
- (−) **Pas de synchronisation hors ligne** : les changements de groupes prennent effet à la prochaine authentification, selon le modèle OIDC existant.

**Mise en œuvre et mesures** (7 novembre 2026)

- **Configuration** : une entrée `oidc` de `IDENTITY_PROVIDERS_FILE` prend `"profile": "entra"` et `"tenant_id"`. `profile` absent ou `oidc` : rien ne change. Le `tenant_id` est un GUID **en minuscules** ; l'émetteur est comparé au caractère près à `https://login.microsoftonline.com/<tenant_id>/v2.0`. Le contrôle est fait deux fois : à la lecture du fichier, et à la construction du fournisseur, avant toute requête.
- **Jeton** : `tid` doit être présent, une chaîne, et égal au tenant (sans tenir compte de la casse). Un overage est reconnu à `_claim_names` qui nomme le claim de groupes (ou `groups`), ou à `hasgroups` vrai : refus, et la référence n'est jamais suivie. `_claim_sources` seul, ou des claims distribués qui ne sont pas les groupes, sont de l'OIDC valide (OpenID Connect Core §5.6.2) : ils ne sont pas refusés, et ne sont pas suivis non plus. Ce dernier point est une correction du propriétaire, après la première mise en œuvre qui refusait tout `_claim_sources`.
- **Écart avec l'OIDC générique, trouvé à la mise en œuvre** : le client demandait le scope du claim de groupes (`openid profile email groups`). Entra ID n'a pas de scope `groups` : les groupes viennent de la configuration de l'application. Pour le profil `entra`, le scope est `openid profile email`. Déduit de la documentation Microsoft, **non vérifié contre un vrai tenant**.
- **Tests de l'infrastructure** : 7 tests (jeton valide ; `tid` absent, vide, d'un autre tenant ou non textuel ; trois formes d'overage, sans aucune requête vers Graph, et trois jetons valides à claims distribués étrangers aux groupes ; fournisseur générique inchangé ; dix configurations refusées avant tout réseau ; scope ; fichier). Mutations tuées : contrôle du tenant retiré, tout tenant accepté, `_claim_names` des groupes accepté, tout `_claim_sources` refusé (l'ancienne règle), émetteur non vérifié par le fournisseur ou par le fichier, autorités multi-tenant admises. Un défaut du test lui-même a été trouvé en le durcissant : un GUID sans lettre est identique en majuscules ; le cas utilise maintenant un tenant qui en a.
- **Processus réels, sans tenant Microsoft** (`test/integration/entra_flow_test.go`, 4 à 6 s, sous PostgreSQL) : le vrai binaire joint `login.microsoftonline.com` en HTTPS par un proxy `CONNECT` de test (`HTTPS_PROXY`), qui l'envoie à un faux Entra ID servi avec le certificat d'une autorité de test (`SSL_CERT_FILE`). Le service n'a pas de mode de test : l'émetteur est le vrai, en HTTPS. Six sous-tests verts : refus de démarrer (`common`, émetteur d'un autre tenant) ; deux tenants, même `sub`, deux comptes, rôles de la table ; `tid` d'un autre tenant ou absent : `401`, aucun compte ; claim `roles` ou groupe inconnu : `403`, aucun compte ; overage : `401`, et le proxy n'a vu passer que `login.microsoftonline.com` ; autre tenant sous le même identifiant : refus de démarrer (ADR-0078). Trois mutations tuées sur ces processus (contrôles Entra retirés, tout overage accepté, scope `groups` demandé).

**Alternatives envisagées**

- **Un connecteur Entra indépendant avec son propre flux OAuth** : écarté, car il dupliquerait la validation OIDC, le PKCE, les états, les nonces et le cycle de vie des fournisseurs.
- **Accepter `common` ou `organizations` puis vérifier seulement `tid`** : écarté, car la sélection de l'autorité ne serait plus liée à une frontière de tenant unique au démarrage.
- **Interroger Microsoft Graph pour chaque connexion** : écarté de cette tranche ; cela ajoute des permissions, un jeton d'accès distinct, une dépendance réseau et un modèle de panne à décider.
- **Faire confiance aux claims `roles` ou aux groupes sans table locale** : écarté, car le fournisseur ne doit pas attribuer directement les privilèges OpenBastion.
