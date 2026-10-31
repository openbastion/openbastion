# ADR-0061 — Un utilisateur d'annuaire (LDAP ou Active Directory) se connecte avec son mot de passe d'annuaire ; seuls ses groupes déclarés lui donnent des rôles

**Statut** `Accepté` · 31 octobre 2026 · premier lot de la v1.0, choisi par Bony Kiss le 31 octobre 2026 (avec `go-ldap` v3.4.15 et des tests contre OpenLDAP et Samba AD) ; texte accepté par son go du 31 octobre 2026

**Contexte** — OpenBastion connaît deux sortes de comptes : locaux (un mot de passe Argon2id ici) et fédérés par OIDC (ADR-0035). Une entreprise dont les identités sont dans un annuaire — Active Directory le plus souvent, OpenLDAP ailleurs — doit aujourd'hui recréer chaque opérateur à la main, et lui donner un second mot de passe qu'aucun départ ne révoque. La feuille de route met LDAP/AD en tête de la v1.0 (`docs/roadmap.md` §6 : les pilotes en AD pur sont bloqués). La bibliothèque standard Go n'a pas de client LDAP : `github.com/go-ldap/ldap/v3` v3.4.15 (MIT ; tire `asn1-ber` MIT, `go-ntlmssp` MIT, `google/uuid` BSD-3) est accordée pour le seul module `authentication`.

Invariants touchés : l'identité qui décide est celle que le service vérifie, jamais un nom que le client choisit (comme `oidc:<sub>`, ADR-0035) ; défaut strict ; aucun secret au journal.

**Décision**

1. **Une route à part** : `POST /auth/ldap/login` (Gateway, publique, dans le **même budget par adresse** que `/auth/login`) → `POST /auth/v1/ldap/login` (Authentication, réservée à `api-gateway`). Même corps que `/auth/login` (`username`, `password`), même réponse (le jeton OpenBastion). `/auth/login` ne change pas : il ne consulte jamais l'annuaire.
2. **Désactivée par défaut, tout ou rien** :

   | Variable | Rôle |
   |---|---|
   | `LDAP_URL` | `ldaps://dc.example:636`, ou `ldap://…` **avec StartTLS, toujours** — même vers une adresse de bouclage : aucun mot de passe ne part en clair (resserré à l'implémentation, par rapport à la première rédaction qui tolérait le clair en boucle locale). |
   | `LDAP_CA_FILE` | Facultatif : l'autorité du certificat de l'annuaire. Jamais de vérification désactivée. |
   | `LDAP_SCHEMA` | `ad` ou `rfc` (OpenLDAP et compatibles) — fixe les attributs ci-dessous ; aucun attribut libre. |
   | `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD_FILE` | Le compte de service qui **cherche** (lecture seule) ; son mot de passe dans un fichier lisible par son seul propriétaire, relu à chaque connexion. |
   | `LDAP_USER_BASE_DN`, `LDAP_GROUP_BASE_DN` | Où chercher les utilisateurs et les groupes. |
   | `LDAP_ROLE_MAP_FILE` | La table des rôles : DN de groupe → rôles, le format et les règles d'ADR-0035 ; un groupe absent ne donne rien. |

   | `LDAP_SCHEMA` | Nom de connexion | Identifiant stable | Groupes | Compte désactivé |
   |---|---|---|---|---|
   | `ad` | `sAMAccountName` | `objectGUID` | recherche `member:1.2.840.113556.1.4.1941:=<DN>` (groupes **imbriqués**) | l'annuaire refuse le bind (mesuré contre Samba AD) ; *la vérification préalable de `userAccountControl` prévue ici a été retirée à l'implémentation : aucune mutation ne pouvait montrer qu'elle changeait quoi que ce soit* |
   | `rfc` | `uid` | `entryUUID` | recherche `member=<DN>` ou `uniqueMember=<DN>` (sans imbrication) | — (l'annuaire refuse le bind) |

3. **La connexion, dans cet ordre** — chaque étape qui échoue est un refus :
   1. le nom (1 à 256 caractères, sans caractère de contrôle) et un mot de passe **non vide** — un bind avec un mot de passe vide est un bind *anonyme* que l'annuaire accepte (RFC 4513 §5.1.2) : refusé avant le réseau ;
   2. le compte de service cherche l'utilisateur sous `LDAP_USER_BASE_DN`, le nom **échappé** (RFC 4515) — **exactement une** entrée, sinon refus ;
   3. une **nouvelle connexion** se lie avec le DN trouvé et le mot de passe donné : c'est l'annuaire qui vérifie le mot de passe ; OpenBastion ne le garde ni ne le compare ;
   4. le compte de service cherche les groupes du DN ; la table des rôles les traduit ; **aucun rôle : `403`, aucun compte créé** (comme ADR-0035) ;
   5. le compte `ldap:<identifiant stable>` est trouvé ou créé, ses rôles **remplacés** par ceux du jour ; le jeton est émis.
4. **Les refus** : nom inconnu, plusieurs entrées, mot de passe faux, compte désactivé — `401` identique, sans dire lequel. Annuaire injoignable, StartTLS refusé, certificat d'une autre autorité, compte de service refusé, réponse illisible — `503`, la cause au journal du service, **jamais** de repli sur un compte local. Délai de 5 s par opération. **Un annuaire muet au démarrage n'arrête pas le service** (ajouté à l'implémentation) : la connexion locale, la porte de l'administrateur, reste ouverte ; le journal le dit et la route répond `503`.
5. **Rien n'est écrit** : ni le mot de passe de l'utilisateur, ni celui du compte de service, dans une erreur ou un journal ; ni le nom de connexion (aucune ligne de journal ne le porte).
6. **L'Admin UI** propose « Annuaire de l'entreprise » (par défaut) et « Compte local » quand la Gateway le déclare (`GET /auth/ldap` → `{enabled}`, publique, gardé 30 s par la Gateway).

**Conséquences**

- (+) **Mesuré, avant** (sur `f4ca8a7`, processus réels, OpenLDAP et Samba AD réels) : l'Authentication Service démarre en ignorant toute la configuration LDAP, et aucune connexion par annuaire n'aboutit (90 s d'attente sur les deux annuaires).
- (+) **Mesuré, après** — les deux annuaires construits depuis `debian:13-slim` épinglée (paquets Debian `slapd` et `samba`), TLS avec une autorité que le test fabrique :
  - **OpenLDAP** (`ldap://` + StartTLS, schéma `rfc`) : `alice` (`groupOfNames`) reçoit `[platform-admin]`, `bob` (`groupOfUniqueNames`, clé de la table écrite `CN=DBAs, OU=Groups…`) reçoit `[dba]`, chacun en `ldap:<entryUUID>` ; ni `alice` ni ce compte ne se connectent par `/auth/login` ; **`401`** pour un mot de passe faux, vide, un nom inconnu, `alic*` (avec le mot de passe d'alice), `alice)(uid=*`, un nom porté par deux entrées, le mot de passe d'un autre ; **`403`** pour `carol`, sans groupe déclaré ; **`503`** avec une autre autorité, un compte de service refusé, l'annuaire en pause ; budget par adresse : `[401 401 429]` ; aucun des mots de passe dans les journaux ; six configurations refusées au démarrage.
  - **Samba AD** (`ldaps://`, schéma `ad`) : `alice`, membre de `bastion-ops` lui-même membre de `bastion-admins`, reçoit `[platform-admin]` **par l'imbrication**, en `ldap:<objectGUID>` — le GUID que `samba-tool` affiche ; `dave`, désactivé et membre direct des administrateurs, `401` ; mot de passe faux, vide, `alic*` : `401` ; `carol` : `403`.
  - En unitaire : le cas d'usage (5 tests : rôles de la table seulement, aucun compte sans rôle, six entrées refusées **sans** que l'annuaire soit interrogé, un annuaire muet n'est pas un refus, désactivé par défaut) ; l'adaptateur (4 tests : quinze configurations refusées sans le mot de passe dans le message, comparaison des DN, ordre des octets d'`objectGUID`, **le premier message sur `ldap://` est la demande StartTLS** — sans elle, le bind du compte de service partait en clair, mot de passe compris, mesuré par la contre-épreuve) ; l'Admin UI (3 tests, et un test existant rendu indépendant de l'ordre des appels, contre-épreuve faite).
- (+) **13 mutations : 12 tuées, la treizième a fait retirer du code.** Celle qui survivait retirait le contrôle préalable d'un compte AD désactivé : l'annuaire refuse déjà ce bind, et le contrôle a été retiré plutôt que gardé sans preuve. « Pas de StartTLS » n'était d'abord tuée que par l'OpenLDAP de test, qui exige TLS ; le test du premier message la tue désormais de notre côté.
- (+) **Trouvé en chemin** : dans l'Admin UI, un effet basculait le choix sur « Annuaire » après l'affichage ; un clic sur « Compte local » dans cet intervalle était perdu, et l'utilisateur se connectait par l'annuaire — le choix est désormais calculé, pas posé par un effet (le test qui l'a trouvé échouait sur l'ancienne forme). Et mon premier test démarrait le service avant que `slapd` soit prêt.
- (−) **Le temps de réponse trahit l'existence d'un nom** : un nom inconnu ne fait pas de bind. Un faux bind pour égaliser compterait, sous AD, comme un échec sur un vrai compte (verrouillage) ; la borne par adresse de la Gateway reste la protection.
- (−) **Les échecs comptent pour le verrouillage de l'annuaire** : qui connaît un nom peut, par la Gateway, consommer ses essais (une par minute et par adresse après la rafale) ; la politique de verrouillage est celle de l'annuaire.
- (−) Une connexion n'est pas écrite à l'audit — comme la connexion locale et OIDC aujourd'hui.
- (−) Les rôles valent jusqu'à la fin du jeton : un départ de l'annuaire coupe la **prochaine** connexion, pas le jeton en cours (comme ADR-0035).
- (−) Ni Kerberos, ni NTLM, ni authentification par certificat ; ni référence d'annuaire suivie (`referral`) ; un seul annuaire ; pas de groupes imbriqués en `rfc`.
- (−) Une dépendance externe de plus dans le module `authentication` (et sa surface : un analyseur BER), surveillée par `govulncheck` et Dependabot.

**Alternatives envisagées**

- **Le même `/auth/login`, essayé en local puis dans l'annuaire** : un même nom aurait deux mots de passe valables pour deux comptes différents, et l'ordre déciderait lequel ; une route par source ne mélange rien.
- **Lier directement avec un DN construit depuis le nom** (`uid=<nom>,<base>`) : pas de compte de service, mais le nom entre dans un DN (injection), et AD lie par `userPrincipalName`, pas par un DN prévisible.
- **Synchroniser l'annuaire (SCIM, import)** : prévu ailleurs dans la v1.0 ; ne remplace pas la vérification du mot de passe par l'annuaire.
- **Un client LDAP maison** : écarté par Bony Kiss au profit de `go-ldap` — un analyseur BER maison dans le chemin d'authentification.
- **Les attributs réglables** (`LDAP_USER_FILTER`, `LDAP_ID_ATTRIBUTE`…) : plus souple, mais un filtre libre est une injection écrite par l'exploitant, et un identifiant mal choisi (un nom qui change) rattache un compte à quelqu'un d'autre ; deux schémas fixes couvrent AD et OpenLDAP.
