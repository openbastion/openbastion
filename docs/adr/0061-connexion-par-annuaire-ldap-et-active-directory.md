# ADR-0061 — Un utilisateur d'annuaire (LDAP ou Active Directory) se connecte avec son mot de passe d'annuaire ; seuls ses groupes déclarés lui donnent des rôles

**Statut** `Proposé` · 31 octobre 2026 · premier lot de la v1.0, choisi par Bony Kiss le 31 octobre 2026 (avec `go-ldap` v3.4.15 et des tests contre OpenLDAP et Samba AD) ; `Accepté` seulement avec son go sur ce texte

**Contexte** — OpenBastion connaît deux sortes de comptes : locaux (un mot de passe Argon2id ici) et fédérés par OIDC (ADR-0035). Une entreprise dont les identités sont dans un annuaire — Active Directory le plus souvent, OpenLDAP ailleurs — doit aujourd'hui recréer chaque opérateur à la main, et lui donner un second mot de passe qu'aucun départ ne révoque. La feuille de route met LDAP/AD en tête de la v1.0 (`docs/roadmap.md` §6 : les pilotes en AD pur sont bloqués). La bibliothèque standard Go n'a pas de client LDAP : `github.com/go-ldap/ldap/v3` v3.4.15 (MIT ; tire `asn1-ber` MIT, `go-ntlmssp` MIT, `google/uuid` BSD-3) est accordée pour le seul module `authentication`.

Invariants touchés : l'identité qui décide est celle que le service vérifie, jamais un nom que le client choisit (comme `oidc:<sub>`, ADR-0035) ; défaut strict ; aucun secret au journal.

**Décision**

1. **Une route à part** : `POST /auth/ldap/login` (Gateway, publique, dans le **même budget par adresse** que `/auth/login`) → `POST /auth/v1/ldap/login` (Authentication, réservée à `api-gateway`). Même corps que `/auth/login` (`username`, `password`), même réponse (le jeton OpenBastion). `/auth/login` ne change pas : il ne consulte jamais l'annuaire.
2. **Désactivée par défaut, tout ou rien** :

   | Variable | Rôle |
   |---|---|
   | `LDAP_URL` | `ldaps://dc.example:636`, ou `ldap://…` **avec StartTLS obligatoire** ; `ldap://` sans TLS seulement vers une adresse de bouclage (développement). |
   | `LDAP_CA_FILE` | Facultatif : l'autorité du certificat de l'annuaire. Jamais de vérification désactivée. |
   | `LDAP_SCHEMA` | `ad` ou `rfc` (OpenLDAP et compatibles) — fixe les attributs ci-dessous ; aucun attribut libre. |
   | `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD_FILE` | Le compte de service qui **cherche** (lecture seule) ; son mot de passe dans un fichier lisible par son seul propriétaire, relu à chaque connexion. |
   | `LDAP_USER_BASE_DN`, `LDAP_GROUP_BASE_DN` | Où chercher les utilisateurs et les groupes. |
   | `LDAP_ROLE_MAP_FILE` | La table des rôles : DN de groupe → rôles, le format et les règles d'ADR-0035 ; un groupe absent ne donne rien. |

   | `LDAP_SCHEMA` | Nom de connexion | Identifiant stable | Groupes | Compte désactivé |
   |---|---|---|---|---|
   | `ad` | `sAMAccountName` | `objectGUID` | recherche `member:1.2.840.113556.1.4.1941:=<DN>` (groupes **imbriqués**) | `userAccountControl` bit 2 : refusé avant le bind |
   | `rfc` | `uid` | `entryUUID` | recherche `member=<DN>` ou `uniqueMember=<DN>` (sans imbrication) | — (l'annuaire refuse le bind) |

3. **La connexion, dans cet ordre** — chaque étape qui échoue est un refus :
   1. le nom (1 à 256 caractères, sans caractère de contrôle) et un mot de passe **non vide** — un bind avec un mot de passe vide est un bind *anonyme* que l'annuaire accepte (RFC 4513 §5.1.2) : refusé avant le réseau ;
   2. le compte de service cherche l'utilisateur sous `LDAP_USER_BASE_DN`, le nom **échappé** (RFC 4515) — **exactement une** entrée, sinon refus ;
   3. une **nouvelle connexion** se lie avec le DN trouvé et le mot de passe donné : c'est l'annuaire qui vérifie le mot de passe ; OpenBastion ne le garde ni ne le compare ;
   4. le compte de service cherche les groupes du DN ; la table des rôles les traduit ; **aucun rôle : `403`, aucun compte créé** (comme ADR-0035) ;
   5. le compte `ldap:<identifiant stable>` est trouvé ou créé, ses rôles **remplacés** par ceux du jour ; le jeton est émis.
4. **Les refus** : nom inconnu, plusieurs entrées, mot de passe faux, compte désactivé — `401` identique, sans dire lequel. Annuaire injoignable, compte de service refusé, réponse illisible — `503`, la cause au journal du service, **jamais** de repli sur un compte local. Délai de 5 s par opération.
5. **Rien n'est écrit** : ni le mot de passe de l'utilisateur, ni celui du compte de service, dans une erreur ou un journal ; le nom de connexion n'apparaît qu'échappé (`webhook.SafeText`).
6. **L'Admin UI** propose « Annuaire » à côté du mot de passe local quand la Gateway le déclare (`GET /auth/ldap` → `{enabled}`, publique).

**Conséquences**

- (+) *À mesurer : rouge avant (la route n'existe pas), vert après contre OpenLDAP et Samba AD réels — connexion, rôles par groupe (imbriqué sous AD), refus (mot de passe faux, vide, compte désactivé, nom injecté `*)(uid=*`, deux entrées, aucun groupe déclaré), annuaire en `ldap://` distant refusé, mauvaise autorité refusée —, mutations.*
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
