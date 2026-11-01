# ADR-0064 — Les connexions et les gestes d'administration du second facteur sont écrits à l'audit ; un jeton n'est émis qu'une fois sa connexion écrite

**Statut** `Proposé` · 1ᵉʳ novembre 2026 · troisième lot de la v0.0.1, recommandé après ADR-0062 ; `Accepté` seulement avec le go de Bony Kiss sur ce texte, et ses réponses aux deux questions du § Décision

**Contexte** — L'Authentication Service n'écrit rien à l'audit : ni qui s'est connecté, ni quand, ni par quelle source, ni qu'un administrateur a émis un code d'enrôlement ou remis à zéro un second facteur (ADR-0062 l'a noté comme sa première limite). Pour un PAM, c'est un trou : on sait qui a ouvert une session sur une cible (Broker, proxy), pas qui a obtenu le jeton qui l'a permise ; et le geste qui permet de remplacer le second facteur d'un administrateur ne laisse qu'une ligne de journal, effaçable. Les autres services écrivent à l'audit par un client mTLS, sous leur identité de certificat (ADR-0027, `emitter`) ; l'Audit Service n'admet pas encore `authentication` comme émetteur.

Invariants touchés : **audit fail-closed** (« enregistrer ou refuser ») ; l'identité de l'émetteur vient de son certificat ; aucun secret dans l'audit.

**Décision**

1. **Un client d'audit** dans l'Authentication Service (`AUDIT_URL`, mTLS sous l'identité `authentication`), comme le Vault. L'Audit Service admet `authentication` sur `POST /audit/v1/emit-event`.
2. **Les événements** (aucun ne porte de mot de passe, de code, de défi ni de secret) :

   | Action | Quand | Acteur · ressource | `success` |
   |---|---|---|---|
   | `auth.login` | un jeton est émis sans second facteur | le compte · `account`/nom du compte — la source s'y lit (`ldap:<id>`, `oidc:<sub>`, sinon local) | `true` |
   | `auth.login_mfa` | un jeton est émis après le second facteur (vérification ou enrôlement) | le compte · `account`/nom du compte | `true` |
   | `auth.login_refused` | mot de passe faux, défi ou code refusé, annuaire qui refuse | — · `login`/nom de connexion tapé (borné à 256, désarmé) | `false` |
   | `auth.mfa_enrollment_code_issued` | `mfa enrollment-code` | l'identité du certificat (`admin-cli`) · `account`/source:nom | `true` |
   | `auth.mfa_enrolled` | la confirmation d'un enrôlement | le compte · `account`/nom | `true` |
   | `auth.mfa_reset` | `mfa reset` | `admin-cli` · `account`/nom | `true` |

3. **Les gestes d'administration sont fail-closed** : le code d'enrôlement n'est rendu, et la remise à zéro n'est faite, **qu'une fois l'événement écrit** ; audit injoignable → `503`, rien n'est fait. Comme le Vault (ADR-0055).
4. **Question 1 — une connexion réussie est-elle fail-closed ?** *Proposé : oui* — le jeton n'est émis qu'une fois `auth.login` écrit ; audit injoignable → `503`, **personne ne se connecte**, y compris l'administrateur local. C'est l'invariant « enregistrer ou refuser » appliqué à la porte d'entrée ; le prix est que l'audit devient une dépendance de toute connexion. *Alternative* : écrire après, au mieux, et continuer si l'audit ne répond pas (une connexion non tracée possible).
5. **Question 2 — les refus sont-ils écrits ?** *Proposé : oui, dans un budget* — `auth.login_refused` au mieux (un refus d'écrire un refus ne protège rien), dans un budget par nom de connexion (`pkg/refusalbudget`, ADR-0020, ADR-0024 : une rafale, puis un débit) pour qu'une force brute ne remplisse pas la chaîne ; au-delà, le refus n'est pas écrit, et c'est compté au journal. *Alternative* : ne pas écrire les refus (le journal de la Gateway garde les `401` et `429`).

**Conséquences**

- (+) *À mesurer : rouge avant (une connexion et une remise à zéro ne laissent rien dans la chaîne), vert après sur processus réels (connexions locale, annuaire et OIDC écrites, avec ou sans second facteur ; code d'enrôlement et remise à zéro écrits avant d'être faits, et refusés sans audit ; refus écrits dans leur budget ; aucun secret dans la chaîne ; l'émetteur est `authentication` d'après le certificat ; vérification de la chaîne), mutations.*
- (−) Si la question 1 est acceptée : **l'audit devient une dépendance de toute connexion** — une panne de l'Audit Service empêche toute connexion, l'accès d'urgence compris. Le break-glass (ADR-0009) dépend déjà de l'audit pour ouvrir une session ; ce lot étend la règle à l'obtention du jeton.
- (−) Les refus au-delà du budget ne sont pas dans la chaîne ; le budget est par processus (comme ADR-0020).
- (−) Le nom de connexion d'un refus est une chaîne que l'attaquant choisit : bornée et désarmée, elle reste une donnée qu'on lit avec prudence.
- (−) La vérification d'un jeton à chaque requête (`/auth/v1/verify`) n'est pas écrite : elle n'est pas une connexion.

**Alternatives envisagées**

- **Écrire la connexion dans la Gateway** : elle ne sait pas qui est le compte avant la réponse, ni par quelle source, ni si le second facteur a servi ; l'Authentication Service est celui qui décide.
- **Le journal du service seulement** (l'état d'ADR-0062) : effaçable, non chaîné, hors de la vérification d'intégrité.
- **Tout fail-closed, refus compris** : un attaquant qui coupe l'audit ferait refuser… des refus ; sans objet.
