# ADR-0023 — Chaque demande servie par la liste des demandes en attente s'enregistre avant d'être servie — et sans enregistrement, la liste n'est pas servie


**Contexte**
ADR-0021 et ADR-0022 ont laissé une seule divulgation hors de la trace : la liste des demandes break-glass en attente (ADR-0012), `GET /sessions?status=pending_approval`. Elle montre à un approbateur, pour chaque demande, ce qu'ADR-0021 trace quand on la lit par son identifiant : le demandeur, le compte privilégié, la durée et la **justification d'une urgence** (« enregistreur en panne pendant l'incident P1 »). J'ai écrit le test d'abord, sur processus réels (Authentication, Authorization, Audit derrière un espion qui peut tomber en panne, Session Broker, Gateway), et constaté qu'il échouait. Ce qui a été **mesuré** (8 sous-cas, **5 en échec avant**) :

- **Une liste servie ne laisse aucune trace.** Bob (politique `breakglass-approve:account:…`) liste les demandes : `200`, avec la justification ; l'espion d'audit a vu **zéro** événement. Cinq listes, deux demandes : zéro.
- **L'audit en panne ne change rien** : Bob reçoit toujours `200`, avec la justification, le compte et le demandeur.
- **Ce qui était déjà juste.** Le Gateway transmet déjà l'appelant vérifié (ADR-0012, règle 3), un appelant sans nom est déjà refusé, une page vide ne dit pas si des demandes existent, et une dépendance muette donne déjà `503` sans liste partielle. Il ne manquait que la trace.
- **Toute la liste passe par une politique.** Les demandes de l'appelant en sont exclues (ADR-0012) : il n'y a pas de lecteur « naturel », chaque demande servie l'est sur la force d'une politique — le cas qu'ADR-0021 rend fermé.

**Décision**
Sept règles.

1. **Chaque demande de la page servie est un événement** `session.listed` : `resource_type = session`, `resource_id` = l'identifiant de la demande, `success = true`, auteur = **l'appelant que le Gateway a vérifié**. Un événement *par demande*, pas un par liste : la question d'un enquêteur est « à qui cette justification a-t-elle été montrée ? », et elle se pose par session. Un nom d'action distinct de `session.read`, pour distinguer « vu dans une liste » de « ouvert par son identifiant ».
2. **Seulement ce qui est servi.** Les demandes de la page renvoyée — pas celles comptées dans `totalItems`, pas celles que le filtre d'autorité a écartées, pas les autres pages.
3. **Écrit avant de servir ; un seul événement qui ne s'écrit pas, et la page n'est pas servie** (`503`, le corps générique d'ADR-0012, la cause dans le journal du Broker). C'est la règle d'ADR-0021, et c'est cohérent avec ADR-0012 : jamais de liste partielle.
4. **Une page vide n'écrit rien, et ne dépend pas de l'audit** : elle ne divulgue rien. Un approbateur sans demande à décider peut interroger la liste sans remplir la trace.
5. **Pas de budget** : chaque liste servie écrit à nouveau (ADR-0021, règle 4).
6. **L'ordre est inchangé, l'audit vient en dernier** : appelant sans nom (`403`), break-glass éteint (page vide), store (`503`), Authorization par compte (`503`), pagination, **audit (`503`)**, puis la page est servie.
7. **Le Gateway, les schémas et le proto ne changent pas.** Le contrat OpenAPI de `GET /sessions` dit désormais que chaque demande servie est enregistrée avant de l'être, et que le `503` peut venir de l'audit.

**Conséquences**
- (+) **Il n'existe plus, dans le Broker et le Recorder, de lecture divulguante sans trace** : la session par son identifiant (ADR-0021), l'enregistrement (ADR-0022) et la liste (cet ADR) sont chacun un événement signé sous le nom de la personne authentifiée — le demandeur et le décideur d'une session mis à part (ADR-0021, règle 5).
- (+) **On peut répondre à « à qui cette justification d'urgence a-t-elle été montrée ? »** en cherchant la session dans l'audit.
- (+) **Mesuré** : *Avant* (processus réels, 5 sous-cas sur 8 rouges) : Bob liste — `200` avec la justification, zéro événement ; cinq listes de deux demandes — zéro ; audit en panne — `200` avec la justification, le compte et le demandeur. *Après*, sur processus réels : la demande servie à Bob est **un** événement `session.listed` en succès **sous son nom** (jamais sous celui du demandeur), ressource `session`, présent à l'instant où la réponse arrive ; une requête forgée `&callerId=<le demandeur>&actorRoles=platform-admin` est écrite sous le nom de Bob ; trois listes de deux demandes ajoutent trois événements par demande ; une page de taille 1 n'écrit que la demande servie ; la liste vide d'Alice (sans autorité) n'écrit rien, y compris l'audit en panne, où elle reste `200` ; l'audit en panne, Bob reçoit `503` sans la justification, le compte, le demandeur ni les identifiants, et rien n'est écrit ; l'audit revenu, la liste est servie avec un événement par demande ; la chaîne se vérifie ; le test d'ADR-0012 passe inchangé. En unitaire : les champs exacts, seulement la page servie, 25 listes = 25 événements, trois sortes de pages vides sans événement, rien de servi sans l'audit puis servi à son retour, rien d'écrit pour une liste non décidée (Authorization muette, appelant sans nom). **14 mutations, toutes tuées** (événement absent, panne ignorée, appelée refus, servie après une panne en milieu de page, écritures en arrière-plan, auteur demandeur, action `session.read`, type, ressource du compte, issue, toutes les demandes visibles au lieu de la page, un seul événement par liste, toute la lecture avant le filtre, un événement pour une page vide). La série d'ADR-0022 n'a pas été rejouée (son code n'a pas changé). Tests : 575 unitaires sans base (46 ignorés), 621 avec ; 52 PostgreSQL ; 41 d'intégration sans base (6 ignorés), 47 avec ; `go test -race` propre sur le Broker et sur les tests d'intégration de la liste.
- (−) **Une panne de l'Audit Service cache les urgences en attente à leurs approbateurs.** Ce n'est pas une capacité perdue : approuver une demande dépend déjà de l'audit (ADR-0011, fail-closed), et la notification d'ADR-0012 continue d'annoncer les demandes. Mais l'approbateur ne voit plus la file pendant la panne.
- (−) **Une interface qui interroge la liste écrit un événement par demande et par interrogation**, sans regroupement. Trois demandes en attente et une interrogation toutes les 30 secondes : six événements par minute et par approbateur. La borne est la limite par adresse du Gateway (ADR-0015) et le plafond de demandes par demandeur (ADR-0013).
- (−) **Les écritures sont séquentielles** : au plus `pageSize` appels à l'Audit Service (100) avant de servir une page de 100. Le port d'audit n'a pas d'écriture par lot.
- (−) **Une écriture qui échoue au milieu d'une page** laisse dans la trace les demandes déjà écrites, sans qu'elles aient été vues (on se trompe du côté de la trace, ADR-0021 règle 7).
- (−) **Une demande vue dans plusieurs listes successives** donne autant d'événements : on sait qu'elle a été montrée, et combien de fois, pas si elle a été lue.

**Alternatives envisagées**
- *Un seul événement par liste* (ressource « liste », sans identifiant) : rejeté — il ne dit pas quelles justifications ont été montrées, ce qui est la question.
- *Réutiliser `session.read`* : rejeté — on ne distinguerait plus une liste d'une lecture par identifiant.
- *Écrire aussi pour une page vide* : rejeté — rien n'est divulgué, et une interface d'approbateur sans demande écrirait à chaque interrogation.
- *Servir la liste au mieux quand l'audit est en panne* : rejeté — c'est la divulgation sans preuve qu'ADR-0021 a refusée ; et l'approbation, elle, dépend déjà de l'audit.
- *Écrire en parallèle* : repoussé — plus rapide, mais une page partiellement écrite dans un ordre quelconque ; à reconsidérer si une écriture par lot arrive au port d'audit.
- *Un budget* : rejeté (ADR-0021, règle 4).
