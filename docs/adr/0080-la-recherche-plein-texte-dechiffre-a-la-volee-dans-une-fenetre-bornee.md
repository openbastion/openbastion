# ADR-0080 — La recherche plein texte déchiffre à la volée, dans une fenêtre bornée, sans index en clair

**Statut** `Accepté`, mise en œuvre en cours · 7 novembre 2026 · go du propriétaire du projet le 7 novembre 2026 (« J'accepte ADR-0080 tel quel, go pour la mise en œuvre ») · amende la feuille de route (`Search Engine (OpenSearch)`, v0.0.1) et ADR-0022

**Contexte** — Un critère de sortie de la v0.0.1 (`docs/roadmap.md` §3) demande une « recherche plein texte opérationnelle sur commandes et sessions ». La feuille de route et `docs/architecture/system-overview.md` prévoient pour cela un Search Engine adossé à OpenSearch. Rien n'existe aujourd'hui, et trois faits du dépôt contredisent ce plan.

- **Les commandes ne sont jamais stockées en clair.** Le Command Recorder chiffre chaque commande (AES-256-GCM) sous une clé propre à sa session, elle-même enveloppée par la KEK, locale ou gardée par Transit (ADR-0049). La table ne contient que `command_sealed` (`services/recording-audit/command-recorder/migrations/001_init.sql`). Or une commande tapée contient parfois un secret : un mot de passe passé en argument, un jeton. Un index plein texte, OpenSearch ou `tsvector`, recopierait ce texte en clair dans un second système, hors de l'enveloppe.
- **Lire un enregistrement est autorisé session par session, et audité avant d'être servi.** La ressource RBAC est `recording:session:<id>`, l'action `recording:session:read` ; chaque page servie écrit `recording.read` d'abord, et sans audit rien n'est servi (ADR-0022). Une lecture de session divulguée écrit `session.read` d'abord, sans budget (ADR-0021). Une recherche transversale doit tenir ces deux règles pour chaque session dont elle montre quelque chose.
- **Il n'existe aucune liste générale des sessions.** L'API publique ne liste que les demandes break-glass en attente (`GET /sessions?status=…`, ADR-0012) ; les métadonnées (demandeur, compte, protocole, dates, justification, ticket) sont en clair dans la base du Session Broker.

**Mesuré** (7 novembre 2026, benchmark jetable dans le paquet de l'enveloppe, Intel Core Ultra 5 135U, 6 cœurs, trois passages) : désenvelopper la clé d'une session par la KEK locale, déchiffrer ses commandes et y chercher une sous-chaîne coûte **0,8 à 1 ms pour 500 commandes** et **0,05 à 0,12 ms pour 50**, soit 1,1 à 2,5 µs par commande, CPU seul. Ne sont **pas** mesurés : la lecture en base, et le désenveloppement par Transit, qui est un appel réseau par session.

Invariants touchés : un secret n'est jamais en clair hors de son enveloppe ; enregistrer ou refuser ; l'audit précède la divulgation (ADR-0021, ADR-0022) ; défaut strict.

**Décision**

1. **Pas d'index, pas de copie en clair, pas de nouveau service.** La recherche des commandes est faite par le Command Recorder, qui déchiffre à la volée les sessions candidates et y cherche le texte demandé, puis jette le clair. Aucun moteur de recherche, aucune colonne `tsvector`, aucun index aveugle n'est ajouté. Le Search Engine OpenSearch de la feuille de route est retiré de la v0.0.1 (point 9).
2. **La recherche des commandes** : `GET /recordings/search?q=…&from=…&to=…`, sur la Gateway, relayée au Command Recorder.
   - `q` : 3 à 256 caractères, cherchés comme **sous-chaîne, sans tenir compte de la casse** (Unicode, après normalisation NFC). Pas d'expressions régulières, pas de jokers.
   - `from` et `to` : la fenêtre, obligatoire, **31 jours au plus**. Les sessions candidates sont celles dont l'enregistrement a commencé dans la fenêtre.
   - **Au plus 200 sessions candidates** par recherche, les plus récentes d'abord ; au-delà, la réponse le dit (`truncated: true`) et demande une fenêtre plus étroite. Rien n'est cherché au-delà de la borne.
   - La réponse donne, par session qui a au moins une correspondance : l'identifiant de la session, et les commandes correspondantes avec leur horodatage, **50 au plus par session**. Pas de contexte autour d'une commande : le reste se lit par la lecture d'enregistrement existante.
3. **L'autorisation, session par session, avant tout déchiffrement.** Pour chaque session candidate, le Command Recorder demande `recording:session:read` sur `recording:session:<id>`, comme pour une lecture. Une session refusée n'est **pas déchiffrée** et n'apparaît pas dans la réponse ; les refus ne sont pas écrits un par un (ce n'est pas une lecture tentée sur une session nommée), mais leur nombre l'est (point 4). L'Authorization Service muet : `503`, rien n'est cherché.
4. **L'audit avant, et fail-closed.**
   - **Avant tout déchiffrement**, un événement `recording.search` (acteur : l'appelant vérifié ; ressource `recording_search`) porte en détails la fenêtre, le nombre de sessions candidates, autorisées et refusées, et une empreinte HMAC-SHA-256 de `q` (normalisé comme au point 2) sous une clé propre au Command Recorder, `SEARCH_AUDIT_KEY_FILE` (fichier `0600`, 32 octets). Sans elle, la recherche est désactivée (`404`), jamais servie sans empreinte. **Le texte cherché n'est jamais dans la chaîne** : un auditeur peut chercher un mot de passe, qui n'a pas à y rester. L'empreinte permet de prouver, après coup et avec la clé, qu'une recherche donnée a été faite. L'audit muet : `503`, rien n'est déchiffré.
   - **Pour chaque session qui a des correspondances**, un événement `recording.read` (ADR-0022) est écrit **avant** que la réponse soit servie : la recherche divulgue des commandes de cette session. Un seul manque, et la réponse entière n'est pas servie (`503`).
   - Une session sans correspondance ne divulgue rien de ses commandes ; elle n'écrit pas de `recording.read`. Qu'elle a été parcourue est dans les compteurs de `recording.search`.
5. **La recherche des sessions** : `GET /sessions/search?q=…&from=…&to=…`, au Session Broker, sur les métadonnées seulement.
   - `q` cherché comme sous-chaîne sans casse dans le demandeur, le compte privilégié, la justification et le ticket. Filtres facultatifs : `status`, `protocol`, `requested_by`, `privileged_account_id`, `break_glass`.
   - Même fenêtre (31 jours au plus) ; **50 sessions par page**.
   - L'autorisation est celle de la lecture d'une session : `session:read` sur le compte de chaque session (ADR-0021). Une session non autorisée n'est pas servie.
   - **Chaque session servie écrit `session.read` avant d'être servie**, sans budget (ADR-0021, règle 4). Un seul manque : `503`, rien n'est servi.
   - Ces métadonnées sont déjà en clair dans la base du Broker : une requête SQL bornée (`ILIKE` dans la fenêtre) suffit, sans index plein texte. Aucun index sur `sessions.created_at` n'existe aujourd'hui : une migration idempotente l'ajoute. Côté Command Recorder, la fenêtre se lit sur `session_recording_keys.created_at`, que la même tranche indexe aussi.
6. **Les bornes sont des constantes du code**, pas des réglages : une fenêtre, un nombre de sessions et une longueur de `q` qu'un opérateur pourrait élargir à volonté feraient d'une recherche une exfiltration en masse.
7. **Rien d'autre ne change** : la lecture d'un enregistrement (ADR-0022), d'une session (ADR-0021), le chiffrement et la rotation des clés (ADR-0049, ADR-0055). Le Video Recorder n'est pas concerné : un flux écran n'a pas de texte.
8. **L'Admin UI** propose les deux recherches, avec la fenêtre obligatoire, et affiche la troncature quand elle a lieu. Une commande trouvée ouvre la lecture de son enregistrement.
9. **La feuille de route et l'architecture sont mises à jour** : le Search Engine (OpenSearch) quitte la v0.0.1. Il ne reviendrait qu'avec une autre décision, qui dirait comment indexer sans copier en clair (par exemple un index chiffré, ou un index aveugle avec la rotation de sa clé).

**Preuve attendue** (processus réels, sous PostgreSQL, avec un vrai Audit Service ; chaque test avec sa contre-épreuve) :

- une commande tapée dans une session SSH réelle est trouvée par une sous-chaîne, sans casse ; aucune autre table ni aucun fichier ne contient son texte en clair après la recherche ;
- un appelant sans politique sur une session ne la voit pas dans les résultats, et elle n'est pas déchiffrée (compteur de désenveloppement) ;
- l'audit coupé : `503`, et rien n'est déchiffré ; une correspondance dont le `recording.read` ne s'écrit pas : `503`, rien n'est servi ;
- `recording.search` porte l'empreinte de `q`, jamais `q` ; le texte cherché n'est dans aucun journal ;
- une fenêtre de plus de 31 jours, un `q` de moins de 3 caractères : `400` ; plus de 200 sessions candidates : `truncated: true`, et les suivantes ne sont pas déchiffrées ;
- la recherche des sessions : un titulaire de politique sur un compte trouve ses sessions par la justification ou le ticket, pas celles d'un autre compte, et chaque session servie est un `session.read` dans la chaîne.
- Mesure, avec Transit réel (ADR-0049) : le temps d'une recherche à la borne de 200 sessions.

**Conséquences**

- (+) Aucun texte de commande ne sort de son enveloppe vers un stockage : la propriété du Command Recorder est gardée telle quelle.
- (+) Pas de nouveau composant à opérer, à sécuriser, à sauvegarder ou à restaurer : ni cluster, ni index à reconstruire après une restauration ou une rotation de clés.
- (+) Chaque divulgation par la recherche est un événement de la chaîne, sous le nom de l'appelant vérifié, comme une lecture.
- (−) **Pas de recherche sur tout l'historique** : 31 jours et 200 sessions par recherche. Fouiller un an demande douze recherches, chacune auditée. C'est voulu, mais c'est un coût pour un auditeur.
- (−) **Le coût croît avec les sessions parcourues** : chaque recherche désenveloppe jusqu'à 200 clés. Avec Transit, ce sont jusqu'à 200 appels réseau, **non mesurés** ici ; le temps de réponse en dépend. Transit sait déchiffrer par lot (`batch_input`), ce qui serait une optimisation à mesurer, pas une décision.
- (−) **Sous-chaîne seulement** : pas de racinisation, pas de recherche floue, pas de classement par pertinence.
- (−) **Le critère de sortie est reformulé** : « opérationnelle » veut dire ici bornée dans le temps et dans le nombre de sessions. Le propriétaire doit dire si cela le remplit.
- (−) La justification et le ticket restent cherchables en clair, comme ils sont déjà lisibles en clair : la recherche des sessions n'ajoute aucune exposition, mais elle rend la lecture plus facile, d'où l'audit de chaque session servie.
- (−) Une session sans correspondance a été déchiffrée en mémoire sans `recording.read` ; seuls les compteurs de `recording.search` le disent.
- (−) L'empreinte de `q` permet de confirmer une recherche supposée, avec la clé, mais pas de retrouver ce qui a été cherché sans elle. Un `q` court et courant (`root`) se retrouve par dictionnaire **pour qui a la clé** : elle se garde comme un secret.
- (−) **Un secret de plus à fournir et à sauvegarder** : `SEARCH_AUDIT_KEY_FILE`. Perdue, les empreintes passées ne peuvent plus être confirmées ; la chaîne, elle, reste vérifiable.

**Mise en œuvre** (7 novembre 2026), en trois incréments : (1) les commandes — fait ; (2) les sessions — fait ; (3) l'Admin UI.

- **Incrément 1, les commandes** : `GET /recordings/search` (Gateway) → `GET /recorder/v1/search` (Command Recorder, appelable par la Gateway seule). Migration `002_search_window.sql` (index de la fenêtre). La normalisation NFC et le repli de casse viennent de `golang.org/x/text`, déjà dans l'espace de travail (Gateway, Video Recorder), devenu une dépendance directe du Command Recorder.
- **Précisions, sans changer la décision** :
  - **une borne de plus** : 1 000 commandes par réponse. Sans elle, 200 sessions de 50 commandes de 8 Kio feraient 80 Mo ; au-delà, `truncated` ;
  - **une session dont la KEK n'est plus détenue fait échouer toute la recherche** (`500`), plutôt que d'être sautée : une recherche qui sauterait une session en silence pourrait cacher une preuve ;
  - le `recording.read` d'une session trouvée porte le détail `search_id` ; la ressource de `recording.search` est l'identifiant de la recherche, rendu dans la réponse ;
  - le texte cherché et la cause d'un échec ne sont jamais dans la réponse ni dans les journaux.
- **Mesuré** :
  - application : 7 tests, 6 mutations sur 6 tuées (autorisation retirée, texte au lieu de l'empreinte, pas de `recording.read` par session divulguée, pas de borne des sessions, casse conservée, audit écrit après le déchiffrement) ;
  - magasins : le contrat de la fenêtre et du parcours, en mémoire et sous PostgreSQL ;
  - processus réels (`test/integration/recording_search_flow_test.go`, sous PostgreSQL, vrai Audit Service derrière un espion) : 7 sous-tests verts. Ils couvrent la sous-chaîne sans casse, une politique sur une seule session, le texte cherché absent de la chaîne et des journaux, l'audit coupé (`503`), les bornes (`400`), aucune commande en clair dans aucune colonne du Recorder, et `404` sans clé. La mutation « autorisation retirée » y est tuée. **Les commandes sont enregistrées par la route du Recorder, comme le fait le proxy SSH : aucune n'est tapée dans une vraie session SSH** ;
  - **avec Transit réel** (OpenBao local, ADR-0049) : une recherche de 200 sessions × 50 commandes prend **1,08 à 1,52 s** (trois passages), autorisation de chaque session et audit compris.

- **Incrément 2, les sessions** : `GET /sessions/search` (Gateway) → `GET /sessions/search` (Session Broker), migration `005_search_window.sql`. Précisions, sans changer la décision :
  - **qui voit une session est qui peut la lire** (`GetSession`, ADR-0021) : son demandeur et celui qui l'a décidée, sans politique et **sans événement** (ils n'apprennent rien) ; les autres au titre d'une politique sur son compte, et chacune de ces sessions est un `session.read` écrit avant la réponse. L'ADR disait « chaque session servie » : c'est la règle 4 d'ADR-0021, qui ne vise que les lectures au titre d'une politique ;
  - `q` est **facultatif** (toutes les sessions de la fenêtre, avec les filtres) ; présent, 3 à 256 caractères. Il est cherché par `ILIKE … ESCAPE '\'`, `%`, `_` et `\` échappés ;
  - **une page regarde au plus 500 sessions** : sans cette borne, chercher dans des comptes qu'on ne peut pas lire parcourrait toute la fenêtre. Au-delà, la page s'arrête et `next` (curseur opaque : la date de création et l'identifiant) dit où reprendre ;
  - l'autorisation est demandée **une fois par compte et par page** ; le filtre `status` porte sur le statut effectif (une session échue est `expired`) ;
  - les refus ne sont pas écrits un par un, comme pour les commandes (point 3).
- **Mesuré, incrément 2** :
  - application : 7 tests, 5 mutations sur 5 tuées (autorisation retirée, pas de `session.read`, demandeur soumis à une politique, reste d'un lot perdu, pas de borne des 500) ;
  - magasins : le contrat (jokers neutralisés, sans casse, ticket, demandeur, filtres, ordre, égalités, curseur, limite), en mémoire et sous PostgreSQL ; la mutation « échappement retiré » est tuée sous PostgreSQL ;
  - processus réels (`test/integration/session_search_flow_test.go`, de vraies sessions créées par la Gateway) : 5 sous-tests verts, et la mutation « autorisation retirée » y est tuée.

**Alternatives envisagées**

- **OpenSearch, comme prévu** : écartée pour cette tranche. Les commandes y seraient en clair, hors de l'enveloppe, dans un système de plus à protéger, sauvegarder et restaurer. Ses contrôles d'accès ne sont pas ceux d'OpenBastion : l'autorisation par session et l'audit avant divulgation seraient à reconstruire devant lui.
- **Un index plein texte PostgreSQL** (`tsvector`) **sur les commandes** : écartée pour la même raison. Le texte serait en clair dans la base du Recorder, à côté de son chiffré.
- **Un index aveugle** (HMAC de chaque mot sous une clé du KMS) : écartée pour l'instant. Il ne trouve que des mots exacts (pas `shadow` dans `/etc/shadow`). Il révèle à qui lit la base quels mots se répètent et où. Et une rotation de sa clé demande de tout déchiffrer pour reconstruire l'index. À reconsidérer si les bornes du point 2 s'avèrent insuffisantes.
- **Des bornes réglables par l'opérateur** : écartée (point 6).
- **Écrire `q` en clair dans l'audit** : écartée. Un auditeur qui cherche un mot de passe l'écrirait pour toujours dans la chaîne, qui ne s'efface pas (ADR-0031).
- **Un `recording.read` pour chaque session parcourue, avec ou sans correspondance** : écartée. Il dirait une lecture qui n'a rien divulgué, et noierait la chaîne : 200 événements par recherche.
