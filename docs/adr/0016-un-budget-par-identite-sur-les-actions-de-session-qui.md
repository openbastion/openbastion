# ADR-0016 — Un budget par identité sur les actions de session qui écrivent à chaque appel (`approve`, `reject`, `connect`)


**Contexte**
ADR-0014 a mis un budget par identité sur `POST /sessions` et consigné que les autres routes de session « ne dépendent que de la limite par adresse ». J'avais proposé d'étendre ce budget à `approve`, `reject`, `connect`, `terminate` et à la liste des demandes en attente. Avant de le faire, j'ai lu ce que chacune **écrit ou appelle** quand elle est refusée ou répétée, parce qu'un budget n'a de sens que là où un appel répété coûte quelque chose :

| Route | À chaque appel |
|---|---|
| `POST /sessions/{id}/approve`, `…/reject` | Un refus « qui dit quelque chose de l'appelant » (auto-approbation, aucune politique d'approbation, break-glass désactivé ou hors limite) écrit un **événement d'audit** (`session.breakglass_approved` / `_rejected`, `success=false`), après un appel à l'Authorization Service. Un appelant qui connaît l'identifiant d'une session — la sienne, par exemple — peut donc faire écrire autant d'événements qu'il peut envoyer de requêtes. |
| `POST /sessions/{id}/connect` | Pour son demandeur, sur une session active : un **scope du Vault**, un **ticket du proxy** et un **événement d'audit** (`session.connect`) à chaque appel, sans limite de nombre pendant la durée de la session. Pour un autre appelant, ou sur une session non active : un refus, sans écriture. |
| `DELETE /sessions/{id}` (terminate) | Une écriture, **une fois** par session : l'appel suivant est un conflit, sans écriture. |
| `GET /sessions/{id}`, `GET …/recording`, `GET /sessions?status=pending_approval` | **Aucune écriture.** La liste interroge l'Authorization Service une fois par compte distinct en attente ; l'enregistrement, le Command Recorder. |

L'attaquant réaliste n'est donc pas « n'importe qui » : un refus de création ne révèle pas l'identifiant de la session, il faut en détenir une (une demande acceptée ou en attente). C'est un titulaire de jeton qui a **un** droit, par exemple celui de demander un accès — un compte compromis, pas un inconnu.

Deux questions : (1) **sur quelles routes** mettre un budget, et avec quelle clé ; (2) **comment** l'ajouter sans que changer de route donne un budget neuf, et sans gêner l'enchaînement normal « demander puis se connecter ».

**Décision**
Six règles.

1. **Le budget suit le coût, pas la symétrie.** Il couvre les trois routes qui écrivent à **chaque** appel : `approve`, `reject` et `connect`. Il ne couvre **pas** `terminate` (une écriture par session, bornée par le nombre de sessions — *amendé par ADR-0017 : dès que `terminate` refuse et audite chaque appelant sans autorité, il écrit à chaque appel et rejoint ce seau*) ni les lectures (aucune écriture — *confirmé par ADR-0019 : un refus de lecture n'écrit rien non plus — puis amendé par ADR-0020 : il écrit, mais sous un budget propre, dans le Broker, et les lectures restent hors de ce seau-ci*) : y mettre un budget limiterait des interfaces qui interrogent l'état à intervalles réguliers, pour borner quelque chose qui ne coûte rien à écrire.
2. **Un seau par utilisateur pour les trois, pas un par route**, et **distinct** de celui de `POST /sessions` (ADR-0014). Pas un par route : changer de route ne doit pas donner un budget neuf. Distinct : « demander puis se connecter » est un enchaînement normal, et un utilisateur qui vient d'épuiser ses demandes ne doit pas perdre le droit de se connecter à une session déjà accordée — en urgence surtout.
3. **La clé est l'identité vérifiée, et le compte se fait avant tout travail.** Comme en ADR-0014 : le `UserID` issu du jeton, jamais l'adresse ni le corps (ces routes ne lisent pas le corps du client). Chaque `POST` sur une de ces actions coûte un jeton, accepté ou non, **avant** que le Broker ne soit appelé : une action refusée par le budget n'atteint ni le Broker, ni le Vault, ni le proxy, et n'écrit **aucun événement d'audit**. Une méthode non permise (`405`) ou un chemin inconnu (`404`) ne coûte rien.
4. **Défauts stricts, bornes, pas d'« illimité » :** `SESSION_ACTION_BURST` (défaut **10**, de 1 à 1000) et `SESSION_ACTION_RATE_PER_MINUTE` (défaut **6**, de 1 à 600) ; valeur invalide fatale en nommant la variable ; un Gateway construit à la main applique les défauts ; annonce au démarrage.
5. **`429` avec un `Retry-After` vrai** (secondes, arrondies au-dessus, au moins 1), message **distinct** de celui de `POST /sessions` et de ceux du Broker (« too many session actions from this user … ») : un client sait quel budget il a épuisé. **Une ligne de journal par utilisateur et par épisode de refus**, jamais une par requête, jamais le jeton ; rien dans l'audit (ADR-0014, règle 5).
6. **Par processus**, comme les autres budgets du Gateway.

Réponses : les trois routes ajoutent le `429` du Gateway, avec `Retry-After`. Aucun changement du Broker ni du schéma.

**Conséquences**
- (+) Un titulaire de jeton ne fait plus écrire que le débit de son seau — 10 en rafale, puis 6 par minute (8 640 par jour au plus) — en événements d'audit (`approve`/`reject` refusés) et en scopes Vault, tickets proxy et événements d'audit (`connect`), au lieu de « ce que le réseau laisse passer ». Les refus du budget n'écrivent rien.
- (+) Le budget est celui de l'identité : le bruit d'un utilisateur ne retire rien aux autres.
- (+) **Mesuré** (processus réels : Authorization, Authentication, Audit, Session Broker, trois Gateways) : **sans budget**, 6 approbations refusées et 6 rejets refusés écrivent **12 événements d'audit** ; avec une rafale de 3, huit approbations d'affilée n'en écrivent que **3**, les cinq autres sont des `429` qui n'atteignent pas le Broker ; `reject` et `connect` sont ensuite refusés par le même seau ; un autre utilisateur a le sien. 44 mutations : 43 détectées, 1 équivalente (le budget d'actions emprunte les défauts de `POST /sessions` : valeurs identiques, aucun test ne peut les distinguer).
- (−) **Un jeton volé peut priver son titulaire de ses actions** : un jeton se reforme toutes les 10 secondes, il va à qui arrive le premier. C'est le cas d'**urgence** qui pèse le plus ici : un attaquant qui détient le jeton d'un approbateur ou d'un demandeur peut épuiser son budget pendant l'incident. Le remède est de révoquer le jeton. Même nature qu'ADR-0013 et ADR-0014.
- (−) **Un utilisateur légitime très actif est ralenti** : plus de 10 décisions ou connexions d'un coup, ou plus de 6 par minute en continu, reçoivent des `429`. C'est le prix du budget ; les valeurs sont choisies, non mesurées sur un usage réel, et se règlent. Le seau est partagé entre toutes ses sessions : un script qui en ouvre vingt d'un coup est ralenti.
- (−) **`terminate` et les lectures ne sont pas couverts** (`terminate` l'est depuis ADR-0017) : ils ne dépendent que de la limite par adresse. La liste des demandes en attente peut coûter à l'Authorization Service un appel par compte distinct ; elle n'écrit rien. `terminate` n'a toujours ni contrôle d'appartenance ni politique propre (limite connue) : le budget n'y change rien.
- (−) **Les refus du budget ne sont pas dans l'audit**, seulement dans le journal du Gateway.
- (−) **Le jeton est pris avant de savoir ce que le Broker dira** : un `connect` d'un autre utilisateur, qui ne ferait aucune écriture, coûte un jeton quand même. C'est le prix d'un compte fait avant tout travail.
- (−) **Plusieurs identités, plusieurs budgets** ; **par processus** : N réplicas, N fois le budget.

**Alternatives envisagées**
- *Un budget par route* : rejeté — passer de `approve` à `reject` à `connect` donnerait un budget neuf à chaque fois.
- *Un seul seau avec `POST /sessions`* : rejeté — il ferait perdre à un utilisateur le droit de se connecter parce qu'il a trop demandé, y compris en urgence.
- *Un budget par session* : rejeté — le coût est celui de l'utilisateur sur l'ensemble de ses sessions ; borner chacune laisse la somme libre.
- *Budget sur `terminate` et sur les lectures aussi* : rejeté ici — ils n'écrivent pas à chaque appel ; ce serait limiter des interfaces qui interrogent l'état pour borner un coût nul. À reconsidérer si une mesure montre une charge de lecture sur l'Authorization Service.
- *Un seul `connect` par session* : rejeté — se reconnecter après une coupure est légitime, et cela changerait la sémantique de l'API.
- *Auditer chaque refus du budget* : rejeté — recrée le flux d'écritures qu'on veut borner (ADR-0014).
