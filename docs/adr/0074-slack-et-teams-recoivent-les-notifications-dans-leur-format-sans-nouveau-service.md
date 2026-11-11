# ADR-0074 — Slack et Teams reçoivent les notifications dans leur format, sans nouveau service

**Statut** `Accepté` · 6 novembre 2026 · go du propriétaire du projet le 6 novembre 2026 (« Accepté »), avec les trois choix qui lui étaient soumis : pas de nouveau service, pas d'approbation depuis une messagerie, secret du canal d'alertes maintenu

**Contexte** — Le premier critère de sortie de la v0.0.1 (`docs/roadmap.md`) demande une double validation « avec ticket obligatoire et notification Slack/Teams, de bout en bout ». La double validation et le ticket existent (ADR-0011, ADR-0067). La notification est un webhook JSON générique, dans deux services : le Session Broker (ADR-0012, ADR-0013) et l'Audit Service (ADR-0045), par `pkg/webhook`. ADR-0067 le note : « pas de message Slack ou Teams mis en forme ».

Ce qui ne va pas :

- **Teams.** Le corps est `{event, …, text}`. Microsoft indique que les connecteurs Office 365, webhooks entrants compris, ont été retirés en mai 2026, au profit de l'application Workflows, dont les webhooks attendent une carte adaptative ou un MessageCard. La documentation d'OpenBastion et ses commentaires citent encore Teams comme récepteur : c'est probablement faux aujourd'hui. **Non mesuré** : aucun espace Teams n'a été essayé.
- **Slack.** Le champ `text` est bien celui que lit un webhook entrant, mais le corps porte aussi des champs que Slack n'attend pas, et ceux-là ne passent pas par `SafeText`. **Non mesuré** non plus.

Ce qui existe déjà et ne change pas : l'URL traitée comme un secret et jamais écrite, aucune redirection suivie, `https` exigé, et `SafeText`, qui ne laisse passer que lettres, chiffres et `. _ : -` dans ce qu'une personne a écrit (ADR-0012, règle 9). Une mention ou un lien fabriqués sont donc déjà neutralisés dans `text`.

**Décision**

1. **Un format par canal, dans `pkg/webhook`, sans nouveau service.** `ALERT_NOTIFY_FORMAT` (Audit Service) et `BREAKGLASS_NOTIFY_FORMAT` (Session Broker) valent `generic` (défaut, comportement d'aujourd'hui inchangé, octet pour octet), `slack` ou `teams`. Toute autre valeur, ou un format sans URL : le service refuse de démarrer, et le message ne répète ni l'URL ni le secret.
2. **Les corps, exactement.**
   - `slack` : `{"text": "<phrase>"}`.
   - `teams` : l'enveloppe `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","text":"<phrase>","wrap":true}]}}]}`. Ni bouton ni action.
3. **Slack et Teams ne reçoivent que la phrase.** Elle n'est faite que de textes fixes, de nombres et de valeurs passées par `SafeText`. Les champs bruts du corps générique ne partent pas vers ces deux formats : moins de données vers un tiers, et rien qui échappe à `SafeText`. Le message continue de désigner sans raconter (ADR-0012, règle 7) : ni justification, ni rien de la cible.
4. **Un message n'est jamais une autorité.** Pas de bouton d'approbation, aucune route entrante depuis une messagerie. Approuver passe toujours par l'API authentifiée, sous la politique et la règle des deux personnes. Qui détient l'URL peut écrire un faux message dans le canal, mais ne peut rien décider.
5. **La livraison ne change pas.** Broker : un essai, jamais bloquant, jamais une condition d'accès (ADR-0012). Audit : jusqu'à 5 tentatives, file conservée (ADR-0045, ADR-0057). Tout `2xx` vaut livré, le `202` de Workflows compris. Une notification perdue ne refuse ni ne retarde aucune session.
6. **Le secret reste ce qu'il est.** `ALERT_NOTIFY_SECRET` reste obligatoire avec l'URL (ADR-0045), et la signature reste envoyée. Slack et Teams ne la vérifient pas : pour eux, seule l'URL fait foi, et la documentation le dit. Rien n'est affaibli pour les récepteurs génériques.
7. **Le format ne restreint pas la destination.** Pas de liste d'hôtes : le format `slack` sert aussi aux récepteurs compatibles, et les hôtes de Workflows varient. L'URL reste une configuration d'administrateur.

**Preuves prévues**

- Rouge d'abord : le corps générique n'est pas la forme attendue par chacun des deux formats.
- Attaques : `<!channel>`, `<@U1>`, `<http://evil|clic>`, `[clic](http://evil)`, `<at>x</at>`, sauts de ligne et guillemets, en identifiant de compte, en demandeur et en ticket : rien ne survit dans le corps, et le JSON reste valide.
- Le corps `generic` reste identique à l'octet près : non-régression pour les récepteurs en place.
- Sur processus réels : les événements d'approbation et de break-glass arrivent dans la forme de chaque format à un récepteur de test, et un récepteur mort ne retarde aucune session.
- Mutations sur chacune de ces garanties.
- **Contre un vrai Slack et un vrai Teams** : test ignoré sans URL en variable d'environnement, jamais écrite dans le dépôt, à lancer avec des canaux de test du propriétaire. Sans lui, le critère de sortie reste ouvert.

**Mesuré** (6 novembre 2026, sur récepteurs de test) : rouge avant le code ; `pkg/webhook`, le Broker et l'Audit Service verts, sous `-race` aussi ; sur processus réels, une alerte arrive en carte Teams signée, une demande arrive à Slack en phrase seule et sans justification, et un canal qui ne répond plus ne retarde pas la demande suivante ; `generic` inchangé, parcours existants verts ; 11 mutations sur 11 tuées. **Slack et Teams réels ne sont pas encore essayés : le critère de sortie reste ouvert jusque-là.**

**Mesuré** (7 novembre 2026, par le propriétaire, contre un vrai flux Workflows) : réglé sur un accès réservé, le flux répond `401` à `TestRealChannel`, et son URL ne porte ni `sp`, ni `sv`, ni `sig` ; avec un flux réglé sur « Anyone », `TestRealChannel` passe (`2xx`). Le point 6 ne vaut donc que pour un flux « Anyone » : c'est le réglage exigé. Prendre en charge OAuth reste possible si un tenant interdit « Anyone », par une décision à part. Un `202` ne prouvait pas la livraison : le premier flux publiait le texte d'exemple de son modèle. Avec une boucle sur `attachments` et « Publier une carte » sur `item()?['content']`, **le canal affiche la carte** (version 1.2), et `<!here>` y arrive en `??here?` : la mention est neutralisée. Puis un vrai Audit Service, sous mTLS, pousse au même canal le `vault.rotation_overdue` écrit avec le certificat du Vault, signé et au format `teams` : **le canal l'affiche** (`test/integration/notify_real_channel_test.go`, qui échoue contre un récepteur mort). La signature ne gêne pas Workflows. Enfin, sur une vraie Gateway, un vrai Broker, Authentication, Authorization et Audit Service (Vault simulé), une demande de break-glass puis son approbation par une seconde personne arrivent au canal en **deux cartes**, signées, **sans la justification** de la demande. **Non constaté** : l'alerte née d'une vraie rotation en échec (prouvée séparément, contre un récepteur de test) ; une demande d'accès avec ticket vers Teams (même notifieur, autre phrase)  ; le ticket dans un ITSM. Le critère de sortie reste ouvert.

**Mesuré** (7 novembre 2026, par le propriétaire, contre un vrai Slack) : une URL de lien Workflow Builder (`slack.com/shortcuts/…`) répond `302` : ce n'est pas un webhook, et la redirection n'est pas suivie. Avec un webhook entrant (`hooks.slack.com/services/…`), `TestRealChannel` passe, et **le canal affiche la phrase** ; `<!here>` y arrive en `??here?` et ne notifie personne.

**Mesuré** (7 novembre 2026, par le propriétaire, contre les deux vrais canaux) : `TestRealChannel` de `test/integration` tourne pour chaque URL fournie. Une alerte de l'Audit Service, sous mTLS ; puis, sur une vraie Gateway, un vrai Broker, Vault, Authentication, Authorization et Audit Service, un break-glass et une demande d'accès avec ticket (`CHG0074001`), chacun approuvé par une autre personne. Les cinq messages s'affichent dans Teams et dans Slack, signés, le ticket présent, aucune justification. Contre-épreuve : contre deux récepteurs morts, les quatre sous-tests échouent sur « not delivered ». **Le premier critère de sortie de la v0.0.1 est atteint**, ticket vérifié dans son format (ADR-0067). **Non constaté** : l'alerte d'une vraie rotation en échec vers un vrai canal (prouvée contre un récepteur de test).

**Conséquences**

- (+) Le premier critère de sortie de la v0.0.1 devient atteignable sans service, sans dépendance et sans table.
- (−) Dans `alert_outbox`, le corps est déjà formé : une alerte en attente garde le format qu'elle avait quand elle a été écrite, même après un changement de `ALERT_NOTIFY_FORMAT`.
- (−) `docs/roadmap.md` prévoit un Notification Service et un Workflow Service : cette décision ne crée pas le premier, et la feuille de route est à amender. Les deux services gardent chacun leur canal : **un seul canal par service**, pas de routage par événement ni par équipe, et une reconfiguration par service.
- (−) `SafeText` remplace par `?` tout ce qui sort de sa liste : un nom accentué, ou un ticket contenant `/`, s'affiche mal. Lisibilité sacrifiée à la sûreté, comme aujourd'hui.
- (−) Les identifiants de compte et de demandeur, ainsi que le ticket, partent chez un tiers (Slack, Microsoft). C'est déjà vrai pour qui y pointe son webhook ; l'administrateur en décide, et la documentation le dit.
- (−) Pas de `Retry-After` sur un `429` : Slack limite ses webhooks à environ un message par seconde. Le Broker n'y réessaie pas, et l'Audit Service suit son délai à lui. Accepté : le volume attendu est faible.
- (−) Le ticket reste non vérifié dans l'ITSM (ADR-0067) : ni ServiceNow ni Jira ici. Ce pan de la ligne « Gouvernance » de la feuille de route reste ouvert.
- (−) `text` peut encore prendre une mise en forme légère (`_` en italique) : sans effet de sécurité, à regarder sur les vrais canaux. Le format exact de Workflows dépend du flux que l'administrateur crée : la documentation donnera le modèle à utiliser.

**Alternatives envisagées**

- **Un Notification Service** : une copie du secret de canal en moins, mais un service, une identité mTLS et un point de panne de plus, pour deux formats tenant en quelques lignes, et une nouvelle route interne à protéger. À reconsidérer s'il faut un routage par équipe ou plusieurs canaux.
- **Approuver depuis la messagerie** : écarté. Une route entrante, et une décision de sécurité déléguée à ce que Slack ou Microsoft disent de l'utilisateur, à l'encontre de l'identité tirée du certificat et de la double validation.
- **Gabarits écrits par l'administrateur** : écarté. Chaque gabarit deviendrait un endroit où une valeur échappe à `SafeText`.
- **MessageCard pour Teams** : écarté. Format ancien, dont les sources divergent sur la prise en charge par Workflows.
- **Slack Block Kit** : écarté pour l'instant. Rien à ajouter à une phrase, et davantage de surface de mise en forme.
- **Un SDK par messagerie** : écarté. Deux corps JSON n'en justifient aucun, et la bibliothèque standard suffit (policy des dépendances).
- **Détecter le format depuis l'hôte de l'URL** : écarté. Implicite, et faux pour les récepteurs compatibles.

**Sources** — [Teams : créer un webhook entrant (retrait des connecteurs, Workflows)](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) · [Slack : envoyer par webhook entrant](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) · [Slack : limites de débit](https://docs.slack.dev/apis/web-api/rate-limits/)
