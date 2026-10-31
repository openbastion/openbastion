# ADR-0046 — Plusieurs instances du proxy SSH : le Broker les connaît toutes, émet un ticket chez l'une, et fait révoquer chez toutes

**Contexte**
ADR-0018 a rendu la terminaison réelle, sur une instance : les tickets, les connexions ouvertes et la mémoire des révocations vivent dans le processus du proxy, et le Broker ne connaît qu'une URL (`SSH_PROXY_URL`). Il en a tiré une règle d'exploitation, « ne déployez pas plusieurs réplicas du proxy SSH ». Le défaut est double :
- **la révocation** n'atteint qu'une instance : derrière un équilibreur, l'opérateur connecté à l'autre reste connecté alors que la session est « terminée » ;
- **la connexion elle-même** ne tient pas : chaque instance annonce la même adresse figée (`127.0.0.1:SSH_PORT`), et un ticket n'est connu que de l'instance qui l'a émis ; un opérateur envoyé sur une autre instance est refusé.

Les deux viennent de la même absence : le Broker ne sait pas qu'il y a plusieurs instances.

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « Go pour la prochaine étape », point 4 du backlog ; la forme est renversable)*

1. **Chaque instance annonce sa propre adresse SSH** : `SSH_PUBLIC_ENDPOINT` (`hôte:port`, celle que l'opérateur joint pour **cette** instance), renvoyée par `establish-session` comme `proxy_endpoint`. Absente : `127.0.0.1:SSH_PORT`, comme avant. Illisible (pas `hôte:port`, port hors de 1 à 65535) : le proxy refuse de démarrer.
2. **Le Broker connaît toutes les instances** : `SSH_PROXY_URLS`, les URL de contrôle des instances séparées par des virgules, chacune adressée **directement** (pas un équilibreur), de 1 à 16, sans doublon. Chacune a son client mTLS épinglé sur l'identité `ssh-proxy` (ADR-0010). `SSH_PROXY_URL` reste la forme à une instance ; les deux ensemble, une liste vide, un doublon ou plus de 16 entrées : le Broker refuse de démarrer.
3. **Un `connect` émet un ticket chez une instance** : à tour de rôle ; si elle ne répond pas ou refuse, l'instance suivante, chacune au plus une fois. Si toutes échouent et que l'une a dit « enregistrement indisponible » (ADR-0008), c'est ce refus qui est rendu ; sinon le dernier échec. L'opérateur reçoit l'adresse **de l'instance qui tient son ticket**.
4. **Un `terminate` fait révoquer chez toutes les instances**, en parallèle, avec la route et le sens d'ADR-0018. La session n'est marquée terminée **que si toutes ont répondu `200`** ; une seule injoignable ou qui répond autre chose : `503`, rien n'est terminé, la tentative est à l'audit en échec (ADR-0018, règle 6, inchangée), et le même appel aboutit quand l'instance est revenue. Le Broker ne retient pas quelle instance tient quoi : ce qu'il ne retient pas, il ne peut pas l'oublier.
5. **Pourquoi toutes, et pas celle qui a émis le ticket** : une session peut avoir plusieurs tickets, sur plusieurs instances, et un `connect` en vol pendant un `terminate` peut émettre sur une instance qu'un registre n'aurait pas encore vue. Révoquer chez toutes, c'est confier la course à la mémoire des révocations de chaque instance, qui refuse déjà un `establish-session` arrivé après (ADR-0018, règle 5).

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `13a90c0`, `test/integration/proxy_instances_flow_test.go` dans un worktree) : le Broker démarrait avec une liste illisible, deux variables à la fois ou un doublon (le processus tournait encore après 5 s), ignorait `SSH_PROXY_URLS`, et le premier `connect` répondait `503`.
- (+) **Mesuré, après**, sur processus réels (Gateway, Broker, Authentication, Authorization, Vault, Audit, Command Recorder, **deux** proxys SSH, une cible SSH) :
  - deux `connect` de la même session reçoivent un ticket chacun, d'une instance chacun, avec l'adresse de cette instance (`SSH_PUBLIC_ENDPOINT`, différente du défaut) ;
  - un ticket est refusé par l'autre instance, puis ouvre une connexion sur la sienne : il était refusé, pas dépensé ;
  - la fin de la session ferme les deux shells, chacun avec « session ended because it was terminated. », et laisse intacte une autre session ;
  - une instance arrêtée : deux `connect` vont à l'autre ; `DELETE` répond `503` sans adresse interne, la session reste `active`, `session.terminate` en échec est à l'audit ; l'instance revenue, le même appel termine ;
  - une liste à deux variables, avec doublon, entrée vide, sans schéma ou de 17 instances arrête le Broker ; une adresse annoncée illisible arrête le proxy.
- (+) **Mesuré en unitaire** (`proxy_pool_test.go`, 7 tests) : la révocation est demandée à chaque instance, même quand l'une échoue, et n'en est une que si toutes confirment ; elles sont interrogées en parallèle (trois de 200 ms en moins de 400 ms) ; les tickets tournent ; une instance en échec est passée, chacune au plus une fois ; le refus d'enregistrer l'emporte ; 1 à 16 instances.
- (+) **12 mutations, 12 tuées.** Une survivait d'abord, et c'était mon test : il annonçait `127.0.0.1:<port>`, la valeur par défaut, si bien qu'un proxy qui ignorait `SSH_PUBLIC_ENDPOINT` passait. Il annonce désormais `localhost:<port>`.
- (+) L'application du Broker ne change pas : le pool est un adaptateur derrière le port `ProxyClient`.
- (−) **Une instance injoignable empêche toute terminaison**, même d'une session qui n'y a jamais eu de ticket : le Broker ne distingue pas une instance arrêtée (qui n'a plus rien) d'une instance coupée du réseau (qui peut encore relayer). C'est le sens d'ADR-0018. Pour terminer malgré une instance **dont on sait qu'elle est arrêtée**, l'exploitant la retire de `SSH_PROXY_URLS` et redémarre le Broker : c'est une décision humaine, pas un délai.
- (−) Un `terminate` coûte un appel par instance (en parallèle : le temps de la plus lente, 5 s d'attente des relais au plus chez chacune).
- (−) Pas d'équilibreur TCP devant les ports SSH : un ticket ne vaut que sur son instance. La répartition est celle du Broker (à tour de rôle, par processus du Broker), pas une mesure de charge.
- (−) Le tour de rôle est par processus du Broker ; plusieurs Brokers tournent chacun le leur.
- (−) Un ticket émis chez une instance dont la réponse s'est perdue reste chez elle jusqu'à son échéance ; il n'a été remis à personne, et le `terminate` le révoque comme les autres.

**Alternatives envisagées**
- **Retenir l'instance de chaque ticket** (colonne en base) et ne révoquer que là : une migration, et la course d'un `connect` en vol contre un `terminate` (point 5) à fermer par un état de plus. Écartée pour l'instant.
- **Diffusion par un bus** (NATS, ADR-0001) : le bus n'existe pas dans le MVP ; une diffusion sans accusé de réception ne permettrait pas de dire « coupé ».
- **Les proxys interrogent le Broker** (révocations récentes) : la coupure attendrait l'intervalle d'interrogation, et le Broker ne saurait pas quand dire « terminé ».
- **Un mode « au mieux »** qui termine malgré une instance injoignable : rejeté par ADR-0018 pour la même raison, il rouvre le mensonge qu'il ferme.
