# ADR-0009 — Break-glass : une dérogation d'urgence, bornée et auditée, à « enregistrer ou refuser »


**Contexte**
ADR-0008 fait du Command Recorder une dépendance de disponibilité de tous les accès privilégiés : s'il est en panne, personne n'atteint les cibles via le bastion. C'est le bon défaut — mais c'est aussi exactement la situation où un incident de production exige un accès. Un PAM répond classiquement par un accès « break-glass ». Mal conçu, c'est une porte dérobée : un drapeau que n'importe quel administrateur peut lever pour échapper à l'enregistrement. La question n'est donc pas d'en avoir un, mais de savoir ce que la dérogation coûte et ce qui la borne.

**Décision**
Le break-glass est **une dérogation à l'enregistrement, pour une session, et rien d'autre**. Il ne contourne ni l'authentification, ni le RBAC `session:create`, ni le Vault (le secret n'est toujours jamais exposé), ni l'audit (toujours fail-closed). Il s'appuie sur six verrous :

1. **Demandé explicitement** : `breakGlass: true` à `POST /sessions`, avec une justification d'au moins 10 caractères (un plancher contre le vide, pas une garantie de qualité).
2. **Autorisé à part** : une politique RBAC sur la ressource `breakglass:account:{accountId}` — refusé par défaut. Être administrateur de la plateforme ne suffit pas ; il faut une politique `breakglass:*` explicite. (La ressource, et non l'action, porte la distinction : `CheckAccess` n'évalue aujourd'hui que le rôle et la ressource.)
3. **Borné dans le temps** : durée maximale `BREAKGLASS_MAX_MINUTES` côté Broker, **désactivé tant qu'elle vaut 0 (défaut)**. La durée est imposée par le **proxy**, qui coupe désormais toute session à son échéance (`session.expire`) — jusqu'ici l'expiration n'était qu'une lecture paresseuse du Broker et rien ne coupait une session déjà connectée.
4. **Désactivé par défaut dans le proxy aussi** : `BREAKGLASS_ENABLED` (défaut faux) — un proxy qui ne l'a pas activé refuse la dérogation même si le Broker l'a autorisée. Deux interrupteurs, deux endroits : le Broker décide, le proxy applique.
5. **Exercée seulement en cas de besoin** : si le recorder est prêt à l'admission, la session est enregistrée normalement, avec acquittement par commande (ADR-0008). La dérogation n'a d'effet que lorsque le recorder n'est **pas** prêt ; une session break-glass ne dégrade jamais une session qui pouvait être enregistrée.
6. **Jamais silencieuse** : `session.breakglass_requested` (Broker : qui, succès ou refus), puis `session.breakglass` (proxy : la dérogation a réellement servi, émis **avant** la récupération du credential — si cet événement ne peut pas être audité, la session est refusée), puis `session.expire` à l'échéance. La justification reste lisible sur la session.

Pendant une session dérogée, l'enregistrement continue **au mieux** : les commandes sont envoyées au recorder sans l'attendre, sans jamais bloquer l'opérateur ; celles qui échouent sont comptées et journalisées, pas masquées.

**Conséquences**
- (+) Un accès d'urgence existe, sans trou silencieux : une dérogation laisse trois événements d'audit chaînés et signés, une justification, un titulaire de politique identifiable et une durée butoir.
- (+) La coupure à l'échéance corrige un défaut général : toute session, pas seulement break-glass, a maintenant une fin imposée par le proxy.
- (−) **Pendant une session dérogée, des commandes peuvent ne pas être enregistrées** — c'est le coût assumé de l'exception. La traçabilité repose alors sur l'audit, la justification et les journaux de la cible ; le replay peut être incomplet, et dupliqué (le mode au mieux rejoue sur échec ambigu).
- (−) **Une seule personne suffit** : pas de double validation (le Workflow Service et l'Approval Engine sont v0.0.1). Atténué par une politique étroite et la désactivation par défaut ; à compléter en v0.0.1 par une approbation à deux et une revue post-incident obligatoire. **Approbation à deux : ADR-0011** (requise par défaut) ; la revue post-incident reste ouverte.
- (−) Le drapeau voyage du Broker au proxy sur le canal interne, qui attendait le mTLS (comme le jeton de scope). Sans lui, un appelant atteignant le proxy pouvait l'ajouter lui-même ; il lui fallait toujours un scope Vault valide, et le proxy doit avoir été activé (verrou 4). **Résolu par ADR-0010** : `establish-session` n'accepte que l'identité du Session Broker.
- (−) La ressource `breakglass:account:*` est une convention de nommage, pas un type : une politique mal écrite (`*`) l'accorderait. Les guides le disent.

**Alternatives envisagées**
- *Basculer `RECORDING_POLICY=best-effort` le temps de l'incident* : rejeté — cela dérègle toutes les sessions, exige de redémarrer les proxies, n'identifie personne, et ne se ferme pas tout seul.
- *Tampon local sur le proxy, rejoué au retour du recorder* : écarté pour l'instant (voir ADR-0008) — c'est un second lieu de stockage des données de session (chiffrement, purge, borne, déduplication au rejeu) ; à reconsidérer si les dérogations deviennent fréquentes.
- *Dérogation automatique pour les administrateurs* : rejeté — le privilège de gérer les politiques n'est pas celui d'échapper à l'enregistrement.
- *Sans limite de durée* : rejeté — une dérogation sans butoir devient un mode de fonctionnement.
