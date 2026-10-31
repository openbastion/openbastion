# ADR-0053 — Le jeton Transit se renouvelle de lui-même, à mi-vie, et le dit quand il ne le peut pas

**Contexte**
ADR-0049 a confié les clés du Vault et du Command Recorder au moteur Transit d'OpenBao, avec un jeton lu dans un fichier, et noté : « pas de renouvellement du jeton par OpenBastion ». La procédure recommandée (`docs/security/key-management.md`) crée un jeton **périodique** (`-period=24h`) : il expire au bout de sa période s'il n'est pas renouvelé. À cette échéance, Transit refuse (`403`) : plus aucun secret n'est ouvert, plus aucun enregistrement n'est écrit, plus aucune session ne s'ouvre — une panne programmée, que seul un renouvellement extérieur (un agent, une tâche planifiée) évitait.

**Décision** *(reliquat d'ADR-0049, traité à la demande de Bony Kiss du 31 octobre 2026 : « traite d'abord les reliquats » ; la forme est renversable)*

1. **Le service renouvelle son propre jeton** : au démarrage, après l'aller-retour d'essai, il lit la durée de vie du jeton (`auth/token/lookup-self`) ; un jeton renouvelable est renouvelé (`auth/token/renew-self`) **à mi-vie**, puis à mi-vie de la nouvelle durée, sans fin. Un renouvellement qui échoue est retenté au quart du temps restant (au moins toutes les 5 s), et chaque échec est une ligne du journal, sans le jeton.
2. **Un jeton sans fin** (`ttl` nul, comme un jeton racine) ou **non renouvelable** n'est pas renouvelé ; le démarrage le dit, avec l'échéance pour le second.
3. **La politique minimale du jeton** gagne les deux chemins dont il a besoin pour cela : `auth/token/lookup-self` (`read`) et `auth/token/renew-self` (`update`) — rien de plus.
4. **Le reste ne change pas** : un jeton refusé ou expiré reste une indisponibilité des clés (`503`, ADR-0049) ; un renouvellement n'est jamais une raison de démarrer quand l'aller-retour d'essai échoue.

**Conséquences**
- (+) **Mesuré, avant** (sur `3ff50c0`, vrai OpenBao 2.7.2) : avec un jeton périodique de 4 s, au bout de 10 s, `fetch-credential` répond `503` — le jeton a expiré sous le Vault.
- (+) **Mesuré, après** : le même scénario livre le secret au bout de 10 s ; le Vault et le Recorder annoncent le renouvellement ; la politique minimale (le chiffrement et le déchiffrement de la clé, `lookup-self` et `renew-self`) suffit. En unitaire (`pkg/transit`, 4 tests) : renouvellements répétés à mi-vie d'un jeton de 2 s, jeton sans fin et non renouvelable laissés tels quels et annoncés, échec retenté et dit, politique sans `lookup-self` dite avec ce qu'il faut lui donner, jamais le jeton dans le journal.
- (+) **6 mutations, 6 tuées.**
- (−) Un jeton périodique renouvelé sans fin dure autant que le service : le révoquer reste le geste de l'exploitant (`bao token revoke`), et le service le voit au renouvellement suivant.
- (−) Pas d'AppRole : un jeton qui a atteint sa durée maximale (`explicit_max_ttl`) ne se renouvelle plus, et il faut le remplacer dans le fichier, puis redémarrer le service.
- (−) ~~Le fichier n'est pas relu : un jeton remplacé sur disque n'est pris qu'au redémarrage.~~ **Levé par ADR-0056** : relu, vérifié, pris.

**Alternatives envisagées**
- **L'agent OpenBao à côté du service** (`bao agent` qui renouvelle et réécrit le fichier) : un processus de plus à déployer et à surveiller ; reste possible.
- **AppRole** (le service se connecte avec un rôle et un secret) : un secret de plus à distribuer, et la gestion du cycle de vie de ses propres jetons ; à décider à part.
- **Laisser l'exploitant renouveler** : la position d'ADR-0049, qui laisse une panne programmée à qui l'oublie.
