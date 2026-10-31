# ADR-0056 — Un jeton Transit remplacé sur disque est pris sans redémarrer, après avoir été vérifié auprès de Transit

**Contexte**
ADR-0053 renouvelle le jeton Transit à mi-vie, et note : « le fichier n'est pas relu : un jeton remplacé sur disque n'est pris qu'au redémarrage ». Or remplacer le fichier est le geste ordinaire : un agent OpenBao qui réécrit son puits, un jeton qui a atteint sa durée maximale, un jeton révoqué après un incident. Sans relecture, il faut redémarrer le Vault et le Recorder — deux services de tier 0 — au moment même où l'on remplace une clé d'accès.

**Décision** *(reliquat d'ADR-0053, retenu par Bony Kiss le 31 octobre 2026 ; la forme est renversable)*

1. **Le fichier du jeton est relu** toutes les `TRANSIT_TOKEN_RELOAD_SECONDS` (30 par défaut, de 1 à 3600), par le Vault et par le Recorder.
2. **Un nouveau jeton n'est pris qu'une fois vérifié** : lu avec les mêmes règles qu'au démarrage (fichier régulier, lisible par son seul propriétaire, un seul jeton sur une ligne), puis présenté à Transit (`auth/token/lookup-self`). Refusé, ou fichier illisible : **l'ancien jeton reste**, et le journal le dit une fois, sans aucun des deux jetons.
3. **Pris**, le nouveau jeton sert à tous les appels qui suivent, et c'est lui que le renouvellement d'ADR-0053 renouvelle désormais.

**Conséquences**
- (+) **Mesuré, avant** (sur `eacf0cf`, vrai OpenBao) : le fichier du jeton réécrit avec un nouveau jeton, puis l'ancien révoqué, `fetch-credential` répond `503`.
- (+) **Mesuré, après** : le même scénario (`TRANSIT_TOKEN_RELOAD_SECONDS=1`) livre le secret ; le Vault dit qu'il a pris le nouveau jeton ; aucun des deux jetons n'est dans son journal ; le Recorder annonce sa surveillance. En unitaire (`pkg/transit`, 2 tests) : même contenu sans effet ; jeton refusé par Transit, fichier trop ouvert, vide ou à deux jetons : l'ancien reste, et l'erreur ne porte aucun jeton ; nouveau jeton accepté puis utilisé ; un échec répété dit une seule fois.
- (+) **5 mutations, 5 tuées.**
- (−) Jusqu'à une période entre le remplacement et la prise : révoquer l'ancien jeton **avant** cette prise rend les clés indisponibles pendant ce temps (`503`). L'ordre sûr est : écrire le nouveau, attendre la prise (annoncée au journal), révoquer l'ancien.
- (−) La relecture regarde le contenu du fichier, pas des notifications du système de fichiers : un changement qui revient au même contenu ne se voit pas, et c'est voulu.

**Alternatives envisagées**
- **Relire au premier refus de Transit** (`403`) : la prise attendrait une panne, et un jeton déjà révoqué ferait échouer un appel avant d'être remplacé.
- **Des notifications du système de fichiers** (`inotify`) : une dépendance ou du code propre à Linux, pour gagner quelques secondes.
- **Prendre le nouveau jeton sans le vérifier** : un fichier écrit à moitié, ou un jeton mal copié, couperait les clés sur-le-champ.
