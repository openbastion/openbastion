# ADR-0057 — Avec une base, les alertes en attente d'un renvoi survivent à un redémarrage de l'Audit Service

**Contexte**
ADR-0045 pousse les alertes de l'audit par un webhook signé, avec des renvois, et note : « la file est en mémoire : une alerte en attente d'un renvoi est perdue si l'Audit Service s'arrête ». Le Vault réécrit `vault.rotation_overdue` N échecs plus tard, mais N échecs d'une rotation planifiée, c'est N heures : une alerte poussée pendant une panne du récepteur, suivie d'un redémarrage de l'Audit Service (une mise à jour, une bascule), n'arrive pas avant longtemps.

**Décision** *(reliquat d'ADR-0045, retenu par Bony Kiss le 31 octobre 2026 parmi les reliquats proposés ; la forme est renversable)*

1. **Une file de sortie en base** quand l'Audit Service a une base (`alert_outbox`, migration `002_alert_outbox.sql`) : l'identifiant de l'événement, l'action, le corps signé à l'envoi (la signature, elle, est faite à chaque tentative), la tentative à venir et son heure. Sans base, la file reste en mémoire, comme avant.
2. **Le livreur prend ce qui est dû** dans la file, dans l'ordre de leur heure : livré, il l'oublie ; renvoyable, il le repose pour l'heure du renvoi suivant (même doublement, mêmes 5 tentatives qu'ADR-0045) ; refusé ou épuisé, il l'oublie et le dit. Au redémarrage, il reprend ce qui attendait.
3. **La borne ne change pas** : 256 alertes au plus en attente ; au-delà, une alerte n'est pas gardée, et le journal le dit.
4. **Une alerte ne passe qu'une fois dans la file** (l'identifiant de l'événement est sa clé) : une alerte rejouée n'est pas poussée deux fois.

**Conséquences**
- (+) **Mesuré, avant** (sur `42996d4`, processus réels, vraie PostgreSQL) : le récepteur répond `503`, l'Audit Service est tué avant le renvoi, un nouveau démarre sur la même base, le récepteur revient — aucune alerte en 15 s.
- (+) **Mesuré, après** : le même scénario livre l'alerte, une seule fois, avec le même corps et une signature valable ; `alert_outbox` est vide ensuite ; le journal dit où attendent les alertes, jamais l'URL. En unitaire, sur la mémoire **et** sur PostgreSQL : ce qui est dû vient dans l'ordre de son heure, au plus n ; reposé, une alerte garde sa tentative et sa nouvelle heure ; oubliée, elle ne revient pas ; un même événement n'est gardé qu'une fois ; la borne de 256, puis de la place quand une part ; un livreur neuf livre ce que la file tenait, à la tentative atteinte. Les 8 tests d'ADR-0045 passent sans changement.
- (+) **9 mutations, 9 tuées.** Une survivait d'abord : rien ne vérifiait qu'une alerte écrite pendant que le livreur attend part aussitôt (chaque test écrivait avant que le livreur ait regardé la file) ; un test l'écrit maintenant après.
- (+) **Trouvé en écrivant le test** : une file en base peut être pleine au démarrage, et le livreur écrire au journal avant que `WithLogf` ait remplacé le journal ; le journal est désormais sous verrou.
- (−) L'alerte est gardée **après** l'écriture de l'événement, pas dans la même transaction : un arrêt entre les deux perd la poussée (l'événement, lui, est dans la chaîne). La fenêtre est celle d'une requête.
- (−) Le corps est gardé en base en clair : c'est ce que la chaîne contient déjà, sans secret ; la clé de signature, elle, n'y est pas.
- (−) Une seule instance de l'Audit Service (la chaîne l'exige déjà, ADR-0028) : la file n'est pas partagée entre réplicas.

**Alternatives envisagées**
- **Même transaction que l'événement** : un changement du port du magasin de la chaîne pour un rappel de courtoisie ; la fenêtre gagnée est celle d'une requête.
- **Rejouer depuis la chaîne au démarrage** (chercher les alertes non livrées) : il faudrait retenir lesquelles l'ont été, ce qui est la file.
- **Garder la mémoire seule** : la position d'ADR-0045, qui perd au redémarrage ce qui attendait.
