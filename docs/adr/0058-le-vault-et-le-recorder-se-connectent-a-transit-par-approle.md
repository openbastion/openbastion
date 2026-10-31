# ADR-0058 — Le Vault et le Recorder peuvent se connecter à Transit par AppRole, et reprennent un jeton neuf quand le leur atteint sa fin

**Contexte**
Depuis ADR-0049, le Vault et le Command Recorder présentent à Transit un jeton lu dans un fichier. ADR-0053 le renouvelle, ADR-0056 le reprend s'il est remplacé sur disque — mais un jeton a une **durée maximale** (`token_max_ttl`, ou celle du système) : arrivé au bout, plus aucun renouvellement ne le prolonge, et il faut qu'un tiers (un agent OpenBao, un exploitant) en écrive un autre. Sans ce tiers, le service perd ses clés à date fixe. ADR-0049 a noté : « pas d'AppRole ». AppRole est la méthode qu'OpenBao prévoit pour une machine : un identifiant de rôle (`role_id`) et un secret (`secret_id`) contre un jeton, que le service redemande lui-même.

**Décision** *(reliquat d'ADR-0049, retenu par Bony Kiss le 31 octobre 2026 parmi les reliquats proposés ; la forme est renversable)*

1. **Deux façons de se connecter, une seule à la fois** : `TRANSIT_TOKEN_FILE` (comme avant), **ou** `TRANSIT_ROLE_ID_FILE` et `TRANSIT_SECRET_ID_FILE` (ensemble), avec `TRANSIT_APPROLE_MOUNT` (`approle` par défaut). Les deux façons données, ou une moitié d'AppRole : le service refuse de démarrer, et le message nomme les variables sans en répéter les valeurs.
2. **Les deux fichiers suivent la règle du jeton** : fichier régulier, lisible par son seul propriétaire, une seule valeur sur une ligne. Ils sont **relus à chaque connexion** : un `secret_id` remplacé sur disque est pris à la connexion suivante.
3. **La connexion** (`auth/<montage>/login`) est faite au démarrage, avant l'aller-retour de vérification d'ADR-0049 : refusée, le service ne démarre pas.
4. **Le jeton obtenu est renouvelé à mi-vie** (ADR-0053). Quand un renouvellement est refusé, ou rend **moins** que la vie qu'avait le jeton à sa connexion — il a atteint sa durée maximale —, le service **se reconnecte** et prend le nouveau jeton pour les appels qui suivent. Une connexion qui échoue est retentée au quart du temps restant (jamais plus tôt que le plancher d'ADR-0053), et chaque échec est dit.
5. **Rien de ce qui sert à se connecter n'est écrit** : ni le `role_id`, ni le `secret_id`, ni le jeton — pas dans une erreur, pas dans un journal.
6. Avec AppRole, la relecture du fichier du jeton (ADR-0056) n'a pas d'objet : le service le dit une fois au démarrage.

**Conséquences**
- (+) **Mesuré, avant** (sur `aedb217`, vrai OpenBao, processus réels) : AppRole donné en plus d'un jeton est ignoré sans un mot, et le service démarre (le test attend un refus et trouve un processus vivant après 5 s) ; sans jeton, l'ancien code exige `TRANSIT_TOKEN_FILE`.
- (+) **Mesuré, après**, sur un vrai OpenBao : un rôle dont les jetons vivent 3 s et au plus 5 s ; le Vault et le Recorder se connectent, et 12 s plus tard le Vault livre toujours le secret ; les deux disent qu'ils se sont reconnectés ; ni le `role_id` ni le `secret_id` dans leur journal. Les deux façons à la fois, une moitié d'AppRole, un `secret_id` refusé par OpenBao : les deux services refusent de démarrer, sans aucune des valeurs. En unitaire (`pkg/transit`, 4 tests) : onze configurations refusées ; la vérification du démarrage se connecte d'abord ; une connexion refusée garde le jeton en usage, et son erreur dit la raison, les valeurs masquées ; un `secret_id` remplacé sur disque est pris à la connexion suivante ; des appels toutes les 20 ms pendant 7 s avec des jetons de 3 s au plus : **aucun** n'échoue ; une connexion refusée est retentée et dite.
- (+) **8 mutations, 8 tuées.** Deux survivaient d'abord : sans reconnexion à la durée maximale, le service se rattrapait à la mort du jeton (le test regardait un seul appel, à la fin ; il en fait désormais un toutes les 20 ms) ; et une erreur de connexion non masquée passait inaperçue, à cause du défaut suivant.
- (+) **Trouvé en écrivant le test** : le masquage du jeton dans les erreurs remplaçait la chaîne vide quand l'appel n'en porte pas (la connexion), et mettait « [token] » entre chaque lettre du message. Corrigé : on ne masque que ce qui existe.
- (−) Le jeton précédent n'est pas révoqué après une reconnexion : il finit à sa date (au plus sa durée maximale). Le révoquer couperait un appel en vol qui le porte encore.
- (−) Un `secret_id` à usage limité (`secret_id_num_uses`) s'épuise au fil des reconnexions : le service le dit, et garde son jeton jusqu'à sa fin ; fournir un nouveau `secret_id` sur disque suffit. Un `secret_id` emballé (*response wrapping*) n'est pas déballé : c'est le travail d'un agent de déploiement.
- (−) La politique du rôle doit permettre `auth/token/renew-self` (et `lookup-self`), comme pour un jeton (ADR-0053).

**Alternatives envisagées**
- **Se reconnecter à chaque mi-vie, sans renouveler** : plus simple, mais chaque connexion consomme une utilisation du `secret_id`, et multiplie les jetons vivants.
- **Laisser un agent OpenBao écrire le jeton** (ADR-0056 suffit alors) : reste possible et documenté ; AppRole évite un processus de plus à côté de deux services de tier 0.
- **Les identifiants dans des variables d'environnement** : une variable se lit dans `/proc/<pid>/environ` et se recopie dans les journaux de déploiement ; un fichier a un propriétaire et un mode.
