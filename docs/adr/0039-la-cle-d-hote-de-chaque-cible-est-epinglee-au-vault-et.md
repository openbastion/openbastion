# ADR-0039 — La clé d'hôte de chaque cible est épinglée au Vault, et livrée au proxy avec le secret


**Contexte**
Le proxy (depuis le MVP) et le Vault (depuis ADR-0037) se connectaient aux cibles **sans vérifier leur clé d'hôte** (`ssh.InsecureIgnoreHostKey`). Quiconque s'interpose entre eux et une cible — ARP, DNS, une route, l'adresse d'une machine arrêtée — se fait passer pour elle : le proxy lui donne le mot de passe du compte privilégié, le Vault celui du compte de réconciliation et le nouveau secret. Celui qui s'interpose voit donc le secret que l'opérateur, lui, ne voit jamais. Et l'adresse de la cible arrive au proxy **par le Broker** : un Broker compromis pourrait l'orienter vers un serveur à lui.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — clé enregistrée au Vault, vérifiée par le proxy et par le Vault, c'est sa demande ; le reste est renversable)*
1. **Chaque compte porte la clé d'hôte de sa cible** (`hostKey` : une ligne `ssh-ed25519 AAAA…`, telle qu'un fichier `.pub` ou une ligne `known_hosts`, dont les noms d'hôtes sont retirés). Elle est vérifiée et normalisée à l'enregistrement. Les marqueurs `@revoked` et `@cert-authority`, deux lignes ou une ligne illisible sont refusés. `GET` d'un compte rend la clé et son empreinte (`SHA256:…`). C'est une donnée publique, pas un secret.
2. **Elle est obligatoire à l'enregistrement** d'un compte (`400` sans elle). Un compte enregistré avant cet ADR n'en a pas : **aucune session ni rotation** ne s'y ouvre tant qu'un administrateur ne l'a pas épinglée. Le Vault répond `409` (« no pinned host key ») à `authorize-scope`, `fetch-credential` et `rotate`, et `connect` répond `409` à l'opérateur.
   - L'épinglage passe par `PUT /vault/accounts/{id}/host-key`, réservé aux administrateurs du compte.
   - Il est audité **avant** le changement (`vault.host_key_set`, fail-closed, sous le nom du jeton), et le journal du Vault garde l'ancienne et la nouvelle empreinte.
   - Pas de « confiance au premier usage » : le premier usage est justement celui qu'un attaquant attend.
3. **La clé arrive au proxy par le Vault, avec le secret** : `fetch-credential` rend, en plus du secret, l'adresse et la clé épinglée de la cible. Le proxy n'envoie le mot de passe qu'à une cible qui présente exactement cette clé, et refuse une session dont l'adresse (celle du Broker) n'est pas celle que le Vault connaît. Un Broker compromis peut se tromper d'adresse ; il ne peut plus faire accepter un autre serveur.
4. **Le Vault vérifie la même clé** quand il se connecte pour une rotation (`ssh.FixedHostKey` ; le compte de réconciliation est sur la même cible).
5. **Une cible qui ne présente pas sa clé** est refusée explicitement :
   - le journal du proxy garde l'empreinte vue et l'empreinte attendue ;
   - l'audit enregistre `session.host_key_mismatch` (en plus de `session.terminate`) ;
   - l'opérateur lit que rien n'a été envoyé et qu'il doit prévenir un administrateur.

**Conséquences**
- (+) **Mesuré** : avant (rouge, sur 2e9166f), un serveur présentant une autre clé à l'adresse de la cible recevait le mot de passe `root` du compte, et le relais répondait sans erreur ; le changeur de mot de passe du Vault se connectait en `root` à des cibles dont il n'avait jamais vu la clé.
- (+) **Mesuré, après** — huit processus réels et le vrai client OpenSSH :
  - l'imposteur reçoit **zéro** mot de passe ;
  - l'opérateur est prévenu et `session.host_key_mismatch` est audité ;
  - un opérateur ne peut pas ré-épingler (`403`) ;
  - un administrateur ré-épingle, l'audit l'attribue au nom du jeton et non à celui que le client écrit dans sa requête, et la session suivante passe ;
  - un enregistrement sans clé, avec une clé vide, illisible ou privée est refusé (`400`).
- (+) **Mesuré, en unitaire** :
  - un compte sans clé n'obtient ni scope, ni secret (même pour un scope accordé avant), ni rotation ;
  - un épinglage sans l'audit n'a pas lieu ;
  - une session dont l'adresse diffère de celle du Vault n'envoie rien.
  - **25 mutations, 25 tuées.** Deux survivaient au départ. Le repli `known_hosts` était du code mort : il est retiré, et le marqueur `@revoked` sans nom d'hôte est maintenant refusé. Le refus d'une rotation sans clé n'était pas distingué d'un autre `409` : le test exige maintenant le motif.
- (+) Celui qui s'interpose entre le bastion et une cible ne reçoit plus aucun secret ; un Broker compromis ne peut plus envoyer le proxy vers un serveur qu'il contrôle.
- (−) **Les comptes existants doivent être épinglés** avant leur prochaine session : c'est une opération d'exploitation, décrite dans le guide d'administration.
- (−) Une cible qui change de clé (réinstallation) refuse les sessions jusqu'à un nouvel épinglage. C'est le comportement voulu, et c'est une panne si personne ne la prévoit.
- (−) Une seule clé par compte : pas de liste de clés acceptées, pas d'autorité de certificats SSH. Une cible qui présente plusieurs types de clé n'est acceptée que par celui qui est épinglé, et le client SSH du bastion négocie ce type-là.
- (−) ~~L'enregistrement et l'épinglage sont deux écritures. Si la seconde échoue, le compte reste sans clé : inutilisable, donc sûr, et réparable par `PUT host-key`.~~ Refermé par ADR-0040 : le compte est écrit en une fois, clé, réconciliation et intervalle compris.

**Alternatives envisagées**
- **Confiance au premier usage** (enregistrer la clé vue à la première connexion) : protège tout sauf la première connexion, qui est celle que l'attaquant vise.
- **La clé par le Broker** (avec l'adresse) : un Broker compromis la changerait avec l'adresse.
- **Autorité de certificats SSH** : plus souple, mais elle suppose une PKI SSH chez l'exploitant ; possible plus tard, à côté de l'épinglage.
