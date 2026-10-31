# ADR-0054 — Une clé d'hôte certifiée peut être révoquée au compte, comme dans `known_hosts`, et ne reçoit plus rien même avec un certificat valable

**Contexte**
Depuis ADR-0048, un compte peut reconnaître sa cible par une autorité de certificats. ADR-0048 a noté : « pas de liste de révocation : un certificat volé vaut jusqu'à sa date de fin ». Qui vole la clé privée d'hôte d'une cible certifiée — et son certificat, qui est public — se fait passer pour elle et reçoit le secret du compte, tant que le certificat court. L'exploitant n'a que deux gestes : attendre la fin du certificat, ou retirer l'autorité du compte (et ne plus reconnaître aucune cible légitime).

`known_hosts` d'OpenSSH a déjà un mot pour cela : une ligne `@revoked <hôtes> <clé>` refuse une clé, même certifiée.

**Décision** *(reliquat d'ADR-0048, retenu par Bony Kiss le 31 octobre 2026 parmi les reliquats proposés ; la forme est renversable)*

1. **Sous la ligne d'autorité d'un compte, des lignes `@revoked <nom ou *> <clé>`** : le champ `hostKey` accepte, pour un compte reconnu par une autorité, la ligne `@cert-authority …` suivie de 0 à 64 lignes `@revoked`. Le contrat ne change pas de forme ; la route d'épinglage, son droit et son audit (`vault.host_key_set`, avant) non plus.
2. **Une clé révoquée n'est jamais acceptée** : un certificat dont la clé est révoquée est refusé, **même** signé par la bonne autorité, pour le bon nom, dans sa période. Rien n'est envoyé ; c'est un refus d'ADR-0039 (`session.host_key_mismatch`, et le journal du proxy dit « revoked »). La même vérification vaut pour la rotation (`pkg/hostkey`).
3. **Ce qui est refusé à l'enregistrement** : une ligne `@revoked` sous une clé épinglée (une clé épinglée n'accepte déjà qu'elle-même), avant la ligne d'autorité, pour un autre nom que celui du compte (ou `*`), qui révoque l'autorité elle-même (on ré-épingle alors), qui est un certificat, ou plus de 64 lignes. Les doublons sont fondus, et la liste est rangée : la même révocation s'écrit toujours de la même façon.
4. **L'empreinte rendue** reste celle de l'autorité.

**Conséquences**
- (+) **Mesuré, avant** (sur `10dc071`, processus réels) : la ligne `@revoked` est refusée à l'épinglage (`400`) — aucun moyen de révoquer ; la clé volée garde le secret.
- (+) **Mesuré, après**, sur processus réels et avec le vrai client OpenSSH : la clé de la cible certifiée révoquée par l'administrateur, la session suivante n'envoie **aucun** mot de passe, l'opérateur n'atteint pas de shell, `session.host_key_mismatch` est à l'audit ; révoquer l'autorité elle-même est refusé (`400`) ; la révocation levée, la session tourne de nouveau. En unitaire (`pkg/hostkey`, 4 tests) : refus d'un certificat valable d'une clé révoquée, les autres clés passent ; normalisation stable (doublons fondus, liste rangée) ; neuf formes refusées.
- (+) **6 mutations, 6 tuées.** Une survivait d'abord, et c'était mon test : l'ordre de la liste n'était vérifié qu'avec deux clés, que l'ordre aléatoire d'une `map` rendait souvent dans le bon ordre.
- (−) La révocation porte sur la **clé** d'hôte, pas sur le numéro de série du certificat (pas de KRL OpenSSH, que `x/crypto` ne lit pas) : un certificat volé dont la clé est révoquée est refusé ; une clé légitime re-certifiée après le vol l'est aussi, et c'est voulu (la clé est compromise).
- (−) Une révocation se pose compte par compte : une clé volée qui sert plusieurs comptes se révoque sur chacun.
- (−) 64 clés révoquées au plus par compte ; au-delà, re-certifier sous une nouvelle autorité est le bon geste.

**Alternatives envisagées**
- **Une KRL OpenSSH** (révocation par numéro de série, par identifiant) : un format binaire que `x/crypto` ne lit pas ; un analyseur de plus dans le chemin qui décide où part le secret.
- **Un champ et une route à part** : un contrat de plus, alors que `known_hosts` dit déjà la même chose dans la même ligne.
- **Une liste de plateforme** : une clé révoquée pour tous les comptes ; plus large, et un réglage sensible de plus (même raison qu'ADR-0048).
