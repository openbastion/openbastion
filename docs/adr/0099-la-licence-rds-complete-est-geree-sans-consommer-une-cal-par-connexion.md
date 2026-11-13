# ADR-0099 — Le client RDP gère la licence RDS complète, sans consommer une licence d'accès par connexion

**Statut** `Accepté` · 13 novembre 2026 · accepté le même jour par le propriétaire du projet : « ADR-0099 l'option B et A ». B d'abord (échange complet, mode par utilisateur, licences en mémoire), puis A (magasin partagé pour le mode par appareil). La sixième cible Windows de la CI et l'emplacement du magasin de A restent à confirmer quand leur incrément viendra.

## Contexte

`pkg/rdp/mcs_licensing.go` ne connaît qu'un cas :
- le serveur envoie un *Server License Request* ;
- le client répond un *Client New License Request* (RSA, plateforme Windows NT) ;
- le serveur conclut par `STATUS_VALID_CLIENT` / `ST_NO_TRANSITION`.

C'est ce que fait un Windows qui n'exige pas de licence : l'administration à distance (deux sessions) ou un hôte de sessions en période de grâce. Les cinq cibles de la CI sont dans ce cas. Tout autre échange est refusé, et la session ne s'ouvre pas.

Un hôte de sessions Bureau à distance (RDSH) adossé à un serveur de licences mène l'échange complet de MS-RDPELE :
- *Platform Challenge* et sa réponse ;
- émission d'une licence (*New License*) ou mise à niveau (*Upgrade License*) ;
- à la connexion suivante, le client présente la licence qu'il a gardée (*Client License Info*).

Ce que le client ne garde pas, le serveur le réémet. En mode **par appareil**, chaque connexion d'un client qui oublie sa licence consomme alors une licence d'accès (CAL) de plus, jusqu'à épuisement. Pour un bastion, qui centralise les connexions, ce serait une panne garantie.

## Options

- **A. Échange complet, licences gardées par le proxy** :
  - le *Platform Challenge* est déchiffré et répondu ;
  - les licences émises sont validées puis gardées ;
  - une licence gardée est présentée à la connexion suivante vers la même cible.

  Le magasin doit survivre à un redémarrage et être partagé par les instances du proxy, sans quoi le mode par appareil s'épuise encore : une table du Broker, ou un objet du Vault. La licence n'est pas un secret de la cible, mais elle identifie le « client ».
- **B. Échange complet en mode par utilisateur seulement, licences en mémoire** : le serveur ne décompte pas d'appareil, et une licence perdue ne coûte rien. Le mode par appareil est refusé, dit comme tel à l'opérateur.
- **C. Statu quo** : seules les cibles sans licence, ou en grâce, sont servies ; tout RDSH licencié est refusé.

## Décision proposée

**B d'abord, A ensuite si un déploiement le demande.**
1. `pkg/rdp` mène le *Platform Challenge* et accepte une licence émise ou mise à niveau, avec les mêmes bornes et le même refus strict que l'échange actuel. La licence n'est gardée qu'en mémoire, le temps du processus.
2. Le mode par appareil n'est pas pris en charge tant qu'un magasin partagé n'existe pas. Le serveur ne le dit pas avant d'émettre, si bien qu'un tel serveur peut consommer des CAL. La documentation d'exploitation le dira : à n'utiliser qu'en mode par utilisateur.
3. **Preuve** : contre un vrai RDSH licencié. dockur/windows peut installer les rôles RDSH et serveur de licences ; c'est une cible de plus pour la CI Windows, et donc plus de temps de CI.

## Ce qui demande ton go

- l'option, B puis A, ou A d'emblée ;
- une sixième cible Windows en CI (RDSH et serveur de licences), plus lente que les autres ;
- pour A plus tard : où garder les licences (une table du Broker ou le Vault).

## Conséquences

- (+) Les fermes RDS licenciées deviennent joignables, sans épuiser les CAL en mode par utilisateur.
- (−) Une nouvelle surface d'analyse de données de la cible, à borner et à fuzzer comme le reste.
- (−) Le mode par appareil reste un risque tant que A n'est pas fait.

## Alternatives envisagées

- **Annoncer une licence factice** : écartée. C'est contourner le contrat de licence de Microsoft, et le serveur la refuserait.
- **Laisser l'exploitant régler ses serveurs en grâce perpétuelle** : écartée. Ce n'est ni possible ni licite au-delà de la période de grâce.
