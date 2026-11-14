# ADR-0103 — Le Network Agent établit un tunnel sortant multiplexé sans terminer le protocole PAM

**Statut** Proposé · 14 novembre 2026

**Contexte**

Les sites derrière NAT ou pare-feu ne doivent pas exposer leurs cibles au bastion. Une passerelle sortante répond à ce besoin, mais OpenBastion doit conserver la médiation, l'enregistrement et les contrôles dans ses proxies. ADR-0050 prévoit de réexaminer gRPC lorsqu'un vrai flux bidirectionnel le justifie.

**Décision**

1. Le Network Agent initie une connexion persistante sortante vers un endpoint de contrôle déclaré ; aucun port entrant n'est ouvert pour son plan de contrôle.
2. Le transport agent utilise gRPC bidirectionnel sur HTTP/2, TLS 1.3 et mTLS après enrôlement. Cette exception ne concerne que les agents et Agent Control. Les RPC entre microservices restent HTTP/JSON sous mTLS conformément à ADR-0050.
3. Le flux multiplexe des tunnels TCP individuels. Le proxy protocolaire termine SSH, RDP, VNC ou SQL ; l'agent ne parle pas ces protocoles à la place du proxy.
4. L'agent reçoit une IP littérale, un port, un identifiant de ressource et une capacité liée à la session. Il ne fait aucune résolution DNS libre.
5. Les trames sont bornées à 64 Kio, séquencées, soumises à backpressure, quotas et délais. Les limites sont appliquées côté serveur et agent.
6. Aucun mot de passe, secret Vault, clé privée cible ou ticket utilisateur ne transite dans les messages agent.
7. Pas de SOCKS, UDP, tunnel arbitraire, exécution distante ou route réseau transparente en v0.0.3.
8. Les contrats sont définis dans proto/agent/v1 ; Buf et la compatibilité seront obligatoires avant l'implémentation de production.

**Conséquences**

- (+) Accès à un site privé sans ouverture entrante vers les cibles.
- (+) Le proxy conserve la terminaison, l'enregistrement et les contrôles de session.
- (−) gRPC constitue une exception explicite à ADR-0050 et ajoute un outillage Protobuf.
- (−) Une perte du flux de contrôle interrompt les tunnels selon ADR-0110.
- (−) Un agent compromis reste un point de rebond limité par capacités et politique locale.

**Alternatives envisagées**

- **WebSocket brut** : écarté au profit de contrats Protobuf typés et d'un flux bidirectionnel.
- **gRPC pour tous les microservices** : rejeté ; ADR-0050 reste applicable.
- **VPN L3 ou SOCKS** : rejeté, surface d'accès trop large.