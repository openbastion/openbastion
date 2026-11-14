# ADR-0105 — Chaque tunnel exige une capacité signée, éphémère et bornée

**Statut** Proposé · 14 novembre 2026

**Contexte**

Une passerelle réseau devient un point de rebond potentiel. Une simple allowlist CIDR ne lie pas l'accès à une session, un utilisateur ou une durée. Le serveur autorise, mais l'agent doit vérifier une capacité minimale avant d'ouvrir une socket.

**Décision**

1. Authorization Service reste l'autorité de décision. Agent Control émet une capacité JWS EdDSA à courte durée, destinée à un seul agent.
2. La capacité contient issuer, audience agent, jti unique, session, ressource, IP, port, protocole, émission et expiration. Le jeton d'ouverture expire au plus après 60 secondes ; le tunnel ne dépasse jamais la session.
3. La capacité est à usage unique. L'agent garde un cache anti-rejeu borné jusqu'à expiration. Signature, audience, jti, horloge ou revendication invalide entraînent un refus.
4. Une politique locale signée limite CIDR, ports, nombre de tunnels, durée et protocoles. Elle peut restreindre une capacité, jamais l'élargir.
5. La destination est une IP littérale. L'agent valide IPv4/IPv6, plages réservées, CIDR, port et adresse réellement utilisée. Aucune résolution DNS n'est faite par l'agent.
6. Aucune capacité ne permet shell, exécution distante, accès fichiers, UDP, SOCKS ou réseau entier.
7. Toute validation impossible, expiration, répétition ou discordance entraîne un refus par défaut.

**Conséquences**

- (+) Chaque tunnel est lié à une session et une destination.
- (+) La politique locale limite le rayon d'impact d'un plan de contrôle compromis.
- (−) Cache anti-rejeu, horloge et rotation des clés JWS doivent être testés.
- (−) Un serveur central autorisé mais compromis peut émettre des capacités malveillantes ; la politique locale est une défense indépendante.
- (−) Les adresses dynamiques doivent être résolues par l'inventaire central, jamais librement par l'agent.

**Alternatives envisagées**

- **CIDR seul** : rejeté, trop large et non lié à une session.
- **Autorisation uniquement centrale** : rejetée, absence de défense locale en cas de compromission.
- **Capacité permanente** : rejetée, risque de rejeu et d'accès hors session.