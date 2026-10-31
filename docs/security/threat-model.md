# Modèle de menace

| Acteur / scénario | Considéré dans ce modèle | Contre-mesure principale |
|---|---|---|
| Opérateur privilégié malveillant ou compte compromis | Oui | Zero Standing Privilege : aucun credential statique connu de l'opérateur (`docs/architecture/principles.md`) |
| Compromission du control plane (Gateway, Broker, Workflow) | Oui | Invariant ADR-0003 : le control plane ne détient jamais de secret |
| Compromission d'un proxy protocolaire | Oui | Scope token à usage unique, purge mémoire immédiate, droits Vault strictement scopés par type de proxy |
| Interception réseau (MITM) inter-services | Oui | mTLS obligatoire sur tout trafic interne (`docs/security/network-security.md`, ADR-0010) |
| Interposition entre le bastion et une cible (ARP, DNS, route, machine remplacée) pour recevoir le secret | Oui | Clé d'hôte épinglée au Vault, livrée avec le secret ; le proxy et la rotation n'envoient rien à une autre clé (ADR-0039) |
| Service compromis ou pod hostile se faisant passer pour un autre service interne | Oui | Identité tirée du certificat, table d'appelants par route avec refus par défaut, identité du pair épinglée côté client (`docs/security/network-security.md`, ADR-0010) |
| Falsification rétroactive du journal d'audit | Oui | Chaînage par hash `prev_hash` → `hash` (`docs/architecture/data-architecture.md` §4) |
| Compromission du KMS/HSM externe | Hors périmètre applicatif — traité comme dépendance externe critique, cf. §7 |
| Attaque physique sur l'infrastructure hôte | Hors périmètre de ce guide — relève de la sécurité de l'hébergeur/datacenter |
