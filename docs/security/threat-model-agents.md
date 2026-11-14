# Modèle de menace STRIDE — OpenBastion Agent Framework

**Version** v0.0.3 · **Date** 14 novembre 2026 · **Statut** analyse de conception proposée, à revalider sur implémentation et tests.

Ce document complète docs/security/threat-model.md. Il analyse les frontières de confiance des agents Network et Security. Aucun agent de production n'est implémenté dans cet incrément documentaire.

## 1. Actifs et hypothèses

**Actifs** : clés privées et certificats agent ; jetons d'enrôlement ; clés JWS ; capacités de tunnel ; autorisations et destinations ; secrets cibles (qui ne doivent jamais entrer dans le plan agent) ; flux TCP médiatisés ; télémétrie et séquences ; binaires, politiques et racines de confiance ; disponibilité d'Agent Control et des sites privés.

**Adversaires** : opérateur externe ; utilisateur PAM malveillant/compromis ; attaquant root/SYSTEM sur un hôte ; processus local non privilégié ; agent compromis ou certificat volé ; microservice central compromis ; attaquant réseau ; chaîne de livraison compromise.

**Hors périmètre** : compromission physique/firmware/hyperviseur ; défense contre un administrateur root/SYSTEM hostile contrôlant l'hôte ; EDR complet ; garantie de vérité d'une télémétrie provenant d'un hôte compromis.

## 2. Architecture et frontières de confiance

~~~mermaid
flowchart TB
  OP[Operateur] --> UI[Portail / API Gateway]
  UI --> AUTH[Authentication + MFA]
  AUTH --> AZ[Authorization Service]
  AZ --> SB[Session Broker]
  SB --> PX[Proxy protocolaire]
  PX --> AC[Agent Control]
  AC <-->|gRPC bidirectionnel · TLS 1.3 · mTLS| NA[Network Agent]
  NA -->|TCP autorise uniquement| TARGET[Machine cible]
  SA[Security Agent] -->|gRPC streaming · mTLS| AT[Agent Telemetry]
  AT --> ING[Ingestion / normalisation]
  ING --> TS[Stockage télémétrie / détection]
  ING --> AUD[Audit Service · métadonnées de réception seulement]
  UP[Livraison signee] --> NA
  UP --> SA
~~~

- **TB-1 utilisateur / plateforme** : client non fiable ; authentification et autorisation serveur.
- **TB-2 control plane / proxy** : le Broker orchestre ; le proxy détient seul le credential cible (ADR-0003).
- **TB-3 service central / agent** : réseau hostile ; mTLS, identité individuelle, capacités et validation.
- **TB-4 agent / réseau privé** : IP littérale, politique locale, refus par défaut.
- **TB-5 Network / Security Agent** : processus, clés, permissions et IPC séparés.
- **TB-6 hôte observé / collecte** : source contrôlable ; télémétrie = observation, pas preuve indépendante.
- **TB-7 livraison / agent** : artefacts et politiques vérifiés avant activation.

## 3. Cotation DREAD

Chaque dimension Damage (D), Reproducibility (R), Exploitability (E), Affected users (A) et Discoverability (Di) est notée de 1 à 10 ; le vecteur D/R/E/A/Di apparaît dans le tableau et le score est sa moyenne. C'est une estimation de conception, pas une mesure empirique. Seuils du guide sécurité : Critical 8–10, High 6–7,9, Medium 4–5,9, Low 1–3,9. Réévaluer après tests et mesures.

## 4. Menaces STRIDE

| ID | STRIDE | Scénario / actif | D/R/E/A/Di | DREAD | Niveau | Contrôles exigés |
|---|---|---|---:|---|---|
| AG-S01 | Spoofing | Usurpation agent_id dans Hello | 9/9/8/8/7 | 8,2 | Critical | Identité tirée du SAN mTLS ; assertion du message comparée au registre ; test mismatch |
| AG-S02 | Spoofing | Vol du jeton d'enrôlement | 8/8/7/8/8 | 7,8 | High | Jeton aléatoire, usage unique, TTL ≤ 10 min, lié à agent, CSR signé, audit |
| AG-S03 | Spoofing | Certificat révoqué utilisé sur flux existant | 9/8/8/8/7 | 8,0 | Critical | Vérification révocation, fermeture des flux, génération identité, tests multi-replicas |
| AG-T01 | Tampering | Modification de capacité (session, IP, port, audience, durée) | 9/9/8/9/7 | 8,4 | Critical | JWS EdDSA, claims strictes, TTL ≤ 60 s, jti anti-rejeu, algorithme en allowlist |
| AG-T02 | Tampering | Politique locale modifiée ou rollback | 9/8/8/8/7 | 8,0 | Critical | Signature détachée, canonicalisation, agent binding, génération monotone, expiration |
| AG-T03 | Tampering | Injection/troncature/réordonnancement de trames | 7/7/7/7/6 | 6,8 | High | TLS, séquence par tunnel, limites, validation d'état, fermeture, fuzzing |
| AG-R01 | Repudiation | Agent nie un tunnel ou un événement | 7/7/6/6/6 | 6,4 | High | Journal serveur ouverture/fermeture, identité mTLS, séquence et heure de réception |
| AG-R02 | Repudiation | Agent compromis falsifie ou supprime ses observations | 9/8/8/9/7 | 8,2 | Critical | Provenance host-agent, trous de séquence, santé, corrélation Broker/proxy ; pas de preuve indépendante |
| AG-I01 | Information Disclosure | Secret cible reçu ou journalisé par agent | 10/9/8/9/7 | 8,6 | Critical | Aucun secret dans les contrats agent ; Vault accessible au proxy seulement ; tests canaris |
| AG-I02 | Information Disclosure | Tunnel vers loopback, link-local, métadonnées ou IP interdite | 10/9/8/9/6 | 8,4 | Critical | IP littérale, filtrage IPv4/IPv6, CIDR/ports, contrôle IP réelle, tests SSRF |
| AG-I03 | Information Disclosure | Payload contient tokens, PII ou contenu de session | 7/7/6/7/6 | 6,6 | High | Schémas bornés, minimisation, redaction, ACL, chiffrement, rétention |
| AG-D01 | Denial of Service | Tunnels ou trames volumineuses épuisent agent/serveur | 8/8/7/7/5 | 7,0 | High | Quotas, 64 Kio, backpressure, timeouts, budgets mémoire et débit |
| AG-D02 | Denial of Service | Tempête de reconnexion ou ingestion | 7/7/6/6/6 | 6,4 | High | Backoff jitter, rate limits, quotas, files bornées, alertes |
| AG-D03 | Denial of Service | Perte du flux de contrôle pendant une session | 7/8/5/6/3 | 5,8 | Medium | Fermeture fail-closed, état Broker/proxy, nouvelle autorisation ; impact documenté |
| AG-E01 | Elevation of Privilege | Processus local non privilégié utilise IPC agent | 9/8/8/8/7 | 8,0 | Critical | IPC authentifié OS, ACL, protocole typé, aucune commande générique, tests |
| AG-E02 | Elevation of Privilege | Compromission Security Agent atteint Network Agent/root | 9/8/8/9/7 | 8,2 | Critical | Processus, comptes, clés, sockets et politiques séparés ; helpers bornés |
| AG-E03 | Elevation of Privilege | Agent Control compromis émet une capacité arbitraire | 10/9/9/9/7 | 8,8 | Critical | Allowlist locale indépendante, capacité liée session/ressource/IP/port, révocation |
| AG-E04 | Elevation of Privilege | Update/rollback installe un binaire non autorisé | 9/8/7/8/7 | 7,8 | High | Signature, provenance, SBOM, dépôt/canal épinglé, anti-rollback, activation atomique |

### Priorités

**P0 avant tout pilote réseau réel** : AG-S01, S02, S03, T01, T02, I01, I02, E01, E02 et E03.

**P1 avant déploiement multi-site** : AG-T03, AG-R01, AG-R02, AG-I03, AG-D01, AG-D02 et AG-E04.

**Compromis accepté** : AG-D03. La perte de contrôle ferme les tunnels ; une session légitime peut être interrompue, mais aucun accès hors ligne impossible à révoquer n'est maintenu.

## 5. Invariants de sécurité

1. Aucun secret cible, clé privée cible ou token Vault dans les messages agent.
2. Aucun accès sur la seule base d'un agent_id, d'un CIDR ou d'un message client.
3. Destination IP littérale contrôlée ; aucune résolution DNS arbitraire par l'agent.
4. Identité issue du certificat mTLS.
5. Capacité liée à un agent, une session, une ressource, IP, port et expiration ; usage unique.
6. Politique locale ne peut qu'affaiblir la capacité (restreindre), jamais l'élargir.
7. Perte du flux, révocation, politique expirée ou erreur de validation ferme le tunnel.
8. Agents Network et Security séparés processus, identité, permissions et IPC.
9. Télémétrie agent jamais assimilée à la preuve d'audit indépendante.
10. Binaires et politiques vérifiés avant activation.

## 6. Plan de vérification v0.0.3

| Contrôle | Preuve attendue |
|---|---|
| Identité | SAN mismatch, agent inconnu, certificat expiré/révoqué |
| Enrôlement | Rejeu jeton, double consommation concurrente, CSR invalide |
| Capacités | Signature, audience, TTL, jti rejoué, IP/port/session erronés |
| SSRF | Loopback, link-local, IPv4/IPv6, métadonnées, CIDR/ports interdits |
| Flux | Fuzzing Protobuf, séquences, trame > 64 Kio, backpressure |
| Isolation | Linux utilisateur dédié/seccomp/AppArmor ; Windows ACL/Service SID |
| Télémétrie | Perte, doublon, trou, horloge fausse, payload secret |
| Audit | Corrélation Broker/proxy/agent ; agent incapable d'écrire une action PAM faisant autorité |
| Mise à jour | Signature invalide, mauvais dépôt, rollback, interruption activation |
| HA | Bascule, double connexion, révocation en reconnexion, absence de reprise tunnel |
| Charge | Quotas, saturation, reconnexions massives, mémoire bornée |

## 7. Risques résiduels

- Root/SYSTEM contrôle potentiellement le processus, les sources et la clé agent.
- Une racine de signature compromise peut publier un artefact malveillant.
- Un administrateur local hostile peut modifier la politique si l'hôte est compromis.
- La disponibilité dépend du service de contrôle ; comportement retenu : fail-closed.
- Réponse automatique, eBPF obligatoire et fonctions EDR restent hors v0.0.3.

## 8. Références

ADR-0003, ADR-0008, ADR-0010, ADR-0025 à ADR-0028, ADR-0050, ADR-0094, ADR-0102 à ADR-0110 ; docs/security/threat-model.md et docs/security/network-security.md.
