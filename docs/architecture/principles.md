# Principes et invariant fondateur

## Principes fondateurs

| Principe | Traduction architecturale |
|---|---|
| **Zero Standing Privilege** | Aucun compte cible ne possède de credential statique connu d'un humain ; les identifiants sont éphémères, générés/rotés à la demande. |
| **No Direct Access** | Aucun client ne dialogue jamais directement avec un système cible : tout passe par un proxy protocolaire OpenBastion. |
| **Full Auditability** | Chaque action (auth, session, commande, rotation, workflow, admin) génère un événement signé et immuable. |
| **Cloud-Native Portability** | Images OCI, stateless où possible, configuration 12-factor, déploiement identique on-prem/cloud. |
| **API-First** | Toute fonctionnalité de l'UI est d'abord un contrat OpenAPI/gRPC ; l'UI est un client comme un autre. |
| **Zero-Trust Internal Networking** | mTLS systématique inter-services, autorisation par service (SPIFFE-like identity), aucune confiance implicite liée au réseau. |

## Invariant architectural : les secrets ne traversent jamais le control plane

> **Contrainte de premier ordre.** Le Session Broker, l'API Gateway et le Workflow Service n'ont **jamais** connaissance d'un secret cible. Seuls les proxies protocolaires récupèrent un credential éphémère, directement auprès du Vault via mTLS, au moment de l'établissement de connexion. Ce credential est conservé brièvement en mémoire du proxy et purgé immédiatement après usage.

Conséquences de conception :
- Le control plane (Broker, Gateway, Workflow) ne peut pas être un vecteur de fuite de secrets, même en cas de compromission.
- Chaque proxy a un droit d'accès Vault scoping strict (un proxy ne peut demander que les types de credentials correspondant à son protocole).
- L'audit peut prouver *qu'un* credential a été utilisé, sans jamais l'avoir vu transiter par un composant loggé de bout en bout.
