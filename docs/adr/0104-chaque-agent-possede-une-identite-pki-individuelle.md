# ADR-0104 — Chaque agent possède une identité PKI individuelle et enrôlée une seule fois

**Statut** Proposé · 14 novembre 2026

**Contexte**

Une clé partagée permettrait à la compromission d'un site d'usurper toutes les passerelles. ADR-0010 impose déjà l'identité issue du certificat, TLS 1.3, l'identité du pair épinglée et le refus par défaut. Les agents ont besoin d'une identité révocable sans affecter les identités des microservices.

**Décision**

1. Chaque agent génère localement sa paire de clés ; la clé privée ne quitte jamais l'hôte et est protégée par les permissions du compte de service ou le magasin de clés OS/TPM lorsqu'il existe. Le CSR prouve la possession de la clé.
2. L'enrôlement utilise un jeton aléatoire d'au moins 256 bits, à usage unique, lié à un agent déclaré, valable au plus 10 minutes et consommé atomiquement. Il n'est jamais journalisé ni conservé en clair après émission.
3. L'identifiant agent est borné à 1–64 caractères dans [a-z0-9-], non réutilisable et sans alias. Le certificat porte un SAN URI unique spiffe://<trust-domain>/agent-<agent-id>. Ce profil est distinct de l'identité de service ADR-0010 ; un certificat agent ne peut pas appeler une route de microservice.
4. Le serveur valide chaîne, usage de clé, SAN exact, statut d'enrôlement et preuve de possession. TLS 1.3 et vérification de l'identité serveur sont obligatoires ; aucun mode InsecureSkipVerify en production.
5. La durée maximale du certificat est de 24 heures. Le renouvellement exige un certificat encore valide et un nouveau CSR signé par la clé courante.
6. La révocation est consultée à chaque ouverture de flux et commande de contrôle. Elle ferme les flux actifs, interdit le renouvellement et incrémente la génération d'identité.
7. L'enrôlement est une opération administrative auditée, distincte de l'autorisation d'accès aux ressources.

**Conséquences**

- (+) Une clé compromise n'usurpe pas les autres agents ; la révocation est ciblée.
- (−) PKI, horloge et disponibilité de l'enrôlement deviennent des dépendances.
- (−) Le renouvellement des certificats doit être supervisé.
- (−) La révocation dépend de la propagation de l'état central et de la fermeture des flux.

**Alternatives envisagées**

- **Token statique par site** : rejeté, identité durable et difficile à borner.
- **Certificat partagé** : rejeté, rayon d'impact trop large.
- **Identité dans le message Protobuf** : rejetée, l'identité vient du certificat.