# Vue d'ensemble de la sécurité

## Rappel des trois invariants (`docs/architecture/principles.md`)

1. **Zero Standing Privilege** — aucun compte cible n'a de credential statique connu d'un humain.
2. **No Direct Access** — aucun client ne dialogue directement avec une cible ; tout passe par un proxy.
3. **Full Auditability** — chaque action produit un événement signé et chaîné.

Tout le reste de ce guide explique comment ces trois invariants sont concrètement appliqués et comment les vérifier.

## Sécurité transverse

| Domaine | Mesure |
|---|---|
| Transport | TLS partout ; mTLS obligatoire pour tout trafic inter-services. |
| Autorisation | RBAC (rôles) + ABAC (attributs contextuels : heure, IP, risque) combinés. |
| Chiffrement au repos | AES-256 pour secrets, enregistrements vidéo/commande, exports. |
| Hachage | Argon2id pour tout secret applicatif nécessitant un hash. |
| Identité de session | JWT courte durée, renouvellement via OIDC. |
| PKI | Rotation automatique des certificats internes (courte durée, réémission continue). |
| Applicatif | Protections CSRF, XSS, SSRF, et limitation des tentatives (anti brute-force) sur toutes les surfaces exposées. |
