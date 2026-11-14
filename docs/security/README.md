# Sécurité

Pour le responsable sécurité, l'auditeur et le contributeur qui touche à une garantie. Les invariants que le code ne doit jamais affaiblir sont dans [`security-overview.md`](security-overview.md) ; **ce que le MVP ne garantit pas** est dans [`known-limitations.md`](known-limitations.md), à lire avant toute mise en production.

| Page | Contenu |
|---|---|
| [`security-overview.md`](security-overview.md) | Les trois invariants, la sécurité transverse |
| [`threat-model.md`](threat-model.md) | Modèle de menace global |
| [`threat-model-agents.md`](threat-model-agents.md) | Analyse STRIDE/DREAD des Network Agent et Security Agent, frontières de confiance et plan de vérification v0.0.3 |
| [`network-security.md`](network-security.md) | Sécurité du transport (mTLS interne, TLS en bordure) |
| [`authentication.md`](authentication.md) | Authentification |
| [`authorization-rbac-abac.md`](authorization-rbac-abac.md) | Autorisation (RBAC dans le MVP) |
| [`secrets-management.md`](secrets-management.md) | Secrets : chiffrement, scopes, purge |
| [`secret-injection-step-up-contract.md`](secret-injection-step-up-contract.md) | MFA step-up ADR-0097 : défis TOTP/WebAuthn liés à l'action et routes mTLS internes Authentication implémentés ; orchestration Broker non livrée |
| [`key-management.md`](key-management.md) | Clés de chiffrement : clé locale ou Transit d'OpenBao, mise en place, migration, pannes (ADR-0049) |
| [`secure-development.md`](secure-development.md) | Sécurité applicative |
| [`session-security.md`](session-security.md) | Couche proxy : clé d'hôte, enregistrement, révocation |
| [`audit-integrity.md`](audit-integrity.md) | Intégrité de l'audit : chaîne à clé, ancrage, archives |
| [`hardening.md`](hardening.md) | Durcissement du déploiement |
| [`vulnerability-management.md`](vulnerability-management.md) | Gestion des vulnérabilités et divulgation responsable |
| [`known-limitations.md`](known-limitations.md) | Limites connues du périmètre MVP |

## Pages prévues

| Page | État |
|---|---|
| `zero-trust.md` | Les principes sont dans [`../architecture/principles.md`](../architecture/principles.md), leur mise en œuvre dans [`network-security.md`](network-security.md) (ADR-0010). |
| `cryptography.md`, `certificate-management.md` | Couverts aujourd'hui par [`secrets-management.md`](secrets-management.md), [`audit-integrity.md`](audit-integrity.md) et [`../deployment/tls-certificates.md`](../deployment/tls-certificates.md) ; la KEK est locale (`LocalKMS`), un vrai KMS/HSM est au backlog. |
| `security-testing.md` | Voir [`../development/testing.md`](../development/testing.md). |
| `incident-response.md`, `security-advisories.md`, `vulnerability-disclosure.md` | Aucun avis publié ; la divulgation est décrite dans [`vulnerability-management.md`](vulnerability-management.md). |
