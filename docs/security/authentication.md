# Sécurité de l'authentification

- **Émission de jetons** : Keycloak comme IdP de plateforme (ADR-0007), JWT à courte durée pour toute session opérateur.
- **Fédération externe** : LDAP, AD, Entra ID, OIDC, SAML délèguent l'authentification sans dupliquer de logique cryptographique par connecteur (ADR-0007).
- **MFA** (v1.0) : TOTP, WebAuthn/FIDO2, clés de sécurité, Passkeys, carte à puce/PKI — en MVP, le MFA est délégué au fournisseur OIDC externe (`docs/roadmap.md` §2), pas encore natif.
- **Protection anti brute-force** : verrouillage progressif après échecs répétés sur `/auth/login`, limité par IP et par compte, avec back-off exponentiel — à implémenter au niveau de l'Authentication Service, jamais laissé à la seule discrétion du proxy edge.

**Depuis ADR-0062** : TOTP natif pour les rôles de `MFA_REQUIRED_ROLES` (comptes locaux et d'annuaire), enrôlé par un code d'administrateur — voir [`../administration/second-factor.md`](../administration/second-factor.md). **Limite connue MVP (antérieure)** : sans MFA natif, la robustesse de l'authentification dépend entièrement du fournisseur OIDC configuré — à documenter explicitement dans `docs/administration/` comme prérequis de déploiement.
