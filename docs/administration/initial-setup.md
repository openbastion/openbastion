# Configuration initiale


1. **Donner une identité à chaque service** (mTLS interne, obligatoire) — voir « Identité des services » ci-dessous.
2. **Bootstrap du premier compte administrateur** — créé automatiquement à l'installation si `bootstrapAdmin` est renseigné dans `values.yaml` ; désactivé après première connexion.
3. **Vérifier la fédération OIDC** : `GET /api/v1/auth/me` après une connexion de test doit renvoyer `identitySource: "oidc"` et le mapping correct de `username`/`displayName` (`docs/api/rest/openapi.yaml`, schéma `User`).
4. **Créer les premiers rôles** (`docs/administration/access-policies.md`).
5. **Politique d'enregistrement des sessions** — voir ci-dessous.
6. **Décider du break-glass** (désactivé par défaut) — voir « Accès d'urgence (break-glass) » ci-dessous.
