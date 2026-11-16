# Audit des écrans de référence UX Pilot

Date : 2026-11-16
Source : archive `OpenBastion-Ecrans-Extraits.zip`, huit captures PNG 1440 × 1040.
Périmètre : comparaison avec `web/admin-ui` après intégration de `origin/main` au commit `0925dfc`.

Cet audit est réalisé hors UX Pilot. Les captures sont des références visuelles, pas une spécification d'API ni une preuve de fonctionnalités disponibles.

## Décision de réalisation

Reprendre la direction visuelle (navigation latérale persistante, hiérarchie typographique, surfaces, densité, états, palette et composition) sans recopier les chiffres, données métier ou capacités non prouvés. Toute donnée affichée doit provenir d'une réponse de l'API publique, être explicitement signalée comme indisponible, ou être retirée de l'écran. L'Admin UI reste cliente de la Gateway same-origin ; aucune connexion directe aux services, bases, bus ou stockages.

Les écrans doivent rester accessibles au clavier, traduits FR/EN, responsive et compatibles avec les thèmes clair/sombre déjà présents. Réutiliser `@openbastion/design-tokens`, `@openbastion/ui` et `@openbastion/icons`. Ne pas ajouter de dépendance UI applicative.

## Matrice de correspondance

| Capture de référence | Implémentation existante | Écart visuel/fonctionnel constaté | Limite API à respecter |
|---|---|---|---|
| Vue d’ensemble | `features/overview/Overview.tsx` | La page actuelle expose trois indicateurs et un panneau de périmètre ; la référence propose quatre KPI, un graphique d'activité, une posture de sécurité et les sessions récentes. | La liste publique du Broker ne sert que `status=pending_approval`. Aucun endpoint d'agrégats temporels, de sessions actives globales ou de score de posture n'est défini. Ne pas inventer ces séries ni ces scores. |
| Accès privilégiés | `features/accounts/Accounts.tsx`, `features/policies/Policies.tsx`, `features/sessions/PendingRequests.tsx` | Les ressources, comptes, politiques et demandes sont aujourd'hui distribués entre plusieurs vues ; la référence les regroupe sous une page à onglets et inventaire. | Le Vault expose des comptes paginés. Les demandes sont filtrées selon les droits du demandeur. Ne pas présenter un nombre global de demandes ou d'identités si l'API ne le garantit pas. |
| Sessions | `features/sessions/Sessions.tsx`, `SessionDetail.tsx`, `screen/ScreenViewer.tsx` | La référence juxtapose liste de sessions actives, terminal de lecture seule, métadonnées et actions. La page actuelle privilégie demandes à approuver, recherche par ID et écran interactif. | Le Broker ne fournit pas de listing global des sessions actives. La consultation par ID reste autorisée selon la politique. Ne pas simuler un terminal ou exposer une session sans lecture autorisée. |
| Infrastructure | Aucun écran dédié. Le Security Center existe mais ne représente pas une topologie d'infrastructure. | Capture avec topologie, clusters, connecteurs, disponibilité, CPU/mémoire/stockage. | Aucun contrat Gateway recensé pour découverte de ressources, état de connecteurs ou métriques de cluster. Écran à différer jusqu'aux contrats backend ; aucune valeur illustrative en production. |
| Audit & conformité | `features/audit/Recording.tsx`, `VideoReplay.tsx`, `SecretInjectionReconciliation.tsx` | La référence propose journal d'audit, rapports, preuves et rétention. L'écran existant est centré sur les replays et le rapprochement d'injections. | Pas de route publique de recherche/liste globale des événements d'audit ni de génération de rapports de conformité. Les taux ISO/SOC/NIS2 de la maquette ne sont pas des certifications et ne sont pas calculables par les API actuelles. |
| Paramètres | `OperatorPreferencesDialog.tsx` et préférences locales | Les préférences opérateur existent ; les paramètres d'organisation, sécurité globale, IdP et intégrations de la capture ne sont pas un écran d'administration complet. | Aucun contrat public global de configuration du tenant n'a été identifié. Les préférences locales ne doivent pas être présentées comme une configuration de sécurité serveur. |
| Connexion | `features/login/Login.tsx` | Reprise de la composition 39/61, du panneau marque, du CTA SSO avant le formulaire, de la hiérarchie typographique, des champs et du pied de page. Le mot de passe peut être affiché/masqué. | Garder la sélection explicite du fournisseur quand plusieurs sont configurés ; aucune identité ou organisation d'exemple ne doit être préremplie. La récupération de mot de passe et les liens de confidentialité/conditions n'ont pas de route publique identifiée : leur activation fonctionnelle reste à concevoir, ils ne doivent pas simuler une action. |
| Vérification à deux facteurs | `features/login/SecondFactor.tsx` | TOTP et WebAuthn sont présents ; la capture montre six cases TOTP et le chemin de récupération. | Conserver les contrats de challenge serveur, les règles WebAuthn et le code de secours existants. Ne jamais simuler une validation MFA côté navigateur. |

## Garde-fous de contenu

- Les valeurs de la capture (24 sessions, 128 ressources, 86 identités, 98/100, 99,98 %, taux ISO/SOC/NIS2, etc.) sont des données de démonstration et ne doivent pas être reprises.
- Ne pas afficher « toutes les sessions sont chiffrées de bout en bout » : les garanties doivent reprendre exactement les frontières et mécanismes documentés par les ADR.
- Ne pas présenter un « accès direct impossible » comme propriété d'une topologie dessinée ; cette propriété est assurée par les chemins réseau et les proxies, pas par une illustration.
- Une métrique absente reste absente ; un refus API reste visible ; un résultat partiel indique sa pagination et son périmètre.
- Toute action sensible conserve confirmation explicite, contrôle d'autorisation serveur, feedback accessible et audit backend.

## Ordre de réalisation proposé

1. **Socle de navigation et shell** : passer de la navigation horizontale actuelle à une navigation latérale responsive proche de la référence, sans créer de destinations factices. Garder les vues existantes, les favoris, préférences, palette, langues, focus management et thèmes.
2. **Vue d’ensemble** : améliorer la composition avec les seules données réellement disponibles ; ajouter des accès rapides vers comptes et demandes ; ne pas créer de graphique d'activité avant un contrat d'agrégation fiable.
3. **Accès privilégiés** : clarifier la navigation entre comptes, politiques et demandes, et améliorer la densité de l'inventaire sans fusionner des autorisations distinctes.
4. **Sessions** : préserver le modèle d'accès par ID et les contrôles existants ; ne pas créer de listing global tant que le Broker ne le supporte pas.
5. **Audit** : présenter clairement replays et rapprochement des injections ; journal global et rapports restent bloqués par l'absence de contrat API.
6. **Connexion/MFA** : alignement visuel sans changement de protocole ni de logique d'authentification.
7. **Infrastructure et paramètres tenant** : attendre des API dédiées, autorisées et auditées avant d'exposer des écrans d'administration.

## Vérifications de référence

Sur le worktree isolé, avant toute modification :

- `make ui-test ui-build` : PASS.
- Vitest : 25 fichiers, 243 tests passés.
- Build Vite/TypeScript : PASS.
- Contraste des tokens clair/sombre : contrôles du package design tokens PASS.
- Aucun fichier du checkout principal ni des worktrees de sécurité n'a été modifié.

## Incrément connexion — 2026-11-16

- La branche `feat/ui-reference-alignment` a été rebasée sur `origin/main` (`0925dfc`, PR #220 intégrée) ; les modifications locales ont été restaurées sans conflit.
- L'écran de connexion suit désormais les proportions, l'ordre des éléments et les couleurs de la capture 1440 × 1040 ; les couleurs spécifiques sont définies dans les tokens sémantiques `--ob-color-login-*`, avec variantes clair/sombre.
- Les flux locaux, LDAP, OIDC et MFA restent ceux de l'API publique. Le champ identifiant reste de type texte : certains annuaires acceptent un nom d'utilisateur qui n'est pas une adresse e-mail.
- Le lien « Mot de passe oublié ? » et les mentions Confidentialité/Conditions sont uniquement des éléments visuels de référence tant qu'aucune route/documentation publique n'existe ; aucune action factice n'est ajoutée.
- Tests ciblés après correction : `src/features/login/login.test.tsx` et `src/app/app.test.tsx` — 23 tests passés.
- Suite complète : 25 fichiers, 245 tests passés ; TypeScript et Vite build passés. Contraste des tokens et contrôle d'absence de couleurs littérales passés.
- Limite : aucune capture navigateur de comparaison pixel-à-pixel n'a encore été réalisée ; la validation visuelle reste à confirmer dans le navigateur à 1440 × 1040 et sur mobile.
