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
| Vue d’ensemble | `features/overview/Overview.tsx` | Composition alignée sur la référence : bandeau d’accueil, quatre cartes, panneaux Activité/Posture et tableau opérationnel des demandes en attente. Le graphique temporel reste un état explicite d’indisponibilité. | Comptes et demandes proviennent des routes publiques Vault/Broker. Les contrôles de rotation/épinglage portent sur la page de comptes chargée et indiquent ce périmètre. Aucun endpoint d’agrégats temporels, de sessions actives globales ou de score de risque n’est défini ; ne pas inventer ces séries ni ces scores. |
| Accès privilégiés | `features/accounts/Accounts.tsx`, `features/policies/Policies.tsx`, `features/sessions/PendingRequests.tsx` | Les ressources, comptes, politiques et demandes sont aujourd'hui distribués entre plusieurs vues ; la référence les regroupe sous une page à onglets et inventaire. | Le Vault expose des comptes paginés. Les demandes sont filtrées selon les droits du demandeur. Ne pas présenter un nombre global de demandes ou d'identités si l'API ne le garantit pas. |
| Sessions | `features/sessions/Sessions.tsx`, `SessionDetail.tsx`, `screen/ScreenViewer.tsx` | Shell et hiérarchie à deux panneaux repris : indicateurs de capacité, onglets, liste à gauche et détail à droite. La liste est explicitement celle des demandes à décider, pas une liste de sessions actives ; le terminal de démonstration n’est pas reproduit. | Le Broker ne fournit pas de listing global des sessions actives. La liste des demandes est filtrée selon le droit de décision ; une sélection utilise l’objet déjà autorisé et ne déclenche pas un GET qui franchirait la politique de lecture. Une recherche par ID reste soumise à `GET /sessions/{id}`. Aucun flux terminal SSH n’est exposé dans l’Admin UI. |
| Infrastructure | Aucun écran dédié. Le Security Center existe mais ne représente pas une topologie d'infrastructure. | Capture avec topologie, clusters, connecteurs, disponibilité, CPU/mémoire/stockage. | Aucun contrat Gateway recensé pour découverte de ressources, état de connecteurs ou métriques de cluster. Écran à différer jusqu'aux contrats backend ; aucune valeur illustrative en production. |
| Audit & conformité | `features/audit/Recording.tsx`, `VideoReplay.tsx`, `SecretInjectionReconciliation.tsx` | La référence propose journal d'audit, rapports, preuves et rétention. L'écran existant est centré sur les replays et le rapprochement d'injections. | Pas de route publique de recherche/liste globale des événements d'audit ni de génération de rapports de conformité. Les taux ISO/SOC/NIS2 de la maquette ne sont pas des certifications et ne sont pas calculables par les API actuelles. |
| Paramètres | `OperatorPreferencesDialog.tsx` et préférences locales | Les préférences opérateur existent ; les paramètres d'organisation, sécurité globale, IdP et intégrations de la capture ne sont pas un écran d'administration complet. | Aucun contrat public global de configuration du tenant n'a été identifié. Les préférences locales ne doivent pas être présentées comme une configuration de sécurité serveur. |
| Connexion | `features/login/Login.tsx` | Reprise de la composition 39/61, du panneau marque, du CTA SSO avant le formulaire, de la hiérarchie typographique, des champs et du pied de page. Le mot de passe peut être affiché/masqué. | Garder la sélection explicite du fournisseur quand plusieurs sont configurés ; aucune identité ou organisation d'exemple ne doit être préremplie. La récupération de mot de passe et les liens de confidentialité/conditions n'ont pas de route publique identifiée : leur activation fonctionnelle reste à concevoir, ils ne doivent pas simuler une action. |
| Vérification à deux facteurs | `features/login/SecondFactor.tsx` | TOTP et WebAuthn sont présents ; l’écran est aligné sur la composition du SVG : retour, pictogramme, identité du compte, six cases, validation et aide. | Conserver les contrats de challenge serveur et les règles WebAuthn. Aucun endpoint public de code de récupération n’est défini dans OpenAPI ou Authentication : ne pas afficher de lien qui simulerait cette fonction. Ne jamais simuler une validation MFA côté navigateur. |

## Garde-fous de contenu

- Les valeurs de la capture (24 sessions, 128 ressources, 86 identités, 98/100, 99,98 %, taux ISO/SOC/NIS2, etc.) sont des données de démonstration et ne doivent pas être reprises.
- Ne pas afficher « toutes les sessions sont chiffrées de bout en bout » : les garanties doivent reprendre exactement les frontières et mécanismes documentés par les ADR.
- Ne pas présenter un « accès direct impossible » comme propriété d'une topologie dessinée ; cette propriété est assurée par les chemins réseau et les proxies, pas par une illustration.
- Une métrique absente reste absente ; un refus API reste visible ; un résultat partiel indique sa pagination et son périmètre.
- Toute action sensible conserve confirmation explicite, contrôle d'autorisation serveur, feedback accessible et audit backend.

## Ordre de réalisation proposé

1. ~~**Socle de navigation et shell** : passer de la navigation horizontale actuelle à une navigation latérale responsive proche de la référence, sans créer de destinations factices. Garder les vues existantes, les favoris, préférences, palette, langues, focus management et thèmes.~~ Réalisé dans la PR #223 : sidebar, groupes de navigation, fil d’Ariane et menu utilisateur regroupant palette, langue, thème, préférences et déconnexion. Validation visuelle navigateur encore en attente.
2. ~~**Vue d’ensemble** : améliorer la composition avec les seules données réellement disponibles ; ajouter des accès rapides vers comptes et demandes ; ne pas créer de graphique d'activité avant un contrat d'agrégation fiable.~~ Réalisé dans la PR #223 : bandeau, quatre indicateurs, panneaux de pilotage et demandes à traiter. Le graphique agrégé reste explicitement indisponible tant que le contrat n’existe pas.
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
- La première implémentation suivait une capture 1440 × 1040 ; la référence de calques reçue ensuite (1440 × 1024) prévaut désormais : panneau gauche sombre et panneau droit clair, indépendamment du thème applicatif.
- Les flux locaux, LDAP, OIDC et MFA restent ceux de l'API publique. Le champ identifiant reste de type texte : certains annuaires acceptent un nom d'utilisateur qui n'est pas une adresse e-mail.
- Le lien « Mot de passe oublié ? » et les mentions Confidentialité/Conditions sont uniquement des éléments visuels de référence tant qu'aucune route/documentation publique n'existe ; aucune action factice n'est ajoutée.
- Tests ciblés après correction : `src/features/login/login.test.tsx` et `src/app/app.test.tsx` — 23 tests passés.
- Suite complète : 25 fichiers, 245 tests passés ; TypeScript et Vite build passés. Contraste des tokens et contrôle d'absence de couleurs littérales passés.
- Limite : aucune capture navigateur de comparaison pixel-à-pixel n'a encore été réalisée ; la validation visuelle reste à confirmer dans le navigateur à 1440 × 1040 et sur mobile.

## Référence finale de connexion — SVG en calques — 2026-11-16

- Le libellé `OpenBastion` du verrouillage de marque est forcé sur le token de texte clair du panneau gauche, indépendant du thème global ; le nom ne disparaît donc plus en thème sombre.
- Le SVG en calques `openbastion-auth-connexion.svg` remplace les captures précédentes comme référence de vérité : panneau gauche bleu nuit (`#0B192C`), panneau droit clair (`#F8FAFC`), formulaire de 440 px, champs et bouton SSO blancs (`#FFFFFF`), texte principal `#0F172A`, accent `#0F62FE`, séparateurs `#E2E8F0` et encart MFA `#EBF2FE`. Les tokens `--ob-color-login-*` appliquent cette composition indépendamment du thème global.
- Le bandeau global `LegalNotice` est supprimé de la page de connexion. La colonne gauche porte la mention complète `© 2026 OpenBastion — GNU Affero General Public License v3.0 (AGPL-3.0-only)` ; les liens source et licence sont alignés avec Confidentialité / Conditions d'utilisation sous le message d'aide.
- La case « Se souvenir de mon adresse e-mail » mémorise uniquement l'identifiant, uniquement après une connexion réussie et un consentement explicite ; le mot de passe et le jeton restent exclus du stockage navigateur.
- Le bandeau légal global reste présent sur l'espace authentifié et le retour OIDC ; cette correction ne réduit pas la visibilité des informations de licence dans ces parcours.
- Les huit SVG en calques transmis constituent les références de travail : connexion et validation MFA (1440 × 1024), puis Dashboard, Accès privilégiés, Sessions, Infrastructure, Audit et Paramètres (1440 × 1080). Seuls les calques de connexion sont traités dans cet incrément.

## Alignement du panneau gauche — 2026-11-16

- La géométrie reprend les repères du SVG : colonne gauche 560 px à 1440 px de large, retrait horizontal 56 px, marque en haut à 58 px, accroche à y≈264, carte sécurité à (56, 558) avec 448 × 200 px, pied ancré en bas.
- Le pictogramme de marque est spécifique à la connexion et reproduit le bouclier avec serrure du SVG ; le pictogramme générique à coche reste inchangé dans les autres vues.
- La typographie de l'accroche, du titre et du descriptif, ainsi que les espacements de la carte et les trois lignes de bénéfices, sont rapprochés de la référence. Le texte MFA reste exact : application selon la politique d'accès, pas une obligation universelle.
- Le pied reprend trois niveaux visuels sans importer les données fictives « ACME CORPORATION », « v2.8.0 » ou « hébergé en Union européenne ». Il affiche une mention produit, la possibilité de déploiement sur site ou cloud et la licence réelle.
- Les couleurs du panneau sont des tokens de design system, indépendants du thème global. La variante responsive tablette conserve un défilement vertical plutôt que de couper le panneau si la hauteur disponible est insuffisante.
- Tests ajoutés/ajustés pour le pictogramme de marque et le contenu réel du panneau. La comparaison navigateur pixel-à-pixel à 1440 × 1024 reste à confirmer.


## Vérification MFA — SVG en calques — 2026-11-17

- Référence utilisée : `openbastion-mfa-validation.svg` (1440 × 1024), fournie dans `/home/eldorplus/Downloads/Ecrans`. Le panneau de marque reprend le même composant que la connexion ; le panneau droit conserve le formulaire de 440 px et les tokens `--ob-color-login-*` indépendants du thème global.
- L'étape MFA dispose désormais de sa propre hiérarchie : retour à la connexion, badge smartphone, titre « Vérifiez votre identité », description, identifiant fourni lors de la connexion, six cases OTP, indication de renouvellement à 30 secondes, bouton « Vérifier et continuer » et aide administrateur.
- Les six cases sont une présentation d'un seul champ texte accessible, pas six champs indépendants : `autocomplete="one-time-code"`, clavier numérique, collage accepté, caractères non numériques supprimés, longueur plafonnée à six chiffres. Le code n'est soumis que lorsqu'il contient exactement six chiffres ; le serveur reste seul à vérifier le challenge et le TOTP.
- Les rôles exigeant WebAuthn uniquement gardent leur parcours clé sans champ TOTP. Quand les deux facteurs sont autorisés, la clé reste une alternative explicite. L'enrôlement TOTP/WebAuthn et l'ajout d'une clé de secours conservent leurs appels et leurs contrôles existants.
- Le retour à la connexion ne transmet aucune requête de vérification. L'identifiant affiché est celui saisi au login ; aucun compte de démonstration n'est prérempli.
- **Code de récupération non affiché** : aucun endpoint de vérification d'un code de récupération n'a été trouvé dans OpenAPI ni dans Authentication. Le lien de la maquette est donc omis plutôt que de simuler une capacité absente. Il nécessitera un contrat backend et ses tests avant d'être ajouté.
- Suite complète finale : `make ui-test ui-build` PASS — 25 fichiers, 249 tests ; TypeScript et Vite production PASS ; contrastes clair/sombre et `check-app-colors` PASS ; `git diff --check` PASS.
- Limite : aucune capture navigateur de comparaison pixel-à-pixel n'a été obtenue dans ce worktree ; les dimensions et la hiérarchie ont été reprises du SVG et vérifiées par le code/tests, mais le rendu réel à 1440 × 1024 et sur mobile reste à confirmer dans un navigateur.


## Sessions — onglets Historique, Enregistrements et Alertes — 2026-11-17

- Les onze SVG fournis dans `/home/eldorplus/Downloads/Ecrans` ont été déplacés dans `docs/ui/reference-screens/` pour les conserver dans le dépôt. Le dossier source est désormais vide. `README.md` décrit la provenance et l'état d'intégration de chaque écran.
- `openbastion-sessions-historique.svg`, `openbastion-sessions-enregistrements.svg` et `openbastion-sessions-alertes.svg` sont les trois maquettes dérivées de `openbastion-sessions.svg`, validées avant intégration.
- `Sessions.tsx` conserve le parcours existant sous « En direct » et ajoute la navigation accessible par les primitives Tabs partagées.
- Historique : `GET /sessions/search` avec bornes temporelles obligatoires (31 jours maximum), recherche facultative (3 caractères minimum), statut, protocole et pagination par curseur. Les autorisations et l'audit restent ceux du Broker ; aucun accès global n'est accordé par l'UI.
- Enregistrements : `GET /recordings/search` recherche du texte de commandes enregistrées sur une période. Le résultat est borné et peut être tronqué. Le bouton d'un résultat ouvre l'écran d'enregistrements existant (`GET /sessions/{id}/recording`) en réutilisant la navigation de l'Admin UI. Cette recherche ne prétend pas être un inventaire de tous les replays vidéo.
- Alertes : aucun contrat public de file d'alertes de session, de compteur non lu, de statut de traitement ou d'action d'acquittement n'est défini. L'onglet reste visible avec un badge « API requise » et explique la limite ; aucun compteur fictif, appel inventé ou bouton inopérant n'est ajouté. Les événements d'audit ne sont pas requalifiés en alertes.
- Les références originales et les trois variantes SVG sont archivées avec un index dans `docs/ui/reference-screens/README.md`.
- Les tests couvrent le chargement de l'historique, la recherche de commandes, le transfert vers le replay existant, l'absence d'appel non contractuel pour les alertes et le rejet d'une requête de recherche trop courte.


## Incrément shell partagé et Dashboard — 2026-11-17

- Le shell reprend la structure générale du SVG Dashboard : identité OpenBastion et contexte de l'espace de travail dans la sidebar, groupe principal « Espace de travail », groupe « Ressources », fil d'Ariane dans la topbar et identité utilisateur à droite. Les destinations non implémentées ne sont pas des liens factices.
- Le menu utilisateur regroupe palette de commandes, langue, thème, préférences et déconnexion. Le raccourci `Ctrl+K` reste pris en charge. La palette n'a plus de déclencheur dédié dans la topbar.
- Le Dashboard reprend le rythme visuel de la maquette avec bandeau, quatre indicateurs, deux panneaux côte à côte et une table. Il utilise exclusivement les API publiques existantes et signale l'absence de séries temporelles. Les demandes affichées sont uniquement celles de `GET /sessions?status=pending_approval`, donc celles que l'appelant est autorisé à décider.
- Les chiffres et libellés fictifs de la maquette (sessions actives globales, ressources totales, identités MFA, score Zero Trust, courbe SSH/RDP) ne sont pas repris. Le calcul local de rotation et d'épinglage est borné à la page Vault reçue ; l'UI affiche cette limite lorsque la page est partielle.
- Validation : `make ui-test ui-build` PASS — 26 fichiers, 259 tests ; TypeScript/Vite production PASS ; contraste clair/sombre et `check-app-colors` PASS ; `git diff --check` PASS.
- **Non vérifié** : capture navigateur, comparaison pixel-à-pixel, comportement responsive dans un navigateur réel et test lecteur d'écran. LT209227 ne dispose pas d'un navigateur headless installé dans cet environnement.


## Incrément Sessions — workspace à deux panneaux — 2026-11-17

- L'écran Sessions reprend les proportions de la référence (shell commun, quatre cartes d'état, onglets, panneau gauche étroit et détail droit). Le panneau gauche ne prétend pas lister les sessions actives : il présente les demandes en attente que `GET /sessions?status=pending_approval` autorise déjà l'appelant à décider.
- La sélection d'une demande utilise directement l'objet retourné par cette liste ; aucun `GET /sessions/{id}` additionnel n'est fait, car le droit de décider et le droit de lire une session sont deux frontières distinctes. La recherche manuelle par identifiant utilise le GET public et garde son refus visible.
- Le panneau droit expose les métadonnées et les actions déjà disponibles (approbation/refus avec confirmation, injection de secret selon les règles existantes, ouverture d'écran RDP/VNC, terminaison avec confirmation). Le terminal SSH de démonstration du SVG n'est pas reproduit : aucun flux terminal interactif SSH n'est fourni par l'Admin UI.
- Les cartes indiquent le nombre de demandes autorisées, l'absence d'API de listing actif global, la disponibilité de la recherche de commandes enregistrées et l'absence du contrat d'alertes. Aucun nombre illustratif de sessions actives, de commandes, de durée moyenne ou d'interruptions n'est repris.
- La création de demande reste disponible dans une disclosure et le bouton d'en-tête l'ouvre ; Historique, Enregistrements et Alertes conservent leurs composants et contrats précédents.

## Reprise shell — 2026-11-17

La référence Dashboard définit une composition latérale pleine hauteur : sidebar de 232 unités de dessin sur 1440, topbar démarrant à droite de la sidebar, champ de recherche au centre, actions globales et profil opérateur en bas de la sidebar. Le shell Admin UI reprend maintenant cette hiérarchie dans une grille viewport-height. Les liens Documentation et Centre d'aide pointent vers les guides versionnés du dépôt. Le menu Notifications est présent mais annonce l'absence d'API globale ; il ne simule aucun événement. Le thème clair est le défaut pour correspondre à la référence claire ; le thème sombre reste disponible explicitement.
