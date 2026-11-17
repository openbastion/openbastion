# Références visuelles OpenBastion

Ces SVG sont les sources de conception fournies pour l'alignement de l'Admin UI. Ils sont conservés dans le dépôt pour assurer leur traçabilité et permettre leur consultation sans dépendre du dossier Downloads d'un poste de développement.

| Fichier | Écran | Statut |
|---|---|---|
| `openbastion-auth-connexion.svg` | Connexion | Intégré dans l'Admin UI |
| `openbastion-mfa-validation.svg` | Vérification MFA | Intégré dans l'Admin UI |
| `openbastion-sessions.svg` | Sessions — écran de base | Référence de l'écran Sessions |
| `openbastion-sessions-historique.svg` | Sessions — Historique | Maquette validée et onglet React intégré |
| `openbastion-sessions-enregistrements.svg` | Sessions — Enregistrements | Maquette validée ; recherche des commandes SSH et ouverture du replay intégrées |
| `openbastion-sessions-alertes.svg` | Sessions — Alertes | Maquette validée et écran d'état intégré ; contrat API de file d'alertes manquant |
| `openbastion-dashboard.svg` | Vue générale | À intégrer |
| `openbastion-acces-privilegies.svg` | Accès privilégiés | À intégrer |
| `openbastion-audit-conformite.svg` | Audit et conformité | À intégrer |
| `openbastion-infrastructure.svg` | Infrastructure | À intégrer |
| `openbastion-parametres.svg` | Paramètres | À intégrer |

Les trois maquettes Sessions ont été dérivées de la référence Sessions, avec les mêmes dimensions et la même structure de navigation. Les données de maquette sont illustratives et ne constituent pas des métriques de production ni des contrats d'API.

L'implémentation React doit rester bornée aux routes documentées dans `docs/api/rest/openapi.yaml`. En particulier, aucune API publique ne fournit actuellement une file d'alertes de sessions, un état de traitement ou un compteur d'alertes non lues : la maquette Alertes est conservée comme référence, mais l'interface indique cette limite sans inventer de compteur ni d'action.
