# Références visuelles OpenBastion

Ces SVG sont les sources de conception fournies pour l'alignement de l'Admin UI. Ils sont conservés dans le dépôt pour assurer leur traçabilité et permettre leur consultation sans dépendre du dossier Downloads d'un poste de développement.

| Fichier | Écran | Statut |
|---|---|---|
| `openbastion-auth-connexion.svg` | Connexion | Intégré dans l'Admin UI |
| `openbastion-mfa-validation.svg` | Vérification MFA | Intégré dans l'Admin UI |
| `openbastion-sessions.svg` | Sessions — écran de base | Intégré dans l'Admin UI : en-tête, quatre indicateurs, onglets, espace à deux panneaux (demandes à décider, détail) |
| `openbastion-sessions-historique.svg` | Sessions — Historique | Intégré : en-tête dédié, indicateurs, filtres, tableau de référence et pagination par curseur |
| `openbastion-sessions-enregistrements.svg` | Sessions — Enregistrements | Intégré : bibliothèque et aperçu ; recherche des commandes SSH et ouverture du replay réelles |
| `openbastion-sessions-alertes.svg` | Sessions — Alertes | Intégré : en-tête, indicateurs et panneau « alertes récentes » ; contrat API de file d'alertes manquant, état explicite |
| `openbastion-dashboard.svg` | Vue générale | Shell et Dashboard React intégrés ; séries temporelles signalées comme indisponibles faute de contrat API |
| `openbastion-acces-privilegies.svg` | Accès privilégiés | À intégrer |
| `openbastion-audit-conformite.svg` | Audit et conformité | À intégrer |
| `openbastion-infrastructure.svg` | Infrastructure | À intégrer |
| `openbastion-parametres.svg` | Paramètres | À intégrer |

Le shell partagé et le Dashboard ont été rapprochés de la référence Dashboard. Les trois maquettes Sessions ont été dérivées de la référence Sessions, avec les mêmes dimensions et la même structure de navigation. Les données de maquette sont illustratives et ne constituent pas des métriques de production ni des contrats d'API.

L'implémentation React doit rester bornée aux routes documentées dans `docs/api/rest/openapi.yaml`. En particulier, aucune API publique ne fournit actuellement une file d'alertes de sessions, un état de traitement ou un compteur d'alertes non lues : la maquette Alertes est conservée comme référence, mais l'interface indique cette limite sans inventer de compteur ni d'action.
