# Licence AGPL-3.0 et provenance

> Policy normative pour les contributions et dépendances. Elle ne remplace pas un avis juridique. En cas d'incertitude sur les droits, la provenance ou la compatibilité, suspendre l'intégration et demander une revue humaine documentée.

## 1. Licence du projet

1. Le code original OpenBastion est distribué sous **GNU Affero General Public License v3.0 only** (AGPL-3.0-only).
2. Le fichier racine LICENSE est le texte canonique de la licence. Ne pas le modifier pour changer l'identifiant SPDX ou ajouter des conditions.
3. Les métadonnées machine-readable du code et des paquets OpenBastion utilisent AGPL-3.0-only. La prose peut employer « AGPL-3.0 » lorsqu'elle désigne la famille de licence.
4. Une dépendance tierce conserve sa licence, ses mentions de copyright et ses conditions propres. La présence dans le dépôt ne la relicencie pas automatiquement sous AGPL.

## 2. Provenance obligatoire

Pour tout code, documentation, skill, police, icône, image, modèle, exemple ou autre ressource importée :
- enregistrer l'origine exacte (URL, dépôt, version ou commit) ;
- enregistrer les auteurs/copyrights et la licence attestée ;
- conserver les fichiers de licence et mentions exigés ;
- documenter les modifications et les fichiers concernés ;
- vérifier la compatibilité avant intégration et avant redistribution.

Ne jamais déduire une licence de la seule présence d'un fichier dans le dépôt, de son format, de son auteur apparent ou de la licence du projet.

Les éléments dont la provenance n'est pas établie restent **NON VÉRIFIÉS**. Ne pas les présenter comme originaux ou AGPL, ne pas supprimer ni réécrire leur licence par supposition. Leur redistribution doit être revue avant publication d'une version qui les contient.

## 3. Repères de compatibilité (à confirmer selon le cas concret)

| Licence/source | Règle de traitement |
| --- | --- |
| AGPL-3.0 | Compatible avec le projet sous les conditions AGPL applicables ; conserver les notices. |
| GPL-3.0 | Peut être combinée avec AGPL-3.0 selon la section 13 de l'AGPLv3 ; la combinaison est distribuée sous les conditions de l'AGPLv3. Vérifier la forme exacte de combinaison. |
| GPL-2.0-only | Incompatible avec une combinaison sous AGPL-3.0 ; ne pas intégrer comme partie d'une œuvre combinée. |
| MIT, BSD, ISC, CC0 | Généralement compatibles ; conserver les copyrights, textes de licence et notices requis. |
| Apache-2.0 | Généralement compatible avec AGPLv3 ; conserver le texte de licence, les notices et les fichiers NOTICE applicables. |
| MPL-2.0, LGPL, licences à copyleft faible | Revue de compatibilité obligatoire selon le mode de liaison, les fichiers modifiés et les obligations de redistribution. |
| SSPL, licences « source available », licences propriétaires ou personnalisées | Aucune compatibilité présumée. Revue juridique et autorisation explicite requises avant intégration. |

Cette matrice est un repère opérationnel, pas une autorisation automatique. Une dépendance utilisée séparément dans un agrégat peut avoir un traitement différent d'un composant incorporé ou lié dans une œuvre combinée.

## 4. Distribution et interfaces réseau

- Fournir les textes de licence et notices des composants tiers dans les distributions concernées.
- Pour toute version modifiée mise à disposition pour interaction à distance, examiner et satisfaire l'obligation de mise à disposition du code source correspondant prévue par la section 13 de l'AGPLv3.
- Examiner les obligations de notices légales des interfaces interactives au regard de la section 5(d) de l'AGPLv3.
- Ne pas promettre qu'un lien vers la branche main satisfait l'obligation de source : la source doit correspondre à la version réellement déployée.

## 5. Métadonnées et contrôles

- Utiliser AGPL-3.0-only dans les champs SPDX des paquets et documents machine-readable du code OpenBastion.
- Maintenir les notices tierces dans THIRD_PARTY_NOTICES.md et les éléments de provenance dans docs/licensing/.
- Avant publication, générer l'inventaire des licences des dépendances Go/npm et des images/ressources distribuées ; conserver un SBOM et faire échouer la CI sur les licences interdites ou les métadonnées manquantes après revue de la politique.
- Une licence inconnue, contradictoire ou absente bloque l'approbation de la ressource, pas sa suppression automatique.
