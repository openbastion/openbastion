# ADR-0093 — Une relecture lit plusieurs segments par requête

**Statut** `Proposé` · 12 novembre 2026 · demandé par le propriétaire du projet le 12 novembre 2026 : « Go pour le regroupement des images par segment ». La décision change ce que sert une lecture du Video Recorder (ADR-0070) et la granularité de son audit : son acceptation revient au propriétaire.

## Contexte

Une image n'est montrée à l'opérateur qu'après son acquittement par le Video Recorder (ADR-0070, ADR-0071 §4). Le proxy envoie donc **une image par segment** : il attend l'acquittement de chaque image avant de la montrer. Le Recorder stocke ainsi un segment par image.

La relecture lit un segment par requête (`GET /sessions/{id}/recording/video/segments/{first}`), donc **une requête par image**. Chaque requête est autorisée, écrite à l'audit (`recording.read`) avant d'être servie, puis déchiffrée.

**Ce que cela coûte, constaté le 12 novembre 2026 :**
- La Gateway limite les requêtes par adresse à 60 en rafale, puis une par seconde. Une relecture plus rapide qu'une image par seconde s'arrête donc en 429 au bout d'une soixantaine d'images. Dans le bac à sable, le budget a dû être élargi pour qu'un rejeu aille au bout.
- La session du propriétaire, 213 images, a demandé 213 requêtes, 213 autorisations et 213 événements d'audit.
- Avec les images partielles (ADR-0092), une image pèse souvent quelques centaines d'octets : le coût de la requête dépasse de loin celui de la donnée.

**Ce qui ne change pas :**
- ADR-0070 : chiffrement par segment, intégrité vérifiée avant de servir, lecture autorisée et auditée avant le déchiffrement, rien de servi sans audit.
- ADR-0071 §4 : l'image montrée est l'image acquittée, sans attendre davantage.

## Options

**A. Lire plusieurs segments par requête (recommandée).** Le Recorder sert, à partir de `first`, les segments stockés consécutifs, jusqu'à une borne, dans une seule réponse de `first` à `last`.
- Le stockage ne change pas : un segment par image, chacun chiffré et vérifié à part.
- Le schéma Protobuf ne change pas. La réponse le permet déjà (`first_sequence`, `last_sequence`, `frames`), et la Gateway comme l'Admin UI suivent déjà `last + 1`.
- L'enregistrement en direct ne change pas : aucune latence ajoutée.

**B. Regrouper à l'enregistrement** : le proxy envoie des segments de plusieurs images, jusqu'à 250 ms ou 4 Mio (ADR-0070 le permet).
- Une image attendrait l'acquittement de tout son segment : jusqu'à 250 ms de plus avant d'être montrée.
- Une perte d'acquittement emporterait plusieurs images à la fois.

**C. Un budget propre à la relecture, ou une limite plus large à la Gateway.** Le symptôme disparaît, mais il reste une requête, une autorisation et un événement d'audit par image. Le volume d'audit croît avec la longueur des sessions.

**D. Rien** : le rejeu d'une longue session reste coupé en 429, sauf à élargir le budget par adresse partout.

## Décision proposée : A

1. **Une lecture sert les segments consécutifs** à partir de `first` : tous ceux qui existent, dans l'ordre et sans trou, tant que la réponse reste sous ses bornes. La première borne atteinte arrête la lecture :
   - **4 Mio** de données d'images, la borne qu'applique déjà la Gateway ;
   - **600 images** : à 50 ms d'écart, une demi-minute de relecture. Un positionnement ne charge ainsi pas toute la session ;
   - la fin de l'enregistrement.
   Un segment qui ferait dépasser 4 Mio est laissé à la requête suivante ; il est toujours servi seul s'il est le premier.
2. **Une autorisation et un événement d'audit par réponse**, avant tout déchiffrement, comme aujourd'hui. L'événement porte la plage servie (`first`–`last`) dans ses détails bornés (ADR-0068) : on sait toujours qui a lu quoi. L'émetteur d'audit du Recorder n'envoie pas encore de détails : il faudra l'étendre.
3. **Intégrité segment par segment** : chaque segment stocké est vérifié (empreinte, puis déchiffrement authentifié, format, ADR-0070 et ADR-0092) avant d'entrer dans la réponse. Un seul défaut refuse **toute** la réponse : jamais de réponse à moitié vérifiée.
4. **`complete`** dit si l'enregistrement est scellé, comme aujourd'hui pour le dernier segment.
5. **Contrats** : ni le Protobuf, ni la route REST, ni l'Admin UI ne changent de forme. Seule la sémantique s'élargit : une réponse peut couvrir plusieurs segments stockés. L'OpenAPI le dit.

## Conséquences

- (+) **Estimation, à mesurer à la livraison** : une relecture de 213 images devrait demander une requête au lieu de 213, en images partielles comme en images entières tant qu'elles tiennent dans 4 Mio. La limite par adresse de la Gateway ne devrait plus couper un rejeu, et le budget élargi du bac à sable deviendrait inutile.
- (+) L'audit dit toujours qui a lu quoi, en un événement par plage plutôt qu'un par image.
- (+) Rien ne change pour l'enregistrement en direct ni pour l'invariant « montré = acquitté ».
- (−) Une réponse plus lourde : jusqu'à 4 Mio et 600 images à déchiffrer avant de répondre. La première image d'un rejeu arrive un peu plus tard. À mesurer.
- (−) L'audit perd la granularité par image : un événement couvre une plage. Un auditeur qui ne regarde que le début d'une plage est tout de même inscrit pour toute la plage.
- (−) Un segment corrompu au milieu d'une plage refuse toute la plage. Il faut recommencer la lecture juste après le segment fautif pour lire ce qui le suit ; l'Admin UI s'arrête là, comme aujourd'hui sur un segment invalide.

## Mise en œuvre envisagée

1. Video Recorder : lecture d'une plage bornée (dépôt PostgreSQL et mémoire), vérification de chaque segment, un audit par réponse avec sa plage. Tests de bornes, de trou, de segment corrompu au milieu, et mutations.
2. Gateway : la réponse à plusieurs segments est déjà acceptée (même borne de 4 Mio) ; test d'une plage.
3. Épreuve de bout en bout : une relecture d'une session réelle lue en quelques requêtes ; le budget élargi du bac à sable est retiré si la mesure le permet.

## Alternatives envisagées

- **B, regrouper à l'enregistrement** : écartée. Elle ajouterait jusqu'à 250 ms entre l'action de l'opérateur et ce qu'il voit, pour un gain qu'on obtient à la lecture sans rien coûter au direct.
- **C, un budget de lecture** : écartée comme remède. Elle laisse une requête et un audit par image, et ne fait que repousser la limite. Elle reste possible en complément.
- **D, rien** : écartée. Un rejeu coupé à la soixantième image n'est pas une relecture.
