# ADR-0068 — Les détails d'un événement d'audit sont bornés et protégés par le hash

**Statut** `Accepté` · 1ᵉʳ novembre 2026 · extension explicitement approuvée avec ADR-0067

## Contexte

ADR-0067 exige que le ticket d'une demande de session et de sa décision figure dans l'audit. Le contrat d'événement d'audit ne porte que l'acteur, l'action et la ressource ; détourner l'identifiant de ressource ou ajouter le ticket au texte d'action altérerait leur sens. Un champ ajouté sans être couvert par la chaîne de hash pourrait, lui, être modifié après écriture sans détection.

## Décision

1. `audit_events` reçoit une colonne JSONB `details`, ajoutée par migration idempotente. Les événements existants portent `{}`.
2. Les détails sont une map de 16 entrées au plus. Les clés ont 1 à 64 caractères `a-z`, chiffres, `_` ou `.` ; les valeurs font 1 à 256 octets en UTF-8 sans caractère de contrôle. Les erreurs nomment le champ et sa règle, jamais sa valeur.
3. Le format v4 conserve les champs et l'HMAC du format v3 et y ajoute les détails, triés par clé et encadrés de façon déterministe. Une fois la chaîne passée en v4, elle n'en redescend plus. Les formats v1 à v3 restent vérifiés comme avant.
4. Les détails sont persistés et archivés comme les autres champs d'événement. Leur transport HTTP/JSON et le contrat protobuf d'ingestion sont additifs.
5. Pour ADR-0067, le Session Broker envoie `{"ticket":"<référence>"}` pour les tickets valides, sur l'événement de demande et celui de décision. Une entrée ticket invalide est refusée et auditée sans sa valeur.

## Conséquences

- (+) Le ticket est lié cryptographiquement à l'acteur, à l'action, à la ressource et au résultat ; son changement est détecté par `VerifyChain`.
- (+) Les événements historiques, les archives sans détails et les émetteurs qui n'en ont pas besoin gardent leur représentation et leur vérification.
- (+) Les bornes empêchent que ce champ devienne un dépôt de texte arbitraire ou de secrets.
- (−) La première émission de détails fait évoluer le format de la chaîne ; tous les réplicas doivent connaître v4 avant que ce chemin soit utilisé.
- (−) Le champ n'est pas une zone de stockage général : il ne doit recevoir que des métadonnées nécessaires et non secrètes.

## Alternatives envisagées

- **Placer le ticket dans `resource_id`** : écarté, car cela remplacerait l'identifiant de session et rendrait l'événement ambigu.
- **Ajouter le ticket à l'action** : écarté, car cela crée une action différente par ticket et déforme le vocabulaire d'audit.
- **Ajouter des détails non signés** : écarté, car leur altération ne serait pas détectée par la vérification de chaîne.
- **Un champ dédié `ticket` dans chaque événement** : écarté, car il lierait l'Audit Service à un seul domaine ; une map bornée reste générique sans devenir libre.
