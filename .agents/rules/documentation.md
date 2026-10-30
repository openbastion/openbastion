# Documentation

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

1. **ADR** (`docs/architecture/OpenBastion_03_ADR.md`) : `Contexte / Décision / Conséquences / Alternatives envisagées`, ligne dans l'index, statut. Les conséquences distinguent `(+)` (mesuré) et `(−)` (**toutes** les limites). `Accepté` seulement avec le go de l'utilisateur.
2. Pour toute fonctionnalité : ce qu'elle fait **et ce qu'elle ne fait pas** (section « Ce que cela ne fait PAS » de `NOTES_SANDBOX.md`), les choix renversables, les risques résiduels.
3. Dans le **même commit** que le code : ADR, `NOTES_SANDBOX.md` (section + état des tests), Guide Sécurité (§12), guide Administrateur (configuration, dépannage), Guide HA/PRA si la disponibilité ou la reprise change, Guide Développeur si le geste change, OpenAPI (doc 05), interfaces (doc 07 et `proto/`), modèle de données (doc 06), `README`, et les instructions des agents (`architecture/`, `settings/`…) que le changement rend fausses.
4. Une limite refermée se **barre** (`~~…~~`) avec ce qui l'a refermée ; elle ne s'efface pas.
5. Mermaid pour les diagrammes ; tableaux pour les comparaisons ; YAML validé par un vrai analyseur (`python3 -I` + `yaml.safe_load` si PyYAML est là ; sinon un petit programme Go sur `gopkg.in/yaml.v3`, présent dans le cache de modules du codespace, construit dans le répertoire temporaire de la session — jamais dans le dépôt).
6. Un fait documenté (port, variable, comportement, nombre) est **vérifiable dans le code** ou mesuré dans la session ; vérifie avant d'écrire.
