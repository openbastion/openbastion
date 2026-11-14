# Architecture

| Page | Contenu |
|---|---|
| [`system-overview.md`](system-overview.md) | Résumé, vue en couches, catalogue des microservices, flux SSH illustratif, double bus, stack, exigences non fonctionnelles, risques |
| [`principles.md`](principles.md) | Les principes fondateurs et l'invariant : les secrets ne traversent jamais le control plane |
| [`system-context.md`](system-context.md) | C4 niveau 1 : le système et ses acteurs |
| [`containers.md`](containers.md) | C4 niveau 2 : les conteneurs et leur technologie |
| [`components.md`](components.md) | C4 niveau 3 : les composants de chaque conteneur |
| [`deployment-architecture.md`](deployment-architecture.md) | Modèle de déploiement et portabilité cloud-native |
| [`data-architecture.md`](data-architecture.md) | Modèle de données PostgreSQL : diagramme entité-relation, DDL, choix |
| [`data-access-orm-analysis.md`](data-access-orm-analysis.md) | Analyse « faut-il un ORM ? », à l'origine d'ADR-0029 et d'ADR-0030 |

Ces pages décrivent la **cible** autant que le MVP : le catalogue cite 35 services, le dépôt en construit 8. Ce qui est construit est tenu dans [`NOTES_SANDBOX.md`](../../NOTES_SANDBOX.md) et dans `.agents/architecture/known-gaps.md`. Le modèle de menace est dans [`../security/threat-model.md`](../security/threat-model.md) ; les décisions, dans [`../adr/`](../adr/README.md).

Les diagrammes (Mermaid) restent dans les pages qui les expliquent, où GitHub les rend ; ils n'ont pas de copie en fichier `.mmd`, qui divergerait.

## Pages prévues

| Page | Ce qu'il manque pour l'écrire |
|---|---|
| `identity-architecture.md`, `session-architecture.md`, `secrets-architecture.md`, `audit-architecture.md` | Leur contenu actuel tient dans le catalogue de [`system-overview.md`](system-overview.md), les composants de [`components.md`](components.md) et les ADR ; une page par domaine se justifiera quand un domaine dépassera le MVP (feuille de route, v0.0.1). |
| `network-architecture.md` | Le réseau du MVP est décrit par [`../security/network-security.md`](../security/network-security.md) et [`../deployment/tls-certificates.md`](../deployment/tls-certificates.md). |
| `diagrams/*.mmd` | Voir ci-dessus : un diagramme a une seule source. |


## Extension v0.0.3

Le framework d'agents distribués est défini par ADR-0102 à ADR-0110. Ses contrats sont dans proto/agent/v1 et sa revue STRIDE dédiée dans docs/security/threat-model-agents.md. Aucun binaire agent n'est réputé implémenté à ce stade.
