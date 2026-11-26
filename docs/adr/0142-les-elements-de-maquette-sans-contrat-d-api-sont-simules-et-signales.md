# ADR-0142 — Les éléments de la maquette sans contrat d'API sont simulés, signalés et isolés

**Statut** `Proposé` · 26 novembre 2026 · pas encore accepté : il faut le go du propriétaire du projet. Cet ADR était demandé sous le numéro 0137, déjà pris par la navigation adressable ; il prend le numéro libre suivant.

**Contexte** — La maquette de l'Admin UI (archives `openbastion-admin-ui` et `-v2`) montre des éléments que l'API publique ne peut pas produire : le RTT et les FPS d'une session, la prise en main (partagée ou exclusive), l'ouverture d'une session administrative, le tiroir d'inspection d'un flux et des événements d'audit structurés. Il n'existe ni flux de sessions actives, ni métriques de transport, ni route de lecture de l'audit (ADR-0137 et `docs/ui/reference-screens/` : « une carte qui ne peut pas être remplie dit ce qui manque »). Reprendre la maquette telle quelle ferait afficher des chiffres inventés comme s'ils étaient mesurés.

**Décision**

1. Ces éléments sont rendus avec des **données simulées**, définies à un seul endroit : `web/admin-ui/src/features/mockup/simulatedData.ts`. Elles sont statiques, ne partent jamais vers l'API, ne sont jamais stockées, et sont perdues au rechargement.
2. Toute surface qui les affiche porte le badge visible « Données simulées » (`SimulatedBadge`), avec une explication au survol. Aucun chiffre simulé n'apparaît dans une carte d'indicateur ni dans un tableau alimenté par l'API.
3. Elles ne sont montées que dans deux endroits : l'onglet *En direct* de Sessions (`SimulatedSessions` : tableau RTT/FPS, prise en main, session admin, tiroir d'inspection) et l'onglet *Journal d'audit* (`SimulatedAuditEvents`). Aucune action simulée n'appelle le Vault, le Session Broker ni les politiques : elles ne donnent aucun accès réel.
4. Quand un contrat réel existe (flux de sessions, métriques, prise en main, audit lisible), l'élément simulé correspondant est remplacé, puis le dossier `features/mockup/` est supprimé. Chaque contrat fera son propre ADR, avec ses invariants (prise en main : identité, audit fail-closed, enregistrement obligatoire).

**Conséquences**

- (+) L'interface de la maquette est relisible sans toucher au contrat d'API ni affaiblir un invariant ; le retrait est une suppression de dossier et de deux lignes de montage.
- (−) Une capture d'écran ou une démonstration peut être prise pour des données réelles malgré le badge ; le badge est le seul garde-fou.
- (−) Les éléments simulés ne sont pas filtrés par capacité (ADR-0131) puisqu'aucune action réelle n'existe derrière.
- (−) Les actions Accès privilégiés de la maquette n'ont pas d'élément simulé : aucune n'est absente de l'API.

**Alternatives envisagées**

- **Ne rien afficher, dire ce qui manque** : conforme aux références, mais ne permet pas de relire la maquette ; retenu seulement après la mise en œuvre réelle.
- **Mettre un indicateur de fonctionnalité** : ajoute un réglage qui peut être activé en production ; écarté tant qu'aucune politique ne le gouverne.
