# ADR-0077 — Modulariser les workflows GitHub Actions derrière une porte de validation stable

**Statut** `Accepté` · accepté par le propriétaire du projet le 7 novembre 2026

**Contexte**

La CI actuelle est définie dans un unique `.github/workflows/ci.yml`. Elle porte plusieurs responsabilités indépendantes et huit contrôles obligatoires :

- `version` : validation de `VERSION` et cohérence du tag de release ;
- `go` : génération/proto, build, vet, gofmt, tests unitaires ;
- `race` : tests Go sous `-race` ;
- `integration` : intégration sur processus réels sans base ;
- `postgres` : tests unitaires avec PostgreSQL, tests dédiés et intégration avec base ;
- `ui` : tests Vitest et build de l'Admin UI ;
- `vulnerabilities` : `govulncheck` et `npm audit` ;
- `images` : analyse Trivy des images.

Le workflow concentre ainsi l'orchestration, les environnements, les outils et les commandes de plusieurs domaines. Cette organisation rend les changements transverses plus difficiles à relire et à faire évoluer. Elle ne doit toutefois pas conduire à multiplier les workflows indépendants déclenchés chacun par les mêmes événements, ni à perdre les garanties déjà établies par ADR-0047, ADR-0052, ADR-0059, ADR-0060 et ADR-0063.

La protection de branche connaît actuellement les huit noms de jobs ci-dessus. Elle exige les contrôles de statut et l'actualisation de la branche avant fusion. Une modification des noms de jobs ou leur extraction peut donc rendre la règle incohérente si elle est faite avant d'avoir vérifié les nouveaux contrôles sur une pull request réelle.

**Décision**

1. **Conserver un workflow d'entrée unique** : `.github/workflows/ci.yml` reste le point d'entrée événementiel pour les `push` sur `main`, les `pull_request`, les tags de release `v*` et l'exécution planifiée hebdomadaire. Il porte les permissions minimales, la concurrence et les variables communes.
2. **Extraire les responsabilités par domaine** dans des workflows réutilisables appelés avec `workflow_call` :
   - `go.yml` : version, build, vet, gofmt, tests unitaires et tests sous `-race` ;
   - `integration.yml` : intégration sur processus réels sans base ;
   - `postgres.yml` : tests nécessitant PostgreSQL ;
   - `frontend.yml` : tests et build des interfaces web ;
   - `security.yml` : `govulncheck` et `npm audit` ;
   - `containers.yml` : construction et analyse des images avec Trivy.
   
   Les frontières définitives et les dépendances entre ces workflows seront confirmées pendant l'implémentation, sans changer la couverture des contrôles. Le contrôle `version` reste obligatoire et peut être placé dans le workflow Go ou dans un workflow de validation dédié si cela rend son contrat plus clair.
3. **Mutualiser uniquement le bootstrap technique** avec des actions composites locales sous `.github/actions/` lorsque plusieurs domaines partagent réellement la même séquence (par exemple installation/configuration Go ou Node). Les commandes métier restent explicites dans les workflows et le Makefile demeure la source de vérité des commandes de build et de test.
4. **Créer une porte de validation unique et stable** dans le workflow d'entrée : workflow nommé `CI`, job nommé `Required checks`, attendu sous le contexte GitHub `CI / Required checks`. Ce job dépend de tous les workflows spécialisés et utilise `if: always()` afin de s'exécuter même si un contrôle amont échoue, est annulé ou est ignoré. Il réussit uniquement si chacun des résultats attendus est exactement `success`. Tout résultat `failure`, `cancelled` ou `skipped`, ainsi que toute absence de résultat attendu, fait échouer la porte.
5. **Garder la liste des contrôles exhaustive** : les huit contrôles actuellement requis restent exécutés et bloquants. L'extraction ne supprime, ne dégrade et ne rend optionnel aucun contrôle. Le test Compose reste hors de la CI conformément à ADR-0033.
6. **Préserver les garanties de sécurité et de reproductibilité** :
   - actions tierces épinglées par SHA complet, avec l'étiquette de version en commentaire ;
   - images conteneurs épinglées par digest ;
   - permissions minimales, `contents: read` par défaut et `persist-credentials: false` au checkout ;
   - aucun secret réel du dépôt dans les tests ;
   - aucune dépendance d'un workflow appelé à un autre groupe de concurrence partagé qui pourrait annuler une exécution sœur ;
   - les événements `push`, `pull_request`, `schedule` et tags conservent leur couverture actuelle.
7. **Migrer les Required status checks en deux temps** :
   - d'abord créer et exécuter la nouvelle porte sur une pull request réelle, puis vérifier dans GitHub le nom exact du check run, son application émettrice et son comportement lorsque chaque dépendance est en échec, annulée ou ignorée ;
   - seulement après cette preuve, remplacer les huit anciens contextes requis par le seul contexte `CI / Required checks`.
   
   Ne jamais retirer les anciens contextes requis avant que le nouveau soit visible et validé. Ne pas maintenir durablement les anciens et le nouveau jeu de contextes comme exigences simultanées.
8. **Conserver les deux protections de fusion** : `Require status checks to pass before merging` reste activé et exige `CI / Required checks` ; `Require branches to be up to date before merging` reste également activé. Cette seconde option est le mode strict de fraîcheur de branche, pas un contrôle de statut et ne remplace pas le premier réglage.
9. **Ne pas introduire de merge queue dans cet incrément**. Si elle est adoptée ultérieurement, ajouter et valider explicitement l'événement `merge_group` et ses contrôles avant de l'activer.

**Conséquences**

- (+) Les responsabilités Go, intégration, PostgreSQL, frontend, sécurité et images peuvent évoluer indépendamment tout en restant orchestrées par une seule CI.
- (+) La protection de branche dépend d'un contrat stable, indépendant des noms internes et du nombre de jobs spécialisés.
- (+) Un échec, une annulation ou un job ignoré ne peut pas être masqué par le job de synthèse.
- (+) La CI conserve ses événements, sa couverture, ses contrôles de sécurité et ses épinglages existants.
- (−) La migration demande une pull request de validation et une mise à jour manuelle des règles GitHub après observation du nom de check réel.
- (−) Le job de synthèse doit être maintenu en cohérence avec l'ensemble des dépendances ; l'ajout d'un nouveau contrôle obligatoire doit l'ajouter explicitement à la porte.
- (−) Les workflows réutilisables ajoutent une couche d'indirection. Les noms, entrées et dépendances doivent rester simples et documentés.
- (−) Le mode strict peut imposer de relancer les contrôles lorsqu'une branche cible évolue ; c'est le coût accepté d'une fusion sur une base à jour.
- (−) Cette ADR décide de la structure et de la migration, pas de la modification immédiate des règles de protection du dépôt.

**Alternatives envisagées**

- **Un workflow indépendant par contrôle** : écarté, car cela disperse les déclencheurs, les permissions et les règles de concurrence et rend plus difficile l'existence d'une porte globale cohérente.
- **Conserver le workflow monolithique** : écarté, car les responsabilités et leurs environnements restent couplés dans un fichier unique.
- **Rendre directement les workflows spécialisés obligatoires dans la protection de branche** : écarté, car leurs noms et leur découpage deviendraient une API de protection instable.
- **Remplacer les deux options de protection par une seule** : écarté, car l'exigence de checks verts et l'exigence d'une branche à jour répondent à deux garanties distinctes.
