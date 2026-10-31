# ADR-0051 — Toute image tirée d'un registre est épinglée par son empreinte, et un test refuse celle qui ne l'est pas

**Contexte**
ADR-0033 l'avait noté : « les images ne sont pas épinglées par empreinte (`@sha256:`) : reproductible vaut ici pour le code (`go.sum`), pas pour les images ». Le 31 octobre 2026, huit références tirées d'un registre n'étaient épinglées que par une étiquette, qu'un éditeur peut déplacer : `golang:1.23` (deux fois, Base44), `golang:1.23-alpine`, `node:24-alpine` et `gcr.io/distroless/static-debian12:nonroot` (image de déploiement), `postgres:16` (deux fichiers compose), `node:22` (Base44). Une image compromise ou simplement changée en amont entrait dans la construction suivante sans qu'aucun fichier du dépôt ne change. La CI (ADR-0047) et le test contre OpenBao (ADR-0049) épinglaient déjà les leurs.

**Décision** *(Go de Bony Kiss le 31 octobre 2026 pour le point 9 du backlog ; la forme est renversable)*

1. **Chaque image tirée porte son étiquette et son empreinte d'index** (`name:tag@sha256:…`) : l'étiquette pour qui lit, l'empreinte pour ce qui est tiré. L'empreinte d'index (multi-architecture) est celle que le registre donne (`docker buildx imagetools inspect <image>`), relevée le jour de l'épinglage.
2. **Un test l'impose** (`test/integration/images_test.go`) : il lit les `Dockerfile*` et `docker-compose*.yml` de `deploy/` et les workflows de `.github/`, et échoue sur toute image tirée sans empreinte. Seules les images que Compose construit depuis ce dépôt (`openbastion*`, jamais tirées) et les étapes d'un même Dockerfile (`FROM build AS tools`) en sont exemptes.
3. **Les versions ne changent pas** : cet ADR épingle ce qui était utilisé ; changer de version est une autre décision.

**Conséquences**
- (+) **Mesuré, avant** : le test échoue sur les huit références (rouge). **Après** : il passe ; l'empreinte de `postgres:16` relevée est celle que la CI épinglait déjà.
- (+) **Les images se construisent encore** avec leurs bases épinglées : l'image de déploiement (106 Mo, distroless), l'image d'outils et l'image Base44 ; un binaire de l'image distroless démarre et refuse, comme attendu, de tourner sans ses certificats.
- (+) **3 mutations, 3 tuées** : une empreinte retirée, une empreinte tronquée, une image ajoutée sans empreinte au workflow.
- (−) **`make test-compose` n'a pas tourné** pour cet incrément : il pose une règle de pare-feu temporaire que le mode de permission de la session a refusée. Les images ont été construites, la pile n'a pas été démarrée.
- (−) **Une empreinte ne se met pas à jour seule** : un correctif de sécurité publié sous la même étiquette n'entre qu'au prochain épinglage. La mise à jour se fait à la main, image par image (relever l'empreinte, la remplacer, construire, tester).
- (−) ~~**Les images de construction sont sur Go 1.23**, qui ne reçoit plus de correctifs de sécurité, quand la CI et le développement sont sur Go 1.27 : l'épinglage fige cette version.~~ **Levé le même jour** : `golang:1.27.1` et `golang:1.27.1-alpine`, épinglées, la version de la CI.
- (−) Les images tirées par les tests eux-mêmes (`openBaoImage` dans le code Go) ne sont pas lues par ce test ; l'une l'est par construction, et il faudra la garder épinglée à la main.

**Alternatives envisagées**
- **Un outil de mise à jour automatique** (Renovate, Dependabot) : un service tiers de plus, avec accès au dépôt ; à décider à part.
- **Épingler l'empreinte d'une seule architecture** : plus stricte encore, mais la construction échouerait sur une autre architecture.
- **Garder les étiquettes** : la limite d'ADR-0033, que cet ADR ferme.
