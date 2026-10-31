# ADR-0036 — L'Admin UI : React, Vite et TypeScript, servie par la Gateway sous `/ui/`, de même origine que l'API, sous une CSP stricte


**Contexte**
Le MVP prévoit une Admin UI (comptes, politiques, consultation d'audit — `docs/roadmap.md` §2), sous `web/admin-ui/` en React, TypeScript et Vite (`docs/development/repository-structure.md` §5). Rien n'existe. Bony Kiss a choisi cette pile, et avec elle les dépendances npm qu'elle demande. La connexion fédérée (ADR-0035) attend aussi une page de retour qui renvoie `code` et `state` à `POST /auth/oidc/callback`.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — la pile est son choix ; le reste est renversable)*
1. **`web/admin-ui/`** : React et React DOM à l'exécution, **rien d'autre** (ni routeur, ni bibliothèque d'interface, ni gestion d'état) ; à la construction : Vite, son greffon React, TypeScript, et pour les tests Vitest, jsdom et Testing Library. Versions **exactes** dans `package.json`, `package-lock.json` commité, `npm ci` seulement.
2. **L'interface ne parle qu'à l'API publique de la Gateway** (`docs/api/rest/openapi.yaml`), avec le jeton porteur. Elle ne demande aucune route nouvelle aux services : elle fait ce que l'API permet (connexion locale et OIDC ; comptes du Vault : liste, enregistrement, détail, rotation, désactivation ; création de politiques ; sessions : demande, demandes en attente, approbation, refus, détail, terminaison ; relecture d'un enregistrement), et dit ce qu'elle ne peut pas faire (lister les politiques : l'API ne le permet pas).
3. **Servie par la Gateway, sous `/ui/`, de même origine que l'API** : pas de CORS à ouvrir, pas de second serveur. `ADMIN_UI_DIR` (absolu, contenant `index.html`) l'active ; absent, rien n'est servi sous `/ui/` ; un répertoire qui ne convient pas est fatal.
4. **Chaque réponse de `/ui/` porte** : `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` (aucun script en ligne, aucune origine tierce), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (le `code` d'OIDC ne fuit pas par l'en-tête Referer), `X-Frame-Options: DENY`, et `Cache-Control: no-store` sur `index.html`. Un chemin sans extension sert `index.html` (la page de retour OIDC, `/ui/oidc/callback`) ; un chemin qui sort du répertoire est refusé.
5. **Le jeton vit en mémoire seulement** : ni `localStorage`, ni `sessionStorage`, ni cookie. Recharger la page déconnecte : c'est le prix d'un jeton qu'un script injecté ne trouve nulle part à relire.
6. **La page de retour OIDC** lit `code` et `state`, les **efface de l'URL** (`history.replaceState`) avant tout, puis les envoie à `/auth/oidc/callback`.
7. **L'image Compose** construit l'interface (étape Node) et la Gateway la sert (`ADMIN_UI_DIR`) ; le test Compose vérifie qu'elle est servie avec ses en-têtes.

**Conséquences**
- (+) **Mesuré** : avant, rien sous `/ui/` ni dans `web/`. Après : 17 tests de composants (Vitest, Testing Library, jsdom) — jeton jamais dans un stockage ni un cookie, en-tête porteur seulement une fois connecté, `code` et `state` effacés de l'URL **avant** l'envoi et envoyés une fois, rien d'envoyé si le fournisseur a refusé, une commande `<img src=x onerror=…>` affichée comme texte (aucun élément `img`), le secret effacé du formulaire après l'enregistrement et envoyé en octets, la déconnexion oublie le jeton ; 4 tests Go du service de `/ui/` (en-têtes sur chaque réponse, la page pour les routes, `no-store`, rien hors du répertoire, lecture seule, rien sans `ADMIN_UI_DIR`) ; le test Compose sert l'interface construite dans l'image avec ses en-têtes. **12 contre-épreuves, 12 tuées** (7 sur l'interface, 5 sur le service). La page construite ne contient **aucun script en ligne**. Dépendances : **3 paquets à l'exécution** (`react`, `react-dom`, `scheduler`), 94 en tout ; `npm audit` : **0** vulnérabilité connue.
- (+) Les trois usages du MVP — comptes, politiques, consultation — ont une interface, et la connexion fédérée a sa page de retour.
- (−) Des dizaines de paquets npm à la construction (le compte exact et `npm audit` sont dans NOTES_SANDBOX.md) ; deux seulement à l'exécution.
- (−) Pas de test dans un vrai navigateur (Playwright demanderait des navigateurs téléchargés) : les composants sont testés sous jsdom, les en-têtes et le service des fichiers en Go.
- (−) Recharger la page déconnecte (rule 5).
- (−) Pas de liste des politiques ni des événements d'audit : l'API publique n'en a pas.

**Alternatives envisagées**
- **Go et `html/template` sans npm** : écarté par le propriétaire.
- **Un serveur d'interface à part** (nginx ou Go) : une origine de plus, donc CORS à ouvrir sur l'API, et un service de plus à durcir.
- **Le jeton dans `localStorage`** : lisible par tout script de la page, pour toujours.
