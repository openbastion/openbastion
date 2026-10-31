# ADR-0037 — La rotation d'un secret atteint la cible : un compte de réconciliation, une version en attente, une vérification avant de la rendre courante


**Contexte**
Le MVP promet une rotation « manuelle et post-usage » (`docs/roadmap.md` §2). Constaté le 30 octobre 2026 : `VaultService.Rotate` enregistrait un nouveau secret **sans le poser sur la cible** — aucun composant ne change un mot de passe sur une cible. Après une rotation, le Vault injectait un mot de passe que la cible refusait : le compte devenait inutilisable. `post_use` et `scheduled` étaient enregistrés et rien ne les exécutait. Et la rotation remplaçait l'ancienne version **avant** d'écrire la nouvelle, hors transaction : une panne entre les deux laissait un compte sans secret courant. Bony Kiss a choisi le modèle du **compte de réconciliation**.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — le modèle du compte de réconciliation est son choix ; le reste est renversable)*
1. **Un compte peut nommer son compte de réconciliation** (`reconciliationAccountId`) : un autre compte du Vault, actif, **sur la même cible**, jamais lui-même, qui peut changer les mots de passe — `root`, ou un compte autorisé à `sudo chpasswd`. Son secret est au Vault comme les autres, jamais ailleurs.
2. **Sans compte de réconciliation, pas de rotation** : `409` qui le dit. Il n'existe plus de rotation qui ne change que le Vault.
3. **Une version en attente** (`pending`) : le nouveau secret est d'abord écrit chiffré, **à côté** de la version courante, qui reste celle qu'on injecte. Une seule version en attente par compte (une seconde rotation simultanée : `409`).
4. **Poser, puis vérifier, puis rendre courant** : le Vault se connecte en SSH à la cible avec le compte de réconciliation, pose le mot de passe (`chpasswd`, par `sudo -S` si le compte n'est pas `root`), **se connecte avec le nouveau secret** ; seulement alors, **en une transaction**, la version en attente devient courante et l'ancienne est remplacée. La cible refuse : la version en attente est jetée, l'ancienne reste courante. Posée mais non vérifiée : la version en attente est gardée, et la rotation suivante commence par **réconcilier** — le nouveau secret ouvre la cible ? il devient courant ; l'ancien l'ouvre encore ? l'attente est jetée ; aucun des deux ? `502` et rien n'est décidé à la place d'un humain.
5. **Auditée, fail-closed** : `vault.rotate_requested` est écrit **avant** de toucher la cible (audit en panne : pas de rotation), `vault.rotate` (succès ou échec) après, au nom de qui l'a demandée (l'identité vérifiée par la Gateway) ou sans acteur pour une rotation après usage.
6. **Après usage** : quand une session accordée se termine (terminaison, ou expiration par le balayage d'ADR-0034), le Broker le dit au Vault (`POST /vault/v1/rotate-after-use`, réservé au Broker) ; le Vault tourne le secret si le compte est `post_use`, ne fait rien sinon. Un échec est audité et journalisé ; il n'est pas réessayé.
7. **`scheduled` reste enregistré et n'est exécuté par rien** (pas de Scheduler de rotation) : c'est dit.
8. L'Admin UI retrouve le bouton de rotation, et l'enregistrement d'un compte son champ de réconciliation.

**Conséquences**
- (+) **Mesuré** : avant (rouge, sur `HEAD`, huit processus et une vraie cible SSH), après une rotation **l'ancien mot de passe ouvrait encore la cible** et la session suivante **échouait** (le proxy injectait un secret que la cible refusait) ; une rotation sans compte de réconciliation et une rotation l'audit coupé répondaient `202`. Après : le mot de passe de la cible change, l'ancien ne l'ouvre plus, la session suivante s'ouvre avec le nouveau ; une session terminée fait tourner un compte `post_use`, et l'ancien secret n'ouvre plus la cible ; sans compte de réconciliation `409` et rien ne change ; l'audit coupé `503` et la cible n'est pas touchée ; les événements de rotation nomment l'administrateur vérifié, ceux d'après usage personne. `chpasswd` direct (`root`) et par `sudo -S` sont tous deux exercés sur un vrai serveur SSH, et aucun secret ne passe sur une ligne de commande. **17 mutations, 17 tuées.** Quatre tests existants ont changé par construction : la rotation sans cible n'existe plus (tests unitaires du Vault, test des routes d'administration, test de redémarrage du Vault), et « le Vault écrit dans l'audit » n'est plus une attaque (deux tables d'appelants).
- (+) Une rotation change vraiment le mot de passe de la cible, ou ne change rien.
- (+) Aucun moment où un compte n'a pas de secret courant.
- (−) ~~**La clé d'hôte de la cible n'est pas vérifiée** (comme par le proxy, MVP) : quelqu'un qui se place entre le Vault et la cible voit passer le nouveau secret et celui du compte de réconciliation.~~ Refermé par ADR-0039 : le Vault ne se connecte qu'à la clé épinglée.
- (−) Entre la pose et la promotion (quelques secondes), une nouvelle connexion reçoit encore l'ancien secret et échoue.
- (−) ~~Une rotation après usage échouée n'est pas réessayée.~~ Refermé par ADR-0044 : la rotation due est une dette enregistrée des deux côtés, payée jusqu'au bout.
- (−) ~~`scheduled` n'est exécuté par rien (décision 7).~~ Refermé par ADR-0040 : le Vault balaie et fait tourner les comptes planifiés échus.
- (−) Le Vault ouvre maintenant des connexions SSH vers les cibles : un chemin réseau de plus à autoriser (`docs/deployment/high-availability.md`, pare-feu).
- (−) Le module du Vault dépend désormais de `golang.org/x/crypto` (même version et même miroir que le proxy), et le Vault d'un Audit Service (`AUDIT_URL`).

**Alternatives envisagées**
- **Le compte change son propre mot de passe** (`passwd` interactif) : écarté par le propriétaire (dépend des messages de chaque système).
- **Refuser toute rotation** : écarté par le propriétaire.
- **Faire poser le mot de passe par le proxy** : le proxy est déjà l'unique composant qui joint les cibles, mais il deviendrait détenteur des secrets de réconciliation hors d'une session ; garder la rotation dans le Vault laisse ces secrets là où ils vivent.
