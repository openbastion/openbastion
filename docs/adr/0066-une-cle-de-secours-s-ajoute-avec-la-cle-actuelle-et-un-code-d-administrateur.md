# ADR-0066 — Une clé de secours s'ajoute avec la signature de la clé actuelle et un code d'administrateur ; un administrateur révoque une seule clé

**Statut** `Accepté` · 1ᵉʳ novembre 2026 · referme l'écart d'ADR-0065 ; choisi par Bony Kiss le 1ᵉʳ novembre 2026 avec deux décisions qui sont les siennes : l'ajout exige **la clé actuelle et un code d'administrateur**, et **l'administrateur** révoque une clé ; texte accepté par son go du 1ᵉʳ novembre 2026

**Contexte** — ADR-0065 a livré une seule clé par compte : un compte qui détient un facteur admis reçoit un défi de vérification, jamais d'enrôlement — c'est ce qui empêche qu'un mot de passe et un code d'enrôlement suffisent à remplacer le second facteur (ADR-0062). Mais une seule clé, c'est une perte qui coupe l'accès : pour un rôle strict, la seule issue est `mfa reset`, qui efface tout. Et une clé perdue parmi deux ne se retire pas sans effacer l'autre.

**Décision**

1. **Ajouter une clé**, pendant une connexion dont le défi admet `webauthn` : `POST /auth/mfa/webauthn/keys/add` `{challenge, credential, enrollmentCode}` — `credential` est la **signature de la clé actuelle** sur le défi (vérifiée comme à la connexion : origine, `rpId`, présence, signature, compteur), `enrollmentCode` un code émis par l'administrateur pour ce compte (`openbastion-cli mfa enrollment-code`, inchangé). Les deux vérifiés, **le même défi devient une cérémonie d'enregistrement** (compare-échange en base : une fois, et il ne peut plus servir à se connecter) et la réponse porte les options de création, la clé actuelle exclue. Puis `POST /auth/mfa/webauthn/enroll/confirm` (inchangé) enregistre la nouvelle clé, brûle le code, écrit `auth.mfa_webauthn_registered` à l'audit et termine la connexion. **5 clés** au plus par compte.
2. **Ni l'un ni l'autre ne suffit seul** : une signature sans code ne fait que se connecter ; un code sans signature ne s'utilise que pour un compte sans facteur admis (ADR-0062). Un code faux, d'un autre compte ou expiré compte comme un échec du défi (5 essais).
3. **Lister les clés** : `openbastion-cli mfa keys -authn URL -username NOM` (route `POST /auth/v1/mfa/keys`, `admin-cli` seul) — pour chaque clé, son identifiant (base64url), sa date d'enrôlement, son dernier usage. Le dernier usage est gardé à chaque connexion par la clé (migration `005_webauthn_last_used.sql`).
4. **Révoquer une clé** : `openbastion-cli mfa revoke-key -authn URL -username NOM -key ID` (route `POST /auth/v1/mfa/revoke-key`, `admin-cli` seul) ; écrit `auth.mfa_webauthn_revoked` à l'audit **avant** de le faire (sans audit, rien), l'acteur étant l'identité du certificat de l'appelant ; les autres clés restent. Révoquer la dernière clé d'un rôle strict lui redemande un enrôlement à sa prochaine connexion.
5. **L'Admin UI** propose « Ajouter une clé de secours » à l'étape de la clé : le code de l'administrateur, la signature de la clé actuelle, puis la nouvelle clé.

**Conséquences**

- (+) **Mesuré, avant** (sur `ce4c567`, processus réels) : aucune route d'ajout, de liste ni de révocation (`404`) ; rien dans l'audit.
- (+) **Mesuré, après**, avec l'authentificateur logiciel d'ADR-0065 : la clé actuelle sans code → `401` ; un code sans la clé actuelle (une clé de personne) → `401` ; la clé actuelle signant pour une autre origine (l'hameçonnage) → `401` ; les deux preuves → les options de création ; le défi converti ne connecte plus ; la clé de secours enregistrée ; **chacune des deux clés connecte** ensuite ; `mfa keys` en liste deux, la première avec son dernier usage ; la première révoquée ne connecte plus, la clé de secours, si ; `auth.mfa_webauthn_revoked` à l'audit sous `<compte>/<clé>`, avec un acteur. En unitaire (4 tests) : les deux preuves ; chacune seule refusée, un code d'un autre compte, une clé clonée ; le défi converti ne connecte plus et ne se convertit pas deux fois ; une sixième clé refusée ; la liste, le dernier usage posé par une connexion ; la révocation refusée sans audit (la clé reste), une clé révoquée deux fois, les autres clés intactes. Les deux magasins (mémoire et PostgreSQL) : conversion une fois, révocation d'une clé, dernier usage gardé. Admin UI : 1 test.
- (+) **10 mutations, 10 tuées.** Deux survivaient d'abord : une mutation qui ne compilait pas, et le dernier usage — mon test le lisait sur la clé que l'ajout fait signer ; il le lit désormais sur la clé de secours, après une connexion par elle.
- (+) La borne de 5 clés est maintenant atteinte par un chemin réel : elle est vérifiée avant de convertir le défi, et de nouveau par le magasin à l'enregistrement.
- (−) Le dernier usage d'une clé est une écriture de plus à chaque connexion par clé.
- (−) La liste et la révocation passent par la CLI : rien dans l'Admin UI pour l'administrateur.
- (−) L'utilisateur ne révoque pas lui-même une clé (choix de Bony Kiss) : il demande à l'administrateur.

**Alternatives envisagées**

- **La clé actuelle seule** (libre-service) : écartée par Bony Kiss ; qui vole la clé et le mot de passe pourrait y ajouter la sienne et la garder.
- **Une route authentifiée par le jeton** (ajouter une clé avec un jeton valide) : un jeton volé pendant son heure suffirait avec un code ; une signature fraîche de la clé, sur le défi même, est la preuve qu'on a la clé maintenant.
- **Pas de révocation à l'unité** (seulement `mfa reset`) : une clé perdue parmi deux effacerait aussi la bonne.
