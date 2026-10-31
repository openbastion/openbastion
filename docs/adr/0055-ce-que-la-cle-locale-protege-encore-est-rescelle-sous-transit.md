# ADR-0055 — Ce que la clé locale protège encore est rescellé sous la clé courante, en tâche de fond, jusqu'à ce que la clé locale puisse partir

**Contexte**
Depuis ADR-0049, un Vault et un Command Recorder qui reçoivent Transit gardent `KMS_KEY_HEX` comme clé **précédente**, en lecture seule : les nouvelles lignes vont à Transit, les anciennes restent sous la clé locale. ADR-0049 a noté : « pas de ré-enveloppement en masse ». Tant qu'une seule ligne nomme la clé locale, elle ne peut pas être retirée — et c'est justement elle que Transit devait remplacer : qui la lit avec la base lit encore tout ce qu'elle protège.

**Décision** *(reliquat d'ADR-0049, retenu par Bony Kiss le 31 octobre 2026 parmi les reliquats proposés ; la forme est renversable)*

1. **Un balayage de fond**, dans le Vault et dans le Recorder, quand ils tiennent une clé précédente : une **passe** toutes les `KEY_REWRAP_SWEEP_SECONDS` (60 par défaut, de 1 à 3600 ; la première après une période), par pages de 50, sur ce qui nomme une clé précédente.
   - Le Vault rouvre chaque version — courante, en attente **ou** ancienne — avec la clé qu'elle nomme et la rescelle sous la clé courante (une enveloppe Transit neuve) : le secret ne change pas.
   - Le Recorder désenveloppe la clé de données de chaque session et la renveloppe sous la clé courante, liée au nouvel identifiant de clé : l'enregistrement n'est pas touché.
2. **Un compare-échange** sur l'ancienne clé : une ligne changée entre la lecture et l'écriture — une rotation, un autre réplica — est laissée à celui qui l'a écrite.
3. **Le Vault écrit chaque rescellement à l'audit avant de le faire** (`vault.secret_rewrapped`, action du système, sur le compte) : sans l'audit, rien n'est rescellé. Le Recorder le dit dans son journal.
4. **Une ligne qui ne s'ouvre pas** avec la clé précédente tenue (une autre époque de `KMS_KEY_HEX`, une ligne altérée) est **sautée et comptée**, jamais une raison d'arrêter les autres : la passe continue après elle (curseur par identifiant). À la fin de la passe, le service dit combien restent, et que `KMS_KEY_HEX` ne peut pas encore partir.
5. **Le service dit une fois** qu'une passe n'a plus rien trouvé : « nothing is sealed under … any more: KMS_KEY_HEX can be removed ».

**Conséquences**
- (+) **Mesuré, avant** (sur `3e11ddf`, vrai OpenBao, processus réels, vraie PostgreSQL) : un Vault avec Transit et `KMS_KEY_HEX` laisse le secret d'avant sous `local-dev-key-v1` — 30 s plus tard, toujours.
- (+) **Mesuré, après** : le même Vault, `KEY_REWRAP_SWEEP_SECONDS=1`, rescelle ce secret sous Transit en 1,2 s (enveloppe `OBT1`, sans le secret en clair), l'audit reçoit `vault.secret_rewrapped`, et un Vault avec **Transit seul** le relit ensuite. En unitaire : trois secrets rescellés sans changer de valeur, audit écrit pour chacun ; sans audit, rien ; page par page ; une version altérée sautée et les suivantes rescellées ; compare-échange (Vault, et pour le Recorder une course jouée entre la lecture et l'écriture) ; sur PostgreSQL, les clés de session renveloppées puis lues avec la seule clé courante.
- (+) **8 mutations, 8 tuées.** Une survivait d'abord : rien ne faisait changer une clé de session pendant le renveloppement du Recorder ; un crochet de test joue désormais cette course.
- (+) **Trouvé en écrivant le test** : sans audit joignable, le balayage du Vault ne fait rien, et c'est voulu ; mon premier test l'avait oublié.
- (−) Les clés de session du Recorder ne sont pas écrites à l'audit, seulement au journal.
- (−) Une passe relit toute la table à chaque période tant qu'il reste des lignes sautées ; c'est le prix de ne jamais bloquer.
- (−) Retirer `KMS_KEY_HEX` reste un geste de l'exploitant : le service dit quand c'est possible, il ne le fait pas.

**Alternatives envisagées**
- **Une commande d'exploitation** (CLI sous `admin-cli`) : une route de plus, avec ses appelants, pour un travail qu'un balayage fait seul et sans qu'on y pense.
- **Rescellé à la lecture** (au prochain `fetch-credential`) : ce qu'on ne lit jamais — les versions anciennes, les sessions finies — resterait sous la clé locale.
- **S'arrêter à la première ligne qui ne s'ouvre pas** : la première version du code ; une seule ligne d'une autre époque bloquait tout ce qui la suivait.
