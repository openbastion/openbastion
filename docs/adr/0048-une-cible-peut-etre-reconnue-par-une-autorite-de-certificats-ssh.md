# ADR-0048 — Une cible peut être reconnue par une autorité de certificats SSH épinglée au compte, à la place de sa clé

**Contexte**
Depuis ADR-0039, chaque compte porte la clé d'hôte exacte de sa cible, et le secret n'est envoyé — par le proxy comme par la rotation — qu'au serveur qui la présente. ADR-0039 en a noté le prix : « une seule clé par compte : pas d'autorité de certificats SSH » ; une cible qui change de clé (réinstallation, renouvellement planifié) refuse toute session jusqu'à ce qu'un administrateur la ré-épingle. Une organisation qui signe déjà les clés d'hôte de ses serveurs avec une autorité (`ssh-keygen -s ca -h -n hôte`) ne peut pas s'en servir.

L'invariant en jeu, « le secret n'est envoyé qu'à la clé d'hôte épinglée », s'élargit : il devient « qu'au serveur que le compte reconnaît, par sa clé ou par l'autorité qui la certifie pour son nom ». Le risque change de forme : avec une autorité, qui détient sa clé privée se fait passer pour **toutes** les cibles qui lui font confiance ; avec une clé, il faut voler celle de chaque cible.

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « par compte, au choix », parmi trois propositions dont « ne pas le faire » ; la forme est renversable)*

1. **Chaque compte choisit l'un ou l'autre, jamais les deux.** Le champ `hostKey` reçoit soit une clé (comme avant, `ssh-ed25519 AAAA…`), soit une ligne d'autorité au format `known_hosts` : `@cert-authority <nom> <clé de l'autorité>`. Le contrat ne change pas de forme ; il accepte une valeur de plus. L'épinglage d'une clé reste la valeur que l'on attend par défaut.
2. **Le nom est un seul nom d'hôte ou une seule adresse**, sans motif (`*`, `?`, `!`), sans liste, sans port, 253 octets au plus ; il est mis en minuscules. C'est le nom que le certificat de la cible doit porter, **pas** l'adresse de connexion : une cible jointe par son adresse IP peut être certifiée sous son nom DNS.
3. **Un certificat n'est accepté que s'il est** un certificat **d'hôte** (pas d'utilisateur), signé par **cette** autorité, avec une liste de noms **non vide** qui contient **ce** nom, dans sa période de validité, **avec une date de fin** (un certificat sans fin est refusé : rien ne le retirerait), et sans option critique inconnue. Une clé nue présentée à un compte d'autorité est refusée ; un certificat présenté à un compte épinglé est refusé (la clé épinglée est la seule acceptée, comme avant). Quand le compte a une autorité, la connexion propose les algorithmes de certificats d'abord, puis ceux des clés nues : une cible sans certificat atteint la vérification et y est refusée — dite et auditée comme une clé qui ne correspond pas — plutôt que perdue dans un échec de négociation (vu au premier essai).
4. **Une seule vérification pour le proxy et pour la rotation** : la lecture de la ligne et la vérification passent dans `pkg/hostkey`, utilisé par le Vault (enregistrement, épinglage, rotation) et par le proxy SSH (session).
5. **Passer un compte à une autorité est un épinglage** comme un autre : `PUT /vault/accounts/{id}/host-key`, réservé aux administrateurs du compte, audité **avant** (`vault.host_key_set`), l'ancienne et la nouvelle empreinte dans le journal. L'empreinte rendue d'un compte d'autorité est celle **de l'autorité**.
6. **Un refus est un refus d'ADR-0039** : rien n'est envoyé, `session.host_key_mismatch` à l'audit, le journal du proxy dit pourquoi (autorité étrangère, nom absent, certificat expiré ou sans fin, clé nue).

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `30c4214`, `test/integration/hostcert_flow_test.go` dans un worktree) : la ligne d'autorité est refusée à l'enregistrement (`400`) ; aucun compte ne peut reconnaître sa cible par une autorité.
- (+) **Mesuré, après**, sur processus réels (Gateway, Broker, Vault, Authorization, Authentication, Audit, Command Recorder, proxy SSH) et le vrai client OpenSSH :
  - une ligne d'autorité avec un motif, une liste ou un port est refusée (`400`) ; le compte montre l'empreinte **de l'autorité** ;
  - la cible certifiée pour le nom du compte reçoit le mot de passe et la session tourne ;
  - six imposteurs, chacun à l'adresse d'un compte reconnu par l'autorité — une clé nue, un certificat d'une autre autorité, pour un autre nom, pour l'adresse de connexion au lieu du nom, expiré, sans date de fin — ne reçoivent **aucun** mot de passe, l'opérateur n'atteint pas de shell, et `session.host_key_mismatch` est à l'audit.
- (+) **Mesuré en unitaire** : `pkg/hostkey` (6 tests : lecture et refus des lignes, clé épinglée exacte, certificat valable, douze imposteurs dont une signature falsifiée et une option critique, une vraie poignée de main SSH, et un certificat fabriqué par le vrai `ssh-keygen` avec la commande du guide d'administration) ; la rotation du Vault contre une cible certifiée, et trois imposteurs qui ne reçoivent aucun mot de passe.
- (+) **16 mutations, 16 tuées par un test** (aucune par un simple échec de compilation).
- (+) **Trouvé en chemin** : ne proposer que les algorithmes de certificats faisait échouer la négociation avec une cible sans certificat, **avant** la vérification — rien n'était envoyé, mais le refus n'était ni dit à l'opérateur ni écrit à l'audit. Les clés nues sont désormais proposées après les certificats, pour être refusées par la vérification (point 3).
- (−) **La clé privée de l'autorité vaut toutes les cibles** qui lui font confiance. Sa garde est l'affaire de l'exploitant ; OpenBastion ne la voit jamais.
- (−) **Pas de liste de révocation** (KRL) : un certificat volé vaut jusqu'à sa date de fin. Des certificats de courte durée sont la seule défense ; OpenBastion n'en impose pas la durée.
- (−) Un compte n'a qu'une autorité, et une autorité qui change se ré-épingle compte par compte.
- (−) Le nom attendu est déclaré par l'administrateur : un nom faux refuse toutes les sessions (sûr), un nom partagé par plusieurs serveurs les rend interchangeables pour ce compte.

**Alternatives envisagées**
- **Des autorités de plateforme** (une liste au Vault, chaque compte en accepte une) : plus simple à exploiter, mais une autorité ajoutée vaudrait pour tous les comptes qui l'acceptent, et la liste deviendrait un réglage sensible de plus. Écartée par Bony Kiss.
- **Clé et certificat exigés ensemble** : aucune souplesse gagnée — une clé qui change casse encore le compte.
- **Vérifier le nom contre l'adresse de connexion** (le comportement par défaut de `ssh.CertChecker`) : une cible jointe par IP ne pourrait pas être certifiée sous son nom, et le nom viendrait du Broker, pas du Vault.
- **Ne pas le faire** : garder l'invariant tel quel. Écartée par Bony Kiss.
