# ADR-0097 — Un secret est saisi dans la session par le proxy, pour tous les protocoles, sans passer par le presse-papiers ni par l'enregistrement

**Statut** `Accepté` · 13 novembre 2026 · accepté le même jour par le propriétaire du projet : « Go pour A et B, continue ». A (un secret du Vault saisi par le proxy) et B (un mot de passe fourni par l'opérateur, saisi sans enregistrer son contenu) sont acceptés, avec un seul mécanisme pour tous les protocoles, la confirmation par le second facteur à chaque saisie et les bornes de B (128 caractères, une ligne). Étude étude demandée par le propriétaire du projet le 13 novembre 2026, à l'acceptation d'ADR-0096 : « Pour éviter que les mots de passe se retrouvent enregistrés en clair, est-ce que nous ne pourrions pas intégrer un mécanisme de saisie automatique comme op-forward, avec la possibilité de continuer à copier/coller les mots de passe ». `Accepté` seulement avec son go, cité avec sa date. Précisé le même jour : « Ce mécanisme de saisie automatique doit être valable pour tous les protocoles déjà supportés (ssh, vnc, rdp) et supporteraient à l'avenir ».

## Contexte

Avec ADR-0096, un texte collé dans une session RDP est enregistré avec la session. Un mot de passe collé l'est donc aussi.

**Ce que « en clair » veut dire ici.** L'enregistrement est chiffré au repos : une clé AES-256 par session, enveloppée par Transit (ADR-0070). Mais un auditeur autorisé qui rejoue la session lit le texte collé. Le mot de passe est donc lisible par toute personne qui a le droit de relire la session, longtemps après. C'est ce qu'il faut éviter.

**Ce qui existe déjà :**
- Le proxy ouvre la session avec le mot de passe de la cible, tiré du Vault : l'opérateur ne l'a jamais (invariant « secrets jamais dans le control plane », ADR-0039, ADR-0048).
- En SSH, l'enregistreur remplace une ligne tapée après une invite de mot de passe (`sudo`, `su`, `mysql`…) par `[redacted: input at a secret prompt]` (`pkg/proxycore/recording_tap.go`). C'est une heuristique sur l'invite, documentée comme telle.
- En RDP, les frappes ne sont pas enregistrées : seul l'écran l'est (ADR-0069 §6). Un mot de passe tapé dans un champ masqué n'y apparaît pas.

**Ce que fait op-forward** (github.com/eldorplus/op-forward) : la commande `op` de 1Password, lancée dans une VM, est relayée par un tunnel SSH jusqu'à l'hôte, qui l'exécute. Chaque opération sensible y demande une approbation biométrique (Touch ID). Le secret reste sur l'hôte jusqu'à ce qu'une personne approuve son usage, une fois. Les arguments sensibles sont masqués dans son journal.

**L'idée à transposer** : le secret part du coffre et va là où il sert, sans passer par une main ni par une trace lisible. Une approbation forte accompagne chaque usage, et seule la référence du secret est journalisée, jamais sa valeur.

## Options

**A. Saisir un secret du Vault (recommandée).** L'opérateur choisit, dans l'Admin UI, un secret qu'il a le droit d'utiliser. Il confirme par son second facteur (WebAuthn ou TOTP, ADR-0062, ADR-0065), l'équivalent du Touch ID d'op-forward. Le proxy demande alors le secret au Vault, par un scope à usage unique, et le saisit lui-même dans la session.
- **Ni le navigateur ni le presse-papiers** ne voient le secret.
- **L'enregistrement et l'audit gardent la référence** : « secret `<compte>` saisi à 14 h 32 ». Un auditeur sait donc exactement quoi a été saisi, sans lire la valeur. Lire la valeur passe par le Vault, qui a son propre audit.
- **« Enregistrer ou refuser » tient**, par référence : rien d'inconnu n'entre dans la session.

**B. Saisir un mot de passe fourni par l'opérateur, sans l'enregistrer.** Un bouton « Saisir un mot de passe ». Le texte est livré à la cible. L'enregistrement et l'audit gardent sa taille et son empreinte SHA-256, pas son contenu.
- C'est le copier-coller que le propriétaire veut garder.
- Le prix : pour ce texte-là, l'auditeur ne sait plus ce qui est entré. Il peut seulement reconnaître une valeur s'il l'a déjà, en comparant l'empreinte.
- **Bornes**, pour qu'il reste un mot de passe et ne devienne pas un script soustrait à l'enregistrement : 128 caractères au plus, sur une seule ligne, sans tabulation. Un droit propre, refusé par défaut. Un événement d'audit à chaque usage.

**C. Une commande dans la cible, à la manière du shim d'op-forward.** Un outil installé sur la cible demanderait le secret au proxy par un canal de la session. Écartée :
- le secret atterrirait dans un processus et souvent dans la sortie de la cible, donc dans l'enregistrement SSH ;
- il faudrait installer et maintenir un logiciel sur chaque cible ;
- le modèle d'op-forward protège un développeur sur sa propre machine, pas un opérateur sur une cible privilégiée.

**D. Masquer après coup un mot de passe dans l'enregistrement**, en reconnaissant son allure. Écartée : une heuristique sur le contenu manque des secrets et en invente. L'heuristique SSH actuelle porte sur l'invite, pas sur le contenu, et elle reste.

## Décision : A, et B en complément borné, un seul mécanisme pour tous les protocoles

1. **Un mécanisme, pas un par protocole.** La saisie d'un secret est un service commun du proxy (`pkg/proxycore`) :
   - les droits, la confirmation par le second facteur, le scope à usage unique, l'audit et la référence dans l'enregistrement sont les mêmes pour tous les protocoles ;
   - chaque protocole ne fournit qu'une chose : **taper un texte dans sa session** (une interface `SecretTyper`). Le texte ne passe ni par le presse-papiers ni par l'enregistrement ; un secret du Vault (A) ne passe pas non plus par le navigateur, alors qu'un mot de passe fourni par l'opérateur (B) en vient, tapé dans un champ masqué ;
   - **A et B empruntent le même chemin** : seule la source du texte change, le Vault pour A, l'opérateur pour B. « Coller comme mot de passe » est donc une saisie, pas un collage par le presse-papiers.
2. **Chaque protocole, aujourd'hui** :
   - **SSH** : le texte est écrit sur l'entrée de la session. L'enregistreur de commandes note la référence (`[secret <compte> saisi]` ou `[mot de passe collé : N caractères, empreinte …]`) à la place de la ligne.
   - **VNC** : le texte est tapé par des événements clavier RFB en keysyms. Les keysyms Unicode (`0x01000000 + point de code`) couvrent tout caractère, quelle que soit la disposition de la cible ; le proxy les accepte déjà (`pkg/vnc`). Seul l'écran est enregistré.
   - **RDP** : le texte est tapé par des événements clavier Unicode (`TS_UNICODE_KEYBOARD_EVENT`, MS-RDPBCGR 2.2.8.1.1.3.1.1.2). C'est le point 1 du lot E d'ADR-0090, à construire ici, et il lève pour la saisie la limite d'ADR-0088 (un caractère absent de la disposition de la cible). Le presse-papiers de la cible n'est pas utilisé : le secret y resterait, même un instant. Seul l'écran est enregistré.
3. **Les protocoles futurs.** Un protocole ne rejoint le proxy (ADR propre) qu'en disant comment il tape un texte (`SecretTyper`), ou en déclarant explicitement qu'il ne le peut pas. Dans ce cas, le `HELLO` (écran) ou l'équivalent de son flux le dit, et l'Admin UI n'offre pas la saisie : jamais de repli silencieux sur le presse-papiers.
4. **Droits**, refusés par défaut, à l'Authorization Service, les mêmes pour tous les protocoles :
   - `secret:inject:<compte>` : saisir le secret de ce compte du Vault dans une session ;
   - `secret:paste:<compte-cible>` : saisir un mot de passe fourni par l'opérateur, sans enregistrer son contenu, dans une session sur cette cible.
5. **Saisie d'un secret du Vault (A)** :
   - l'opérateur la confirme par son second facteur, à chaque saisie, pas une fois par session ; sans second facteur enrôlé, la saisie est refusée ;
   - le Broker émet un scope à usage unique pour ce compte et cette session ; le proxy l'échange au Vault comme à l'ouverture de session, tape le texte, puis l'efface de sa mémoire ;
   - audit : `session.secret_injected` (le compte du secret, la session, le protocole, l'heure ; jamais la valeur), émis avant la saisie. Sans audit, pas de saisie.
6. **Mot de passe fourni par l'opérateur (B)** :
   - 128 caractères au plus, une seule ligne, sans tabulation : un mot de passe, pas un script ;
   - l'enregistrement et l'audit (`session.secret_pasted`) gardent sa taille et son empreinte SHA-256, pas son contenu ;
   - de l'opérateur vers la cible seulement. Ce qui sort de la cible reste toujours enregistré en entier (ADR-0096).
7. **Contrat écran et terminal** : un message client → proxy « saisir », qui porte soit une référence de compte du Vault (A), soit le texte (B, borné). Pour SSH, le même message passe par le canal de l'Admin UI qui pilote la session, pas par le flux du terminal de l'opérateur.
8. **Admin UI** : un bouton « Saisir un secret » (comptes permis, confirmation par le second facteur) et un bouton « Saisir un mot de passe » (un champ masqué, jamais lu depuis le presse-papiers sans geste), proposés seulement quand la session sait taper.
9. **Ce que cela ne protège pas, dit clairement** : si l'opérateur saisit un secret dans un champ **non masqué** (un éditeur au lieu d'une invite de mot de passe), l'écran enregistré (RDP, VNC) ou la sortie enregistrée (SSH, si la cible répète ce qu'on tape) le montre. Le proxy ne voit pas où est le focus. L'Admin UI le rappelle à chaque saisie.

## Mise en œuvre envisagée

1. **Le service commun** dans `pkg/proxycore` : `SecretTyper`, les droits, la confirmation, le scope, l'audit, la référence enregistrée. Tests avec une session factice.
2. **La confirmation par le second facteur** à l'action (Authentication Service) : un jeton à usage unique, lié à la session et à l'action, de courte durée.
3. **SSH**, puis **VNC** (keysyms Unicode), puis **RDP** (événements clavier Unicode) : chacun avec ses tests et contre une vraie cible (OpenSSH, TigerVNC, les cinq Windows de la CI).
4. **Admin UI**, et vérification dans le navigateur sans interface pour chaque protocole.

## Conséquences

- (+) Le mot de passe d'un compte du Vault n'est plus jamais lisible dans un rejeu : l'auditeur voit quel secret a servi et quand, pas sa valeur.
- (+) L'approbation forte à chaque usage, comme le Touch ID d'op-forward.
- (+) Le copier-coller d'un mot de passe reste possible, borné et audité.
- (−) B affaiblit « enregistrer ou refuser » pour le texte que l'opérateur déclare mot de passe. Les bornes empêchent d'y faire passer un script, mais pas un autre secret court. C'est le droit `secret:paste` qui l'ouvre ou le ferme.
- (−) Un secret saisi dans un champ non masqué reste visible à l'écran enregistré.
- (+) Un seul mécanisme pour SSH, VNC, RDP et les protocoles futurs : un protocole n'ajoute que sa façon de taper un texte.
- (−) RDP demande les événements clavier Unicode, encore à construire (ADR-0090, lot E).
- (−) Chaque saisie demande le second facteur : plus sûr, plus lent. Et c'est à construire : aujourd'hui, le second facteur n'est demandé qu'à la connexion (ADR-0062, ADR-0065), pas pour confirmer une action ; une confirmation par action, liée à la session et à usage unique, est un mécanisme nouveau.

## Alternatives envisagées

- **C, une commande sur la cible** : écartée (voir Options).
- **D, masquer après coup** : écartée (voir Options).
- **Ne rien faire et compter sur le chiffrement de l'enregistrement** : écartée. Le chiffrement protège le stockage, pas la relecture ; or le besoin est qu'un auditeur qui relit ne lise pas le secret.

## État d'implémentation — 14 novembre 2026, incrément 3

- Le Session Broker possède désormais un port applicatif `MFAActionClient` et un adaptateur HTTP qui implémente les trois opérations Authentication `start`, `verify` et `consume`.
- Le client est construit au démarrage avec `rt.Client(mtls.Peer{URL: AUTHENTICATION_URL, Service: mtls.Authentication})` : il utilise donc l'identité mTLS `session-broker` et épingle le pair `authentication`. `AUTHENTICATION_URL` reprend le port interne 8086 par défaut.
- Les DTO du port sont indépendants de l'infrastructure. Le client borne les réponses à 1 Mio, refuse les statuts non 200, les corps JSON incomplets et les données JSON finales supplémentaires ; il ne répercute jamais le corps d'erreur Authentication.
- Tests du client : binding acteur/session/compte/protocole/action sur les trois opérations, ordre start → verify → consume et refus sans fuite du corps d'erreur. Tests ciblés et suite du module Session Broker : PASS après correction des tags JSON.
- **Non livré** : aucune route publique ou Gateway n'expose encore le parcours ; à cet incrément, la validation applicative de session active/propriétaire/Authorization n'est pas encore exécutée ; le grant n'est pas consommé dans une opération proxy réelle ; aucune portée Vault d'injection ni commande de frappe proxy n'est appelée. Le client câblé ne signifie donc pas que l'injection est utilisable.
- Le parcours B demeure bloqué tant que le canal navigateur → proxy chiffré de bout en bout n'est pas conçu et éprouvé. Aucun secret cible ou texte opérateur ne doit être introduit dans le Gateway ou le Broker.

### Incrément 4 — première orchestration applicative du step-up (historique, consolidé à l'incrément 5)

- À cet incrément, le Broker exposait trois méthodes applicatives séparées (start/verify/consume). À l'incrément 5, verify et consume ont été consolidées dans `InjectVaultSecretWithStepUp` et les méthodes qui retournaient le grant ont été supprimées : le grant reste désormais dans une seule portée locale.
- Le binding est construit depuis le jeton vérifié par la Gateway (`actorID`) et la session persistée : compte et protocole ne sont jamais repris du corps opérateur. Seul le demandeur de la session peut déclencher le step-up ; la session doit être `active` et non expirée.
- Chaque étape refait `Authorization.CheckAccess` pour l'action exacte et le compte exact : ressource `secret:inject:account:{id}` / action `secret:inject`, ou `secret:paste:account:{id}` / action `secret:paste`. Refus d'autorisation audité sous `session.secret_step_up`, fail-closed si l'audit échoue. Une panne Authorization est un refus de service (`503`), jamais une permission.
- Le grant opaque reste dans le chemin applicatif Broker et n'est jamais renvoyé à une API publique. La version finale le consomme après une seconde validation de session et d'Authorization, avant l'émission du scope Vault.
- Tests : binding reconstruit, autorisation sur la ressource/action exacte, refus du non-demandeur, refus de politique avec audit, session expirée, propagation de la preuve et consommation du grant. Tests ciblés : PASS.
- **À la fin de l'incrément 4** : routes Gateway/Broker, scope Vault dédié et commande proxy restaient non livrés. Ces éléments internes sont désormais câblés à l'incrément 5 ; les routes Gateway/Broker et l'interface opérateur restent à faire.

- Validation du contenu avant toute dépendance : chaque secret est UTF-8 valide, mono-ligne et sans caractère de contrôle ; un secret Vault est limité à 4 Kio, tandis que le texte opérateur reste limité à 128 caractères. Cela évite qu'un retour chariot provenant du coffre exécute une seconde commande dans le shell.

- Audit à deux phases : `session.secret_injection_started` est acquitté avant le marqueur Command Recorder et la frappe ; après la tentative, `session.secret_injected` ou `session.secret_injection_failed` enregistre le résultat. Le marqueur vidéo/terminal indique explicitement « injection requested » et ne prétend pas que la frappe a réussi. L'événement de résultat utilise un contexte détaché mais borné à 3 s afin de survivre à la déconnexion du client après la frappe.

- Clarification de la frontière de confiance : le scope Vault est une capacité bearer à durée courte, pas le credential cible. Le Broker le reçoit transitoirement de Vault et le relaie uniquement au proxy mTLS sélectionné ; il ne le persiste, ne le journalise et ne le retourne jamais à la Gateway/UI. La Gateway ne voit jamais le scope. L'invariant absolu porte sur le credential/secret cible : il n'est reçu que par le proxy. Le scope doit être traité comme sensible et ne jamais apparaître dans les logs ou traces.

- Résiduel distribué : si le proxy a déjà écrit dans le shell mais que l'événement d'audit final ne peut pas être acquitté, l'API répond en échec alors que la cible peut avoir reçu tout ou partie de la valeur. L'événement préalable et le marqueur « injection requested » restent présents ; aucune répétition du grant n'est possible. L'opérateur devra vérifier l'état de la cible avant une nouvelle cérémonie MFA. Aucun système ne peut annuler une frappe déjà reçue par une cible distante.
