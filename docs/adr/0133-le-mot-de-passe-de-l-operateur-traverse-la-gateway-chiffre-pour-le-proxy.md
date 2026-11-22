# ADR-0133 — Le mot de passe de l'opérateur traverse la Gateway chiffré pour le proxy

**Statut** `Accepté` · 21 novembre 2026 · accepté le même jour par le propriétaire du projet : « Go pour l'option A avec l'empreinte salée ». L'option A (le chiffrement pour le proxy, avec sa limite) et l'empreinte salée (point 4) sont retenues. **Mise en œuvre** le 22 novembre 2026, en six incréments (PR #262, #263, #267, #268, #269, #270, #271), éprouvée de bout en bout en VNC (TigerVNC réel) et en RDP (cinq Windows de CI).

## Contexte

ADR-0097 a accepté deux façons de saisir un secret dans une session, par le proxy et jamais par le presse-papiers :

- **A**, un secret du Vault. C'est fait : routes, Admin UI (`SecretInjection.tsx`), audit en deux phases, frappe SSH, VNC et RDP, réconciliation.
- **B**, un mot de passe fourni par l'opérateur, saisi sans que son contenu soit enregistré. Il reste bloqué par une condition qu'ADR-0097 pose lui-même : « le parcours B demeure bloqué tant que le canal navigateur → proxy chiffré de bout en bout n'est pas conçu et éprouvé. Aucun secret cible ou texte opérateur ne doit être introduit dans le Gateway ou le Broker. »

**Ce qui est mesuré** :

- **Pour RDP et VNC**, le flux d'écran va du navigateur à la Gateway, puis de la Gateway au proxy. La Gateway le relaie en décodant chaque trame WebSocket (`coder/websocket`, `WithScreenAttach`) : ce que le navigateur y enverrait en clair, la Gateway le tiendrait en clair dans sa mémoire.
- **La Gateway sert aussi le code de l'Admin UI** (`/ui/`, une seule origine, ADR-0071). C'est le point qui borne tout ce qui suit.

**La limite que cette décision ne peut pas lever** : une Gateway **compromise** peut servir une Admin UI modifiée, qui lit le mot de passe avant tout chiffrement. Aucun chiffrement fait dans le navigateur ne protège contre elle :

- la clé du proxy lui parvient par la Gateway ;
- une clé épinglée dans le code de l'UI lui parvient aussi par la Gateway.

« De bout en bout » contre la Gateway elle-même est donc hors d'atteinte tant que l'UI est servie par la Gateway. Ce qui est à portée : **une Gateway saine ne tient jamais ce texte en clair**. Il n'est ni dans sa mémoire de relais, ni dans ses journaux, ni dans une capture de son trafic interne, ni dans un vidage de mémoire.

## Options

- **A. Chiffrer pour le proxy, par une clé éphémère de la session d'écran (recommandée).**
  - Le proxy tire une paire ECDH P-256 par session d'écran et en publie la clé publique dans son `HELLO`.
  - Le navigateur chiffre le mot de passe avec WebCrypto : une paire éphémère par saisie, ECDH, HKDF-SHA-256 puis AES-256-GCM, un message par saisie.
  - Le message lie ce qu'il chiffre à la session, au jeton de saisie et au protocole, comme données associées.
  - La Gateway ne relaie que le chiffré. Elle ne peut ni le lire, ni le rejouer, ni le déplacer vers une autre session.
- **B. Une connexion directe du navigateur au proxy**, le proxy publié avec son propre certificat. Ce serait une deuxième origine, et une exposition publique du proxy, contraire à ADR-0071. Et l'UI reste servie par la Gateway : la limite ci-dessus demeure, pour un coût plus grand. Écartée.
- **C. Signer la clé du proxy par une autorité interne épinglée dans l'UI.** Le code de l'UI vient de la Gateway : l'épinglage ne vaut pas plus que la Gateway. Écartée.
- **D. Renoncer à B**, garder A seul. C'est possible, mais le propriétaire a voulu garder le copier-coller d'un mot de passe (ADR-0097).

## Décision : A

1. **Le canal.**
   - Le `HELLO` du flux d'écran porte la clé publique ECDH P-256 éphémère de la session d'écran. Le proxy la tire à l'ouverture et l'efface à la fermeture.
   - Un nouveau message client → proxy, `PASTE`, porte :
     - la clé publique éphémère du navigateur ;
     - un nonce de 12 octets ;
     - le chiffré AES-256-GCM, avec comme données associées : identifiant de session, jeton de saisie, protocole, version du message.
   - Le message est borné à 128 caractères avant chiffrement, sur une seule ligne, sans tabulation ni caractère de contrôle (ADR-0097, point 6).
   - La clé de chiffrement est HKDF-SHA-256 du secret ECDH, avec un sel et une étiquette propres à OpenBastion.
   - Primitives de la bibliothèque standard Go (`crypto/ecdh`, `crypto/hkdf`, `crypto/cipher`) et de WebCrypto : aucune dépendance nouvelle.
2. **L'autorisation**, sans que le texte passe par le Broker :
   - L'UI demande la saisie au Broker. Le droit `secret:paste:<compte-cible>` est refusé par défaut, et le second facteur est exigé à chaque saisie, comme pour A : c'est le parcours existant (`secret-injection-step-up`).
   - Le Broker remet au proxy, par mTLS, un **jeton de saisie** à usage unique, de courte durée (60 s), lié à la session et à l'opérateur. Il remet le même jeton à l'UI, qui n'en reçoit rien d'autre.
   - Le proxy n'accepte un `PASTE` que pour un jeton qu'il détient, dont l'opérateur et la session correspondent, une fois.
3. **Au proxy**, dans l'ordre d'A :
   - déchiffrer, vérifier les bornes ;
   - écrire l'audit `session.secret_pasted` (taille, empreinte, compte, session, protocole) ;
   - poser le marqueur dans l'enregistrement, taper par le `SecretTyper` existant, effacer.
   - Sans audit, pas de frappe. Un `PASTE` qui ne se déchiffre pas, hors bornes, sans jeton ou rejoué est refusé, audité, et la session continue.
4. **L'empreinte enregistrée** : ADR-0097 dit « SHA-256 ». Pour un mot de passe court, une empreinte nue se casse par dictionnaire hors ligne, par quiconque lit l'audit. Retenu : SHA-256 **salé**, avec un sel aléatoire par saisie, enregistré à côté. Celui qui détient une valeur candidate peut toujours la reconnaître, mais une table précalculée ne sert plus à rien. Un mot de passe faible reste attaquable, saisie par saisie.
5. **Le périmètre** : RDP et VNC, par le flux d'écran. SSH n'a pas de flux d'écran : le terminal est le client SSH de l'opérateur. Son canal fera l'objet d'un incrément à part.
6. **L'Admin UI** : un bouton « Saisir un mot de passe » et un champ masqué, jamais lu du presse-papiers sans geste. Le rappel d'ADR-0097, point 9, s'affiche à chaque saisie : un champ non masqué de la cible montrera le texte à l'écran enregistré.

## Conséquences

- (+) Une Gateway saine ne tient jamais le mot de passe en clair. Le Broker ne le voit jamais.
- (+) Un chiffré capturé ne se rejoue pas : le jeton est à usage unique, lié à la session. Il ne se déplace pas non plus, car les données associées lient session, jeton et protocole.
- (−) **Une Gateway compromise lit le mot de passe** : elle sert l'UI. C'est la limite de toute solution où la Gateway sert l'UI, et la documentation de sécurité doit le dire.
- (−) Pour ce texte, l'enregistrement ne garde que la taille et l'empreinte salée : un auditeur ne sait pas ce qui a été saisi.
- (−) Un nouveau message du contrat d'écran, et une cryptographie côté navigateur, à tester dans un navigateur réel (sans interface) pour RDP et VNC.

## Alternatives envisagées

- **B** et **C**, voir ci-dessus : elles ne protègent pas mieux, car l'UI vient de la Gateway, et B coûte une exposition publique du proxy.
- **Passer le texte par le Broker, chiffré pour le proxy** : c'est le même chiffrement, avec un saut de plus. Rien n'y gagne.
- **Un SHA-256 nu, comme ADR-0097 l'écrit** : écarté pour un mot de passe court, voir le point 4.

## Mise en œuvre

### Incrément 1a — l'empreinte salée et le marqueur de l'opérateur (21 novembre 2026)

- **Fait** :
  - l'empreinte d'un mot de passe de l'opérateur est SHA-256(sel ‖ texte), avec un sel aléatoire de 16 octets par saisie, gardé à côté (point 4). Le chemin commun (`InjectSecret`, `SaltedSecretFingerprint`) la calcule ; le marqueur SSH, l'audit SSH et l'audit du proxy écran l'écrivent avec son sel, jamais le texte. Les événements d'audit sont `session.secret_paste_started`, `session.secret_pasted` et `session.secret_paste_failed` ;
  - le Video Recorder accepte un marqueur `secret_paste_started` de source `operator`, qui porte `paste_bytes` (1 à 512), `paste_salt` et `paste_sha256`. Le changement touche le contrat protobuf (ajout seul), l'application, la mémoire et PostgreSQL (`003_video_paste_events.sql`) : la contrainte de la table refuse un marqueur du Vault avec empreinte, et un marqueur de l'opérateur sans elle ou avec son texte à la place. La Gateway le relaie et le vérifie ; l'Admin UI l'affiche en relecture.
- **Trouvé par le test PostgreSQL** : la première contrainte laissait passer un marqueur de l'opérateur sans empreinte, car un CHECK sur NULL passe. Les colonnes sont exigées NOT NULL.
- **Prouvé** : chaque couche (application, PostgreSQL réel, Gateway, Admin UI, clients d'audit et du Video Recorder du proxy écran, audit SSH) accepte ce qu'elle doit et refuse les mélanges ; l'empreinte se retrouve à partir du sel et de la valeur.
- **Reste** : l'incrément 1b (le canal chiffré du flux d'écran, les jetons à usage unique, la route interne du proxy), puis le Broker et la Gateway, puis l'Admin UI.

### Incrément 1b — le canal chiffré du flux d'écran (21 novembre 2026)

- **Fait** :
  - **le contrat d'écran** (`pkg/screenstream`) : le `HELLO` porte la clé publique ECDH P-256 de la session derrière le drapeau `HelloPaste` (65 octets après l'identifiant de session). Un `HELLO` sans lui est, à l'octet près, celui d'avant. Le message client `InputPaste` porte le jeton (32 octets), la clé éphémère du client (65), le nonce (12) et le chiffré (au plus 512 octets de texte et 16 d'étiquette). L'Admin UI lit déjà la clé ;
  - **la cryptographie** (`pkg/proxycore/paste.go`) : clé de session tirée à l'ouverture et jamais écrite ; HKDF-SHA-256 salé par le jeton, lié aux deux clés publiques ; AES-256-GCM, avec session, jeton et protocole comme données associées. `SealPaste` est ce que fait le navigateur, écrit en Go pour les tests. HKDF vient de `golang.org/x/crypto`, déjà dépendance du dépôt : `crypto/hkdf` demande Go 1.24, et `pkg/proxycore` passe à `go 1.26.0`, comme l'espace de travail ;
  - **le relais** : la clé n'est publiée qu'avec un registre qui tient les jetons et un auditeur. Le jeton est pris avant de déchiffrer, puis vient le chemin commun d'ADR-0097. Un refus est audité (`session.secret_paste_refused`) et la session continue ; un `InputPaste` mal formé, ou envoyé à une session qui n'en prend pas, la termine ;
  - **le proxy écran** : les jetons du registre servent une fois, pour une session, 60 s au plus, et leur nombre est borné. La route interne `POST /internal/v1/authorize-paste` est réservée au certificat `session-broker`, et le contrat protobuf gagne `ProxyControl.AuthorizePaste`.
- **Prouvé** :
  - sur le vrai relais : un mot de passe scellé pour la session est tapé, son empreinte salée enregistrée et auditée, jamais son texte ;
  - le même message rejoué, un jeton que personne n'a émis, un chiffré pour une autre session et un texte de 129 caractères sont refusés et audités, et la session continue ;
  - une session sans registre n'a pas de clé, et un `InputPaste` reçu malgré tout la termine ;
  - le chiffré ne s'ouvre ni pour une autre session, ni pour un autre protocole, une autre clé, un autre jeton ou un octet changé ;
  - le registre et la route ont leurs bornes, et le fuzzer du décodeur n'a rien trouvé ;
  - **6 mutations tuées sur 6** (données associées, prise du jeton avant le déchiffrement, session et expiration du jeton, refus des bornes). La dernière a montré un trou du test, refermé ;
  - `-race`.
- **Reste** : le Broker et la Gateway (le second facteur, puis le jeton remis au proxy et à l'UI), puis l'Admin UI (WebCrypto, le bouton et le champ masqué, le test en navigateur).

### Incrément 2 — l'autorisation d'une saisie : le Broker et la Gateway (21 novembre 2026)

- **Fait** :
  - deux routes publiques, construites comme celles du secret du Vault : `POST /sessions/{id}/secret-paste-step-up` (le facteur pour `secret:paste` sur le compte de la session) et `POST /sessions/{id}/secret-paste` (la preuve, rien d'autre : un champ de plus, dont un texte, est refusé). L'identité et les rôles viennent du jeton vérifié, et les routes partagent le seau des actions de session ;
  - au Broker, `AuthorizeOperatorPasteWithStepUp` :
    - le demandeur seul, sur une session VNC ou RDP active (SSH n'a pas de flux d'écran : `409`) ;
    - le facteur vérifié, la session et le droit relus après lui, le grant consommé avant que le jeton existe ;
    - un jeton de 32 octets remis par mTLS au proxy écran qui relaie la session (pour 60 s, `ProxyControl.AuthorizePaste`, routeur de protocoles puis instance d'affinité) ;
    - l'audit `session.secret_paste_authorized`, puis le même jeton rendu au navigateur. Sans audit, le navigateur n'a rien, et le jeton du proxy expire inutilisé.
- **Prouvé** :
  - le facteur, puis le jeton : la liaison du facteur, la consommation, et le même jeton au proxy et au navigateur, pour VNC et RDP ;
  - refusés : SSH, un autre utilisateur, un droit retiré pendant le facteur (rien n'est consommé, rien n'atteint le proxy), un proxy qui refuse le jeton, un audit absent, un Broker sans proxy de saisie ;
  - la Gateway ne fait passer que la preuve, avec l'identité du jeton, et partage le budget des actions ;
  - le client du Broker vers le proxy n'envoie que le jeton et sa durée ;
  - 3 mutations tuées sur 3 (la relecture après le facteur, l'audit avant le jeton, le refus de SSH) ; test de contrat.
- **Reste** : l'Admin UI (incrément 3) : le bouton « Saisir un mot de passe », le champ masqué, le facteur, WebCrypto, l'envoi par le flux d'écran, et le test dans un vrai navigateur.

### Incrément 3 — l'Admin UI (21 novembre 2026)

- **Fait** :
  - le bouton « Saisir un mot de passe… » dans l'écran d'une session VNC ou RDP. Il n'apparaît que si le `HELLO` porte la clé du proxy, et il demande la capacité `secrets.paste` (`secret:paste` sur un compte) ;
  - le mot de passe est lu dans un champ masqué, jamais dans le presse-papiers. Il est vérifié comme le proxy le vérifiera (128 caractères au plus, une ligne, sans tabulation ni caractère de contrôle) avant de demander un facteur ;
  - le facteur (TOTP ou clé), le jeton, puis le chiffrement WebCrypto (`pasteCrypto.ts` : ECDH P-256, HKDF-SHA-256, AES-256-GCM) et l'envoi par le flux d'écran (`InputPaste`) ;
  - le rappel de placer le curseur dans un champ masqué de la cible.
- **Prouvé** :
  - un **vecteur à réponse connue** commun aux deux côtés : `pkg/proxycore/paste_vector_test.go` le produit et l'ouvre, `pasteCrypto.test.ts` retrouve le même chiffré, octet pour octet ; une autre session, un autre protocole ou un autre texte donnent autre chose ;
  - le composant : la preuve seule part vers l'API, jamais le mot de passe ; le message envoyé porte le jeton du Broker et pas le texte en clair ; un texte invalide ne coûte aucun facteur ; sans jeton, ou avec un jeton mal formé, rien n'est envoyé ;
  - 4 mutations tuées sur 4 (validation, contrôle du jeton, données associées, sel), plus une témoin qui survit.
- **Reste** : le parcours dans un vrai navigateur, contre le proxy réel (`TestBase44Preview` ou un test Playwright), qui prouvera le texte tapé dans la cible.

### Incrément 4 — le parcours de bout en bout, et trois défauts qu'il a trouvés (21 novembre 2026)

- **Trois défauts réels**. Avant ce parcours, aucune saisie n'aurait atteint une cible en production :
  1. **la Gateway** relit chaque message du navigateur avant de le relayer (`validScreenInput`) et ne connaissait que les entrées de 16 octets et le presse-papiers : un `InputPaste` coupait l'écran. Elle vérifie maintenant sa forme (`DecodePasteInput`) ; elle ne peut pas l'ouvrir ;
  2. **la limite de lecture du proxy** (`screenReadLimit`) était de 64 octets hors presse-papiers ; elle va jusqu'à la plus longue saisie chiffrée quand le proxy prend les saisies ;
  3. **la lecture WebSocket du proxy** (`websocketScreenSink.ReceiveInput`) rejetait tout ce qui n'était ni une entrée de 16 octets ni un texte de presse-papiers ; la session finissait en `target_unreachable`.
  Les tests de l'incrément 1b prenaient la boucle du relais en mémoire, sans ces deux couches ; chacun a maintenant son test unitaire et sa contre-épreuve (le test échoue sans le correctif).
- **Prouvé sur processus réels** (`operator_paste_vnc_flow_test.go`, dans le parcours VNC à huit services sous mTLS, Video Recorder sur PostgreSQL). Le client est `proxycore.SealPaste`, dont le chiffrement est celui de l'Admin UI (vecteur commun) :
  - la cible reçoit le mot de passe, touche par touche ;
  - un jeton inventé, un message scellé pour une autre session (qui brûle le jeton) et le même message rejoué ne tapent rien, et chacun est audité `session.secret_paste_refused` ;
  - un autre utilisateur ne peut pas demander le facteur ;
  - l'enregistrement porte un seul marqueur `secret_paste_started`, avec la taille et l'empreinte : `pasteSha256` vaut SHA-256(`pasteSalt`‖mot de passe), sel de 16 octets ;
  - ni le stockage objet, ni un événement d'audit, ni un journal de service ne contient le mot de passe ;
  - en CI, le même parcours contre le vrai TigerVNC (`OPENBASTION_VNC_TARGET`).
- **Prouvé dans un vrai navigateur** (`admin_ui_operator_paste_browser_test.go`, Chromium, job navigateur de `integration.yml`) : l'Admin UI chiffre ; la clé est tirée par `proxycore.NewPasteKey` et ouverte par `(*PasteKey).Open`, le code même du proxy, qui retrouve le mot de passe tapé. Le message ne s'ouvre ni pour une autre session ni pour un autre protocole ; l'API n'a reçu que la preuve du facteur. Contre-épreuve : une étiquette de dérivation changée dans le navigateur, et le proxy refuse.
- **Reste** : un même test qui enchaîne le navigateur et les processus réels (l'Admin UI servie par la Gateway, avec Chrome, dans le job PostgreSQL) ; les deux moitiés sont prouvées séparément, et le vecteur commun les relie. RDP : la saisie suit le même chemin dans le proxy (`InjectSecret`), mais aucun test ne la tape encore dans un Windows réel ; la règle de ne jamais taper de secret dans un test Windows s'applique aussi ici.

### Incrément 5 — le trajet d'un seul tenant (22 novembre 2026)

- **Prouvé** (`TestScreenFlow_VNCInAHeadlessBrowser`, job PostgreSQL : l'Admin UI construite, servie par la Gateway, dans Chrome ; les services réels sous mTLS ; le vrai TigerVNC en CI, la cible simulée sinon) :
  - un opérateur avec second facteur se connecte dans la page (mot de passe, puis code), ouvre l'écran de sa session, tape un mot de passe dans le champ masqué du bouton « Saisir un mot de passe… » et confirme par un second code ;
  - la cible reçoit le mot de passe, touche par touche (sans les modificateurs qu'un serveur X ajoute) ; l'écran reste ouvert ;
  - l'enregistrement porte un seul marqueur, dont `pasteSha256` vaut SHA-256(`pasteSalt`‖mot de passe) ; `session.secret_pasted` est audité ; ni le stockage objet, ni l'audit, ni le journal du proxy ne contient le mot de passe.
  - Contre-épreuve : sans le correctif de la lecture WebSocket du proxy (incrément 4), le mot de passe n'arrive pas et le test échoue.
- **Reste** : RDP dans un vrai Windows, que la règle de ne jamais taper de secret dans un test Windows tient à l'écart ; la décision revient au propriétaire (un mot de passe de test jetable ?).

### Incrément 6 — RDP dans un vrai Windows (22 novembre 2026)

- **Décision du propriétaire** (22 novembre 2026) : un mot de passe **inventé dans le test et sans valeur** peut être tapé dans le Windows de CI. Jamais le mot de passe du compte cible, jamais un secret du Vault.
- **Le test** (`TestScreenFlow_RDPOperatorPasteInAHeadlessBrowser`, `windows-rdp.yml`, sur les cinq cibles Windows) : les services réels, l'Admin UI construite servie par la Gateway, Chrome.
  - Un opérateur avec second facteur se connecte, ouvre l'écran de sa session RDP, sélectionne le texte de Notepad et saisit le mot de passe par le bouton, avec un second code.
  - Le texte de Notepad, recopié par le panneau du presse-papiers, est le mot de passe : c'est Windows qui en témoigne. Notepad l'affiche exprès, comme témoin ; un opérateur, lui, place le curseur dans un champ masqué.
  - L'enregistrement porte un seul marqueur RDP, dont l'empreinte vaut SHA-256(sel‖mot de passe) ; ni l'audit ni le journal du proxy ne contient le mot de passe.
  - Le proxy tape en `TS_UNICODE_KEYBOARD_EVENT` : la disposition du clavier (fr-FR comprise) n'y change rien.
- **Limite** : ce test ne tourne qu'en CI (dockur, KVM) ; il n'a pas été lancé en local avant la PR.

