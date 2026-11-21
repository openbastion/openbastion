# ADR-0133 — Le mot de passe de l'opérateur traverse la Gateway chiffré pour le proxy

**Statut** `Accepté` · 21 novembre 2026 · accepté le même jour par le propriétaire du projet : « Go pour l'option A avec l'empreinte salée ». L'option A (le chiffrement pour le proxy, avec sa limite) et l'empreinte salée (point 4) sont retenues.

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

