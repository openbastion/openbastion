# ADR-0096 — Le presse-papiers RDP passe du texte, dans chaque sens selon une politique, enregistré et audité

**Statut** `Accepté` · 13 novembre 2026 · deuxième point du lot D d'ADR-0090, après le socle des canaux (ADR-0095). Accepté le 13 novembre 2026 par le propriétaire du projet : « Je valide ta proposition. » L'option A est acceptée, avec ses bornes (64 Kio par transfert, 10 transferts par minute et par session) et `SCREEN_CLIPBOARD` éteint par défaut. La décision lève, pour le texte du presse-papiers seulement, ce qu'ADR-0069 §6 garde fermé, et étend ce qu'ADR-0070 enregistre. Le propriétaire demande en parallèle d'étudier une saisie automatique des mots de passe, pour qu'ils ne passent pas par le presse-papiers ni par l'enregistrement (voir « Suite »).

## Contexte

Le socle des canaux virtuels existe (ADR-0095) : une liste fermée, des bornes, un canal prouvé contre Windows. Le presse-papiers est le canal que les opérateurs demandent le plus, et le premier qui transporte du **contenu** :
- de l'opérateur vers la cible (coller) : un mot de passe tapé ailleurs, une commande, un script entier. C'est une voie d'entrée de données dans un système privilégié ;
- de la cible vers l'opérateur (copier) : un résultat, mais aussi n'importe quelle donnée de la cible. C'est une voie de sortie, celle d'une exfiltration.

ADR-0069 §6 garde ces canaux fermés tant qu'une décision n'a pas fixé leur enregistrement, leur protection et leur audit. ADR-0070 dit que le presse-papiers n'est pas enregistré. Un invariant tient : **enregistrer ou refuser** (ADR-0008). Un transfert qui ne serait ni enregistré ni audité serait un trou dans la trace de la session.

Le protocole est MS-RDPECLIP, sur le canal statique `cliprdr` : capacités, liste des formats proposés, demande d'un format, réponse avec les données, sur chaque sens. Le texte y est le format `CF_UNICODETEXT` (UTF-16 terminé par un zéro).

## Options

**A. Le texte, dans chaque sens, selon une politique, enregistré et audité (recommandée).**
- Le canal `cliprdr` rejoint la liste fermée, seulement pour une session dont la politique ouvre au moins un sens.
- Seul `CF_UNICODETEXT` est accepté. Tout autre format proposé par la cible (images, fichiers, HTML, formats privés) est retiré de la liste avant que l'opérateur ne la voie, et une demande d'un autre format est refusée.
- Chaque transfert est enregistré, chiffré avec la session, et audité avant d'être livré.

**B. Coller seulement (de l'opérateur vers la cible).** Moins de risque d'exfiltration, mais le besoin le plus courant, copier un résultat, reste sans réponse. Ce serait un premier pas de A, pas une autre décision.

**C. Auditer sans enregistrer le contenu** (seulement la taille et l'empreinte). L'auditeur saurait qu'un transfert a eu lieu, pas ce qu'il contenait : c'est la garantie « enregistrer ou refuser » affaiblie, et un auditeur ne pourrait pas dire si un secret est sorti.

## Décision : A

1. **Politique, refusée par défaut.** Deux droits, distincts, accordés par l'Authorization Service comme les autres (rôle, ressource, effet) :
   - `clipboard:to-target:<compte>` : coller vers la cible ;
   - `clipboard:from-target:<compte>` : copier depuis la cible.
   Le Broker les évalue à la création de la session et les inscrit dans le scope que reçoit le proxy. Sans droit, le canal n'est pas annoncé pour ce sens ; sans aucun des deux, `cliprdr` n'est pas annoncé du tout, et la session est celle d'aujourd'hui.
2. **Le canal** (`pkg/rdp`) : `cliprdr` dans la liste fermée d'ADR-0095, ses PDU lues strictement (MS-RDPECLIP), un seul format accepté, `CF_UNICODETEXT`. Les formats `CF_TEXT` et `CF_OEMTEXT` ne sont pas acceptés : un seul encodage, pas de conversion à deviner.
3. **Bornes.** Un transfert fait au plus **64 Kio** de texte (32 768 caractères UTF-16). Au-delà, il est refusé et la session continue : le refus est audité, l'opérateur voit pourquoi. Un transfert à la fois par sens. Au plus 10 transferts par minute et par session : au-delà, refusés, audités.
4. **Enregistrement.** Chaque transfert devient une entrée de l'enregistrement de la session, chiffrée avec sa clé (ADR-0070), dans un nouveau codec `clipboard-text-v1` : le sens, l'heure, le texte. L'entrée est acquittée par le Video Recorder **avant** que le texte ne soit livré à la cible ou au navigateur : un transfert non enregistré n'a pas lieu. La relecture montre chaque transfert à son heure, à côté de l'écran.
5. **Audit.** Un événement `session.clipboard` par transfert, émis avant la livraison, avec dans ses détails bornés (ADR-0068) : le sens, la taille en octets, l'empreinte SHA-256 du texte. Jamais le texte lui-même : l'audit dit qu'un transfert a eu lieu et permet de le retrouver dans l'enregistrement, qui seul porte le contenu, chiffré.
6. **Admin UI.** Le navigateur ne lit le presse-papiers de l'opérateur que sur un geste de sa part :
   - **coller** : un bouton « Envoyer le presse-papiers » lit le texte (API Clipboard, avec la permission du navigateur), l'affiche avant l'envoi, et l'envoie sur confirmation ;
   - **copier** : quand la cible propose du texte, la page l'affiche dans un panneau, avec un bouton « Copier » qui l'écrit dans le presse-papiers de l'opérateur.
   Le contrat écran (`openbastion.screen.v1`) reçoit deux messages : un transfert vers la cible (client → proxy) et un transfert depuis la cible (proxy → client), bornés comme le reste.
7. **Interrupteur** `SCREEN_CLIPBOARD`, **éteint par défaut**, au proxy, au-dessus de la politique : éteint, `cliprdr` n'est jamais annoncé, quelle que soit la politique. L'allumer par défaut demandera le go du propriétaire, comme pour ADR-0095.
8. **Toujours fermés** : les fichiers par le presse-papiers (`FileGroupDescriptorW`, `CB_FILECLIP_NO_FILE_PATHS`), les images, le HTML, le RTF, et tout format privé. Les fichiers auront leur propre décision (ADR-0090, lot D, point 3).

## Mise en œuvre envisagée

1. `pkg/rdp` : `cliprdr` dans la liste fermée, PDU de MS-RDPECLIP lues strictement, filtre des formats, bornes. Tests, fuzzing, et contre Windows : copier et coller un texte connu dans Notepad.
2. Politique : les deux droits à l'Authorization Service, leur évaluation au Broker, leur passage au proxy dans le scope. Tests du refus par défaut et de chaque sens.
3. Enregistrement et audit : le codec `clipboard-text-v1` au Video Recorder, l'acquittement avant livraison, l'événement `session.clipboard`. Tests : un transfert non acquitté n'est pas livré ; la relecture le montre.
4. Contrat écran et Admin UI : les deux messages, les boutons et le panneau. Tests Vitest.
5. Vérification dans le navigateur sans interface de la CI Windows (comme ADR-0095) : coller vers Notepad, copier depuis Notepad, relire la session et y trouver les deux transferts.

## Mise en œuvre

**Incrément 1, fait (13 novembre 2026) : le canal `cliprdr`.** `pkg/rdp`, derrière `MCSClientSettings.ClipboardChannel` et `EnableClipboard`, que rien n'allume encore hors des tests :
- **Liste fermée** : `cliprdr` rejoint `drdynvc`, chacun derrière son propre réglage ; la liste passe d'un nom à deux. Chaque canal statique a désormais son lecteur (`channelReaders`), au lieu du lecteur unique d'ADR-0095.
- **Protocole** (`clipboard.go`, MS-RDPECLIP) : capacités en version 2 sans aucun drapeau (noms de format courts, pas de fichiers, pas de verrouillage) ; l'ordre est tenu (capacités, Monitor Ready, puis le reste) ; seul `CF_UNICODETEXT` est demandé ou donné, toute demande d'un autre format reçoit un échec ; fichiers, verrouillage, répertoire temporaire et types inconnus ferment la session.
- **Chaque sens selon son droit** : sans le droit de copier, une liste de formats de la cible est acquittée et rien n'est demandé ; sans le droit de coller, aucun texte n'est annoncé et une demande reçoit un échec.
- **En-tête visible** : `cliprdr` est annoncé avec `CHANNEL_OPTION_SHOW_PROTOCOL`, et chacun de ses fragments porte `CHANNEL_FLAG_SHOW_PROTOCOL`, comme chez mstsc et FreeRDP. Sans ce drapeau, les cinq Windows de la CI n'ont rien répondu après Monitor Ready. `drdynvc` reste tel quel.
- **Borne** : un texte fait au plus 65 526 octets en UTF-16, sans son zéro final, pour que la réponse, son en-tête et ce zéro tiennent dans un message de canal (64 Kio, ADR-0095). C'est la borne de 64 Kio du §3, en-tête compris.
- **Prouvé** : 8 tests ; 13 mutations tuées (deux ont d'abord survécu, deux trous de test comblés) ; `FuzzClipboard` (30 s). FreeRDP n'ouvre pas son presse-papiers : la session continue, un texte offert attend. **Contre Windows** (`TestRDPWindows_Clipboard`) : le texte de Notepad copié, puis un texte collé dans Notepad (avec « é » et « € ») et relu, prouvé sur Windows Server 2019 et 2022 en 32 bpp. Les trois 2022 en 16 bpp suivent au passage d'après, une fois le test corrigé pour trouver Notepad à l'écran : les cinq cibles Windows copient et collent.

**Incrément 2, fait (13 novembre 2026) : les droits, du Broker au proxy.** Rien ne s'ouvre encore : le proxy reçoit les droits, le moteur RDP ne les lit pas avant l'incrément 3.
- **Évaluation** : à la création d'une session RDP, et d'une session RDP seulement, le Broker demande à l'Authorization Service `clipboard:to-target:<compte>` et `clipboard:from-target:<compte>`, action `session:clipboard`, avec les rôles du demandeur. Un sens non accordé est refusé, de même qu'un sens sur lequel l'Authorization Service n'a pas pu répondre, même s'il dit « oui » avec son erreur. La session s'ouvre dans tous les cas, sans ce sens. SSH et VNC ne posent pas la question.
- **Conservation** : deux colonnes de `sessions` (`clipboard_to_target`, `clipboard_from_target`, migration `006`, fausses par défaut, donc fausses pour toute session antérieure). Elles sont fixées à la création : une sauvegarde ultérieure (une terminaison), même depuis une copie différente, ne les change pas.
- **Transport** : à `connect`, le Broker les passe au proxy dans `EstablishSession` (`clipboard_to_target`, `clipboard_from_target`, champs 9 et 10 du proto), sous mTLS, et non dans le scope du Vault comme l'écrivait le §1 : le scope est échangé au Vault et le proxy ne le lit pas. Ce choix est renversable. Le proxy les porte sur le ticket à usage unique jusqu'aux métadonnées de la session (`proxycore.SessionMetadata`). Il **refuse** (`400`, avant tout ticket) un droit de presse-papiers pour une session VNC : seul RDP a ce canal, et un tel droit trahirait un Broker en défaut. Le proxy SSH ne lit pas ces champs.
- **Prouvé** : tests de chaque sens (aucun, l'un, l'autre, les deux) de l'Authorization Service jusqu'au proxy, refus sur erreur, aucune question hors RDP, aller-retour PostgreSQL réel (`TestPostgresStore_ClipboardRightsRoundTrip`), refus VNC au proxy, contrat proto↔JSON ; 12 mutations, 12 tuées.

**Incrément 3a, fait (13 novembre 2026) : l'enregistrement d'un texte.** Le transport et l'audit suivent (3b).
- **Le message** : `screenstream` reçoit le type 5, `CLIPBOARD`. Après l'en-tête commun, un octet de sens (1 vers la cible, 2 depuis la cible), trois octets réservés à zéro, puis le texte en UTF-8. Le texte doit être de l'UTF-8 valide, sans NUL (le terminateur de la cible) et de 32 763 unités UTF-16 au plus, la borne de `pkg/rdp` : tout texte que le canal porte peut être enregistré. Un texte vide est admis.
- **Le Video Recorder** l'accepte sous le codec `clipboard-text-v1`, dans la suite numérotée des images. Il vérifie que l'entrée est le message `CLIPBOARD` de sa séquence et de son heure. Une entrée n'est pas une image : une image partielle qui la suit s'applique à l'écran de l'image clé d'avant. Un segment qui contient un texte est scellé au format 3, et aucun format ne s'ouvre sous un autre. Le texte est chiffré avec le segment.
- **La Gateway** le sert à la relecture, après la même vérification, à qui peut relire la session. Le proxy l'envoie sous ce codec.
- **Limite** : la relecture de l'Admin UI refuse encore ce codec, comme tout codec inconnu. Elle le montrera à l'incrément 4. D'ici là, `SCREEN_CLIPBOARD` reste éteint et aucun enregistrement n'en contient.
- **Prouvé** : aller-retour et refus du message, fuzzing de `Decode` ; écriture et relecture à l'identique au Video Recorder, sans texte en clair dans le stockage ; formats ; refus d'une entrée hors de sa place ; Gateway et client du proxy ; 14 mutations, 14 tuées.

**Incrément 3b, fait (13 novembre 2026) : le relais, l'audit et la borne.**
- **Ouverture** : le proxy n'ouvre le presse-papiers que si les trois conditions sont réunies : un droit pour la session, un codec qui le sait (RDP) et un auditeur. Ce dernier n'est branché que si `SCREEN_CLIPBOARD=true` (éteint par défaut, §7). Le moteur annonce alors `cliprdr` et l'ouvre dans les sens accordés. Le texte qui sort de la cible n'est lu qu'avec le droit de copier.
- **Un transfert**, dans cet ordre :
  1. le texte doit tenir dans le contrat ;
  2. la borne : 10 par minute et par session, les deux sens ensemble ;
  3. l'audit `session.clipboard` : le sens, la taille et l'empreinte SHA-256 dans les détails d'ADR-0068, jamais le texte ;
  4. l'enregistrement et son acquittement ;
  5. la livraison (le texte collé est offert à la cible ; le texte copié, comme le collé, est envoyé à la page).
  Sans l'événement d'audit, pas de transfert. Un refus (texte hors contrat, borne, audit indisponible) est audité en échec, et la session continue. Un enregistrement non acquitté termine la session (`recording_lost`), comme pour une image.
- **Une seule suite** : le moteur numérote ses images, le relais les décale du nombre de textes passés avant elles, de sorte que l'enregistrement et la page reçoivent la même suite. La file d'affichage ne jette jamais un texte : ni pour une image clé, ni quand les images partielles débordent, ni en attendant une image clé.
- **Copier** : quand la cible propose un texte, le moteur le demande aussitôt. Quatre textes au plus attendent le relais ; au-delà, un texte est perdu, jamais livré ni enregistré.
- **Admin UI** : la page lit le message `CLIPBOARD` et suit sa séquence ; la relecture parcourt ces entrées sans changer l'écran. Les montrer, et coller depuis la page, est l'incrément 4.
- **Prouvé** : ordre audit → enregistrement → livraison, refus sans audit, borne de 10 par minute, refus hors contrat, transfert non acquitté non livré, place dans la suite (image clé, texte, image partielle), conditions d'ouverture, file d'affichage ; moteur, auditeur, Admin UI ; 21 mutations, 21 tuées (une a d'abord survécu : le relais lisait-il les textes de la cible sans le droit de copier ? un test le dit désormais).

**Incrément 4, fait (13 novembre 2026) : le contrat écran et l'Admin UI.**
- **Le contrat ne dépend pas du client.** Il sert l'Admin UI et servirait de même le client Desktop que propose ADR-0098 (au statut `Proposé` à cette date), qui réutiliserait `openbastion.screen.v1`. L'encodeur et le décodeur sont en Go dans `pkg/screenstream` (`EncodeClipboardInput`, `DecodeClipboardInput`), utilisés par le proxy et la Gateway ; l'Admin UI a son équivalent TypeScript, testé contre les mêmes octets.
  - `HELLO` : bit 2, la session prend un texte collé ; bit 3, elle envoie un texte copié. Les bits suivants restent réservés. Un `HELLO` sans eux est celui d'avant.
  - Entrée `CLIPBOARD` (type 5, client → proxy) : la version, le type, deux octets réservés, la longueur du texte en octets (uint32), puis le texte en UTF-8, avec les bornes du message `CLIPBOARD` (sans NUL, 32 763 unités UTF-16 au plus). C'est la seule entrée qui dépasse 16 octets : 98 297 au plus.
  - Le proxy lit un message aussi long seulement pour une session qui peut coller ; les autres gardent les 64 octets d'avant. La Gateway valide chaque message d'un client aussi strictement que le proxy.
  - Une entrée de type 5 que le `HELLO` n'a pas offerte, ou mal formée, termine la session (`input_invalid`), comme toute entrée invalide.
- **La règle du geste vaut pour tout client** (§6 précisé). Un client ne lit le presse-papiers du poste que sur une action de l'opérateur. Il lui montre le texte, modifiable, avant l'envoi, et ne l'envoie que sur confirmation. Il n'écrit dans le presse-papiers du poste que sur la demande de l'opérateur. Un client Desktop, s'il voit le jour, devra la tenir.
- **Admin UI** : un panneau « Presse-papiers », visible seulement si le `HELLO` offre un sens.
  - « Coller vers la cible… » lit le presse-papiers au clic. Si le navigateur refuse, l'opérateur colle dans le champ. Le texte est montré avant « Envoyer », avec le rappel qu'un mot de passe collé sera dans l'enregistrement.
  - « Copier le texte de la cible » écrit le dernier texte copié.
  - Les cinq derniers transferts sont listés, en texte, jamais en balisage.
  - La relecture montre les trois derniers transferts jusqu'à la position, à leur heure, à côté de l'écran.
- **Prouvé** : aller-retour et refus de l'entrée et des bits du `HELLO`, `FuzzDecodeClipboardInput` (20 s) ; relais (texte collé enregistré puis offert, entrée non offerte qui termine la session, `HELLO` selon les droits) sous `-race` ; limite de lecture du proxy ; validation et relais de la Gateway ; Vitest du panneau et de la relecture. 17 mutations, 16 tuées ; la survivante est équivalente (la borne de taille en tête de `DecodeClipboardInput` refuse tôt ce que la borne en unités UTF-16 refuse de toute façon).
- **Reste** : la vérification dans un navigateur sans interface contre les cinq Windows de la CI (incrément 5), puis la décision du propriétaire sur `SCREEN_CLIPBOARD` par défaut.

## Conséquences

- (+) Le besoin le plus demandé des opérateurs, sans trou dans la trace : chaque transfert est enregistré, chiffré, audité et refusable par politique, dans chaque sens séparément.
- (+) L'auditeur voit ce qui est entré et sorti, à l'heure près, à côté de l'écran.
- (+) Éteint ou sans droit, rien ne change : la négociation d'aujourd'hui.
- (−) Une voie de sortie de données existe, même bornée et enregistrée : c'est le prix d'un presse-papiers. La politique `from-target` est ce qui la ferme.
- (−) Le texte du presse-papiers est dans l'enregistrement : un mot de passe collé par l'opérateur y sera, chiffré. C'est voulu (enregistrer ou refuser), et c'est à dire aux opérateurs.
- (−) Une surface d'entrée de plus, venue de la cible : les PDU de MS-RDPECLIP. Bornée, fuzzée, mais nouvelle.
- (−) VNC a son propre presse-papiers (ClientCutText, ServerCutText), en Latin-1 : hors de cette décision.
- (−) Coller demande un geste et une permission du navigateur : pas de Ctrl+V direct vers la cible.

## Suite

Le propriétaire a demandé, à l'acceptation, d'étudier une **saisie automatique** des mots de passe, sur le modèle d'op-forward, pour qu'un secret saisi dans la session ne finisse ni dans le presse-papiers ni dans l'enregistrement, tout en gardant le copier-coller. Cette étude fera l'objet de sa propre décision ; elle ne change pas celle-ci.

## Alternatives envisagées

- **B, coller seulement** : gardée comme premier pas possible de A, pas comme décision à part. Les deux sens ont la même mécanique ; c'est la politique qui choisit.
- **C, auditer sans enregistrer** : écartée. Elle affaiblit « enregistrer ou refuser » sur la voie même où une donnée sort.
- **Laisser le navigateur synchroniser le presse-papiers en continu** : écartée. Ce serait lire le presse-papiers de l'opérateur sans geste de sa part, et transférer ce qu'il n'a pas choisi d'envoyer.
