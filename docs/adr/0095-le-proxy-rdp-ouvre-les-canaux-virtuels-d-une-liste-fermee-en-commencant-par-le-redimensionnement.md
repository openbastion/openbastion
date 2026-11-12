# ADR-0095 — Le proxy RDP ouvre les canaux virtuels d'une liste fermée, en commençant par le redimensionnement

**Statut** `Accepté` · 12 novembre 2026 · demandé par le propriétaire du projet le 12 novembre 2026 : « go pour le lot D » (ADR-0090) ; accepté le même jour : « Go pour le B ». L'option B est acceptée, avec ses bornes (64 Kio par message de canal, 640 × 480 à 2 560 × 1 600, un redimensionnement par seconde) et `SCREEN_RESIZE` éteint par défaut. La décision lève en partie ADR-0069 §6 : elle ouvre le socle des canaux, et un seul canal, qui ne transporte aucune donnée de l'opérateur vers la cible en dehors de la taille de son écran.

## Contexte

Aujourd'hui, le client RDP du proxy ne demande **aucun canal virtuel** :
- le bloc `CS_NET` de la négociation GCC n'en annonce aucun ;
- un `SC_NET` qui en contiendrait un est refusé (`pkg/rdp/mcs_gcc.go`) ;
- seul le canal d'E/S (1003) et le canal de l'utilisateur sont joints.

ADR-0069 §6 l'a voulu ainsi : presse-papiers, lecteurs, imprimantes et son restent fermés tant qu'une décision n'a pas fixé leur enregistrement, leur protection et leur audit. ADR-0090 (lot D) prévoit d'abord un **socle**, des canaux statiques et dynamiques avec une liste fermée et des bornes par canal, puis chaque canal sous son propre ADR, derrière un interrupteur éteint par défaut. Le lot A est mesuré : il ne justifie pas le lot B, et le lot D est le suivant (ADR-0090, « Ordre et dépendances »).

**Ce que le socle ouvre, et ce qu'il risque :**
- un canal virtuel est une seconde voie de données entre la cible et le proxy, à côté de l'écran. Chaque octet qu'il apporte est une entrée non fiable à borner ;
- un canal dynamique (`DRDYNVC`, MS-RDPEDYC) laisse **la cible** proposer des canaux par leur nom. Le proxy doit refuser tout nom qu'il ne connaît pas, sans fermer la session pour autant : c'est le protocole ;
- un canal qui transporte du contenu (presse-papiers, fichiers) touche l'invariant « enregistrer ou refuser ». Aucun n'est ouvert ici.

**Le premier canal utile** est le contrôle d'affichage (`Microsoft::Windows::RDS::DisplayControl`, MS-RDPEDISP), qui permet de redimensionner le bureau à la taille de la fenêtre de l'opérateur. Il ne transporte que des dimensions. Le flux écran suit déjà un changement de taille par une image clé (ADR-0071, incrément 72 ; ADR-0092), et le rejeu aussi.

## Options

**A. Le socle seul**, sans aucun canal ouvert. Le code de jonction et de cadrage existerait, mais rien ne l'éprouverait contre Windows au-delà de la négociation : on ne prouve pas un socle sans un canal qui s'en serve.

**B. Le socle et le contrôle d'affichage (recommandée).** Le proxy joint un seul canal statique, `drdynvc`, et n'accepte qu'un seul canal dynamique, le contrôle d'affichage. L'opérateur redimensionne, la cible suit, l'enregistrement suit. Le socle est éprouvé de bout en bout par un canal sans contenu.

**C. Le socle et le presse-papiers d'abord.** C'est le canal le plus demandé, mais il transporte du contenu dans les deux sens : il demande d'abord une politique par sens, l'enregistrement chiffré du contenu et un audit par transfert (ADR-0090, lot D, point 2). Deux décisions de sécurité d'un coup, sur un socle pas encore éprouvé.

## Décision : B

1. **Liste fermée des canaux statiques** : le client annonce dans `CS_NET` le seul canal `drdynvc`, et seulement si un canal dynamique est permis (point 5). Sinon, rien ne change : aucun canal n'est annoncé.
   - Un `SC_NET` qui ne rend pas exactement un identifiant de canal par canal annoncé, distinct du canal d'E/S et de l'utilisateur, ferme la connexion.
   - Le proxy joint ce canal comme les autres (Channel Join), et aucun autre.
2. **Cadrage des canaux statiques** (`CHANNEL_PDU_HEADER`, MS-RDPBCGR 2.2.6.1) :
   - un message reconstitué à partir de ses fragments fait au plus **64 Kio** ; au-delà, la session ferme ;
   - un fragment qui ne suit pas `CHANNEL_FLAG_FIRST` … `CHANNEL_FLAG_LAST`, ou dont la longueur annoncée ne correspond pas, ferme la session ;
   - une donnée reçue sur un canal que le proxy n'a pas joint ferme la session (`target_protocol`, ADR-0071 §12) ;
   - la compression des canaux (`CHANNEL_FLAG_PACKET_COMPRESSED`) n'est pas annoncée ; reçue, elle ferme la session.
3. **Canaux dynamiques** (MS-RDPEDYC) :
   - le proxy répond aux capacités de la cible sans la compression de la version 3 ; une cible qui l'exigerait est refusée, constat à vérifier contre Windows ;
   - à chaque `DYNVC_CREATE_REQ`, il accepte le nom s'il est dans la liste, et refuse sinon, par une réponse d'échec : la cible continue sans ce canal, la session aussi. Chaque refus est compté et journalisé, sans le contenu ;
   - un même nom ne s'ouvre qu'une fois à la fois. Un message `DATA_FIRST`/`DATA` reconstitué fait au plus 64 Kio. Une donnée pour un identifiant non ouvert ferme la session.
4. **Le contrôle d'affichage**, seul nom accepté :
   - le proxy attend la capacité de la cible (`DISPLAYCONTROL_CAPS_PDU`) avant d'envoyer quoi que ce soit, et s'y tient (nombre d'écrans, surface maximale) ;
   - il envoie un seul écran, principal, à l'origine : `DISPLAYCONTROL_MONITOR_LAYOUT_PDU`, sans orientation ni facteur d'échelle ;
   - **bornes** : largeur et hauteur de 640 × 480 à 2 560 × 1 600, largeur paire (MS-RDPEDISP), et au plus un redimensionnement par seconde. Au-delà de 2 560 × 1 600, une image clé PNG risque de dépasser les 4 Mio d'un segment (ADR-0070) et de couper la session (`recording_lost`) ;
   - une demande hors bornes est ramenée dans les bornes, pas refusée : l'opérateur voit alors un bureau plus petit que sa fenêtre.
5. **Contrat écran** (`openbastion.screen.v1`) : un nouveau type d'entrée, `InputResize` (largeur, hauteur), dans la borne de 64 octets de `MaxInputBytes`. Le relais le borne avant de le passer au codec. Un codec qui ne sait pas redimensionner, comme VNC aujourd'hui, l'ignore.
6. **Interrupteur** `SCREEN_RESIZE`, **éteint par défaut**, au proxy. Éteint, aucun canal n'est annoncé, et la négociation est celle d'aujourd'hui, à l'octet près. L'Admin UI n'envoie `InputResize` que si le `HELLO` dit que la session sait redimensionner : un drapeau de plus dans l'octet de drapeaux du `HELLO` (ADR-0091).
7. **Enregistrement et audit** : le redimensionnement est déjà dans l'enregistrement, par l'image clé de la nouvelle taille. Le proxy n'écrit pas d'événement d'audit par redimensionnement : ce n'est ni un accès ni une donnée. Le refus d'un canal dynamique par son nom est journalisé (nom borné, compteur), sans audit, puisque la cible le propose et que l'opérateur n'y peut rien.
8. **Toujours fermés**, sans exception : presse-papiers, lecteurs, imprimantes, son, cartes à puce, ports, USB, caméra, saisie audio, et tout canal hors de la liste. Chacun demandera son ADR (ADR-0090, lot D).

## Mise en œuvre envisagée

1. `pkg/rdp` : annonce et jonction de `drdynvc`, cadrage et reconstitution bornés des canaux statiques. Tests de cadrage, tailles, fragments désordonnés, canal inconnu, et fuzzing (`make fuzz`). Contre FreeRDP, puis Windows en CI.
2. `pkg/rdp` : DRDYNVC, capacités, création et refus par nom, données, fermeture. Tests et fuzzing ; contre Windows, la liste des noms qu'il propose, et le refus de ceux qui ne sont pas dans la liste.
3. Contrôle d'affichage, `InputResize` dans `pkg/screenstream`, relais et codec RDP, interrupteur `SCREEN_RESIZE`. Contre Windows : demander une taille, recevoir une image clé de cette taille, rejouer la session.
4. Admin UI : envoyer la taille de la fenêtre, au plus une fois par seconde, quand le `HELLO` le permet. Tests Vitest.
5. Mesure et vérification dans un vrai navigateur, comme pour ADR-0092, avant d'allumer `SCREEN_RESIZE` par défaut. Ce dernier pas demandera le go du propriétaire.

## Mise en œuvre

**Incrément 1, fait (12 novembre 2026) : le canal statique.** `pkg/rdp`, derrière `MCSClientSettings.DynamicChannels`, que rien n'allume encore hors des tests :
- `CS_NET` annonce le seul `drdynvc` (options `INITIALIZED | ENCRYPT_RDP`) ; `SC_NET` doit lui donner un identifiant, distinct du canal d'E/S, avec le bourrage d'un compte impair. Le canal est joint après le canal d'E/S. Le Confirm Active ajoute alors le jeu de capacités des canaux virtuels, sans compression.
- Cadrage (`mcs_virtual_channel.go`) : un message reconstitué fait au plus 64 Kio ; un fragment hors de son message, une longueur qui change, des données plus longues ou plus courtes qu'annoncé, un drapeau autre que `FIRST`, `LAST` et `SHOW_PROTOCOL` (dont la compression), un segment MCS découpé, ou une donnée sur un canal non joint ferment la session. L'envoi découpe en morceaux de 1 600 octets.
- Les paquets d'un canal arrivés pendant la finalisation (ou une réactivation) sont gardés, 16 au plus, et lus en premier par `ReadBitmapUpdate`. Les messages complets vont au lecteur que `SetChannelHandler` désigne ; sans lecteur, ils sont jetés.
- **Prouvé** : tests unitaires de l'annonce, de `SC_NET`, du cadrage, du routage et de la finalisation ; 15 mutations tuées, plus une contre FreeRDP (sans la jonction, FreeRDP refuse la connexion). Deux fuzzers (`FuzzRDPChannelAssembler`, `FuzzRDPChannelPacket`). Contre FreeRDP 3 (`TestRDPInterop_StaticChannel`) : canal joint, 88 mises à jour d'écran, et la demande de capacités DRDYNVC (Cmd 5, 4 octets) reçue par la boucle de lecture. Éteint, la connexion est celle d'avant : tous les tests existants passent, FreeRDP compris.
- **À prouver en CI** : `TestRDPWindows_StaticChannel`, le même parcours contre les cinq cibles Windows.

**Incrément 2, fait (12 novembre 2026) : les canaux dynamiques.** `pkg/rdp/dynamic_channel.go`, derrière `EnableDynamicChannels`, que rien n'appelle encore hors des tests :
- **Capacités** : la réponse annonce la version 2 au plus, qui n'a pas de compression. Une deuxième demande de capacités, ou une longueur fausse pour sa version, ferme la session.
- **Création** : un nom n'est accepté que s'il est dans la liste fermée (`RDPDisplayControlChannel`), une seule fois à la fois. Tout autre nom reçoit un refus (`E_ACCESSDENIED`) et la session continue ; les 32 premiers noms refusés et leur nombre sont gardés (`DynamicChannelRefusals`). Ferment la session : un nom vide, de plus de 255 octets ou hors de l'ASCII imprimable, un identifiant déjà ouvert, une création avant les capacités.
- **Données** : 64 Kio au plus par message reconstitué. Ferment la session : des données sur un canal non ouvert, un `DATA_FIRST` dans un autre, des données plus longues qu'annoncé, la compression, et toute commande hors du protocole (dont la resynchronisation de la version 3).
- **Fermeture** : la cible ferme un canal, le client lui répond par sa propre fermeture, et le nom peut se rouvrir.
- **Envoi** : `SendDynamicChannelMessage` envoie un seul `DATA`, de 1 594 octets au plus.
- **Verrous** : les rappels (`onOpen`, `onMessage`) sont appelés une fois le verrou de la session relâché et les réponses envoyées. Un rappel peut donc envoyer à son tour : un test le prouve, et la mutation qui les appelle sous le verrou est tuée.
- **Prouvé** : 10 tests, 18 mutations tuées, un fuzzer (`FuzzDynamicChannels`, 30 s). Contre FreeRDP 3 (`TestRDPInterop_DynamicChannels`) : capacités échangées, `AUDIO_INPUT` proposé puis refusé, session poursuivie (81 mises à jour d'écran).
- **Prouvé contre Windows** (CI de #154, cinq cibles) : le contrôle d'affichage s'ouvre, et sa capacité arrive (`DISPLAYCONTROL_CAPS_PDU`, 20 octets). Windows propose aussi, et chaque fois reçoit un refus : `Microsoft::Windows::RDS::Geometry::v08.01` (4 à 5 fois par session), `Microsoft::Windows::RDS::Video::Control::v08.01`, `Microsoft::Windows::RDS::Video::Data::v08.01`, `Microsoft::Windows::RDS::Telemetry`, `Microsoft::Windows::RDS::Input` et `ECHO`. La session continue.

**Incrément 3, fait (12 novembre 2026) : le redimensionnement.**
- **Contrat écran** (`pkg/screenstream`) : `InputResize` (type 4 : la largeur en `X`, la hauteur en `Y`, rien d'autre), et le bit 1 des drapeaux du `HELLO` (`HelloResizable`). `ClampResize` ramène une taille entre 640 × 480 et 2 560 × 1 600, largeur paire.
- **Relais** (`pkg/proxycore`) : le `HELLO` dit ce que la session dit (`Resizer`). Une session qui ne redimensionne pas ne reçoit aucun `InputResize`. Sinon, la taille est ramenée dans les bornes, et un redimensionnement au plus par seconde est transmis : ceux qui arrivent plus tôt attendent, et seul le dernier passe à son tour. Ils sont hors du budget d'entrée.
- **Contrôle d'affichage** (`pkg/rdp/display_control.go`) : lecture stricte de `DISPLAYCONTROL_CAPS_PDU`, écriture d'un `DISPLAYCONTROL_MONITOR_LAYOUT_PDU` à un écran, principal, à l'origine, à 100 %.
- **Codec RDP** (`RDPCodec.Resize`, `SCREEN_RESIZE`, éteint par défaut) : annonce `drdynvc`, n'accepte que le contrôle d'affichage, et lit sa capacité une fois (tout autre message ferme la session). Un redimensionnement demandé avant cette capacité, ou au-delà de la surface qu'elle permet, est ignoré. Windows se réactive alors à la nouvelle taille, ce que le lecteur suit déjà, et l'image clé de la nouvelle taille est enregistrée.
- **Prouvé** : tests du contrat, du relais (le `HELLO`, l'ignorance, les bornes, le rythme, le budget), du contrôle d'affichage et du codec ; 16 mutations tuées ; `FuzzParseDisplayControlCaps`. Contre FreeRDP, qui n'offre pas de contrôle d'affichage : `SCREEN_RESIZE` allumé, la session va son chemin et le redimensionnement est ignoré.
- **Deux défauts trouvés par la CI Windows de #155, corrigés** :
  - le jeu de capacités Bitmap annonçait `desktopResizeFlag = 0`, si bien qu'aucune des cinq cibles n'appliquait la disposition (aucune image à la nouvelle taille en 60 s). `MCSClientSettings.DesktopResize` le pose, avec `Resize` ;
  - une réactivation rendait la session « non finalisée », et un second redimensionnement arrivé pendant ce temps était refusé, ce qui fermait la session (Windows Server 2019). Les canaux appartiennent à la connexion MCS et non au partage : ils envoient dès qu'ils sont joints, réactivation comprise. Un test rouge d'abord l'a reproduit.
  - Windows ferme le contrôle d'affichage pendant une réactivation, puis le rouvre et redonne sa capacité (Server 2022, 32 bpp). Un redimensionnement arrivé entre les deux était refusé, et la capacité redonnée l'aurait été aussi. Désormais, `SendDynamicChannelMessage` dit `ErrRDPDynamicChannelClosed`, et le codec abandonne ce redimensionnement : le suivant passera. Chaque réouverture attend une nouvelle capacité.
- **Prouvé contre Windows**, les trois correctifs en place (CI de #155, cinq cibles, Server 2019 et 2022, 16 et 32 bpp, fr-FR, session console) : demande de 1 023 × 768, et une image clé de 1 022 × 768 en 0,5 à 0,9 s.


**Incrément 4, fait (12 novembre 2026) : l'Admin UI.**
- **Protocole** (`web/admin-ui/src/features/screen/protocol.ts`) : le bit 1 du `HELLO` (`resizable`), et `encodeResize`, une entrée de type 4 ramenée dans les mêmes bornes que le proxy (`clampResize`).
- **Visionneuse** : quand la session dit qu'elle redimensionne, la page lui demande la place qu'elle a pour l'écran : la largeur de sa zone, et la hauteur de la fenêtre, moins les boutons et la ligne d'état (112 px). Elle le demande une première fois au `HELLO`, puis chaque fois que la fenêtre a cessé de changer de taille depuis 500 ms, et seulement si la taille change. Le proxy rythme aussi, à un par seconde.
- **Prouvé** : 4 tests (le drapeau, l'encodage, l'envoi et son rythme, rien pour une session qui ne redimensionne pas) ; 7 mutations tuées ; les 117 tests de l'Admin UI passent, et sa construction aussi.
- **Reste** (incrément 5) : la vérification dans un vrai navigateur, contre une cible Windows. Le bac à sable n'en a pas : il n'a qu'une cible VNC, qui ne redimensionne pas. Puis la décision d'allumer `SCREEN_RESIZE` par défaut, qui revient au propriétaire.

**Incrément 5, en cours (12 novembre 2026) : la vérification dans un vrai navigateur, en CI.** Le propriétaire a choisi un navigateur sans interface dans la CI Windows, puisque le bac à sable n'a pas de cible Windows.
- `TestScreenFlow_RDPResizeInAHeadlessBrowser` (`test/integration`) démarre les huit services sur de vrais processus, avec `SCREEN_RESIZE` allumé et l'Admin UI servie par la Gateway, contre la cible Windows de la CI.
- Le Chrome du runner, sans interface, est piloté par le protocole DevTools (`cdp_test.go`, sur le client WebSocket que le module a déjà : aucune dépendance nouvelle). Il se connecte, ouvre l'écran par les boutons de la page, puis la fenêtre est redimensionnée deux fois. Le bureau distant doit suivre, à chaque fois, la taille que la page demande, et la session doit continuer. Les captures vont dans les artefacts (`browser-resize-*.png`).
- L'épreuve RDP de bout en bout prête sa mise en place (`startRDPScreenStack`) ; contre FreeRDP, elle passe toujours.
- **Trouvé par le navigateur, corrigé** :
  - la page demande sa taille une fois, à l'ouverture, avant que Windows ait dit sa capacité ; le codec ignorait cette demande, et la page ne redemande qu'au changement de taille, si bien que le bureau restait à 1 280 × 800. Le codec garde désormais la taille demandée et la demande dès que la capacité arrive, une seule fois pour une même taille ; une demande arrivée canal fermé attend la capacité suivante. 4 mutations tuées ;
  - la page mesurait la hauteur sous sa propre place dans la page : 480 pixels, le minimum, pour une fenêtre de 1 000. Elle prend la hauteur de la fenêtre, moins les boutons et la ligne d'état.

## Conséquences

- (+) Le socle des canaux existe, borné, et il est prouvé par un canal réel contre Windows avant qu'un canal à contenu ne s'y appuie.
- (+) L'opérateur voit le bureau à la taille de sa fenêtre, au lieu d'un 1 280 × 800 réduit à la largeur de la page (l'Admin UI ne l'agrandit jamais).
- (+) Éteint, rien ne change : la négociation d'aujourd'hui reste celle par défaut.
- (−) Une surface d'entrée de plus, venue de la cible : le cadrage des canaux et DRDYNVC. Bornée, fuzzée, mais nouvelle.
- (−) Chaque redimensionnement coûte une image clé, enregistrée. Un opérateur qui redimensionne sans cesse est borné à une par seconde.
- (−) VNC ne redimensionne pas encore (ExtendedDesktopSize) : l'Admin UI ne le proposera que si le `HELLO` le dit.
- (−) Ni presse-papiers ni fichiers : ce que les opérateurs demanderont ensuite reste fermé.

## Alternatives envisagées

- **A, le socle seul** : écartée. Un socle jamais éprouvé par un canal réel ne prouve rien.
- **C, le presse-papiers d'abord** : écartée pour ce pas. Il demande sa propre décision de contenu (politique, enregistrement, audit), sur un socle déjà éprouvé : c'est le pas suivant.
- **Redimensionner par reconnexion** (Deactivation-Reactivation avec une nouvelle taille) : écartée. Elle coupe l'écran à chaque changement, et Windows ne la propose qu'à son initiative.
- **Réduire l'image côté opérateur** : c'est ce qui se fait aujourd'hui (le bureau réduit à la largeur de la page, jamais agrandi), et cela reste le cas quand `SCREEN_RESIZE` est éteint. Le texte d'un bureau réduit devient difficile à lire.
