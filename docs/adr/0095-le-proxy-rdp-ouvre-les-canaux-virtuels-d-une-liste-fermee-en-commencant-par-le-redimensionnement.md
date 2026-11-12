# ADR-0095 — Le proxy RDP ouvre les canaux virtuels d'une liste fermée, en commençant par le redimensionnement

**Statut** `Proposé` · 12 novembre 2026 · demandé par le propriétaire du projet le 12 novembre 2026 : « go pour le lot D » (ADR-0090). `Accepté` seulement avec son go, cité avec sa date. La décision lève en partie ADR-0069 §6 : elle ouvre le socle des canaux, et un seul canal, qui ne transporte aucune donnée de l'opérateur vers la cible en dehors de la taille de son écran.

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

## Décision proposée : B

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
