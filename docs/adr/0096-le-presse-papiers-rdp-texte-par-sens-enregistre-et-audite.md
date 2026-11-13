# ADR-0096 — Le presse-papiers RDP passe du texte, dans chaque sens selon une politique, enregistré et audité

**Statut** `Proposé` · 13 novembre 2026 · deuxième point du lot D d'ADR-0090, après le socle des canaux (ADR-0095). `Accepté` seulement avec le go du propriétaire, cité avec sa date. La décision lève, pour le texte du presse-papiers seulement, ce qu'ADR-0069 §6 garde fermé, et étend ce qu'ADR-0070 enregistre.

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

## Décision proposée : A

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

## Conséquences

- (+) Le besoin le plus demandé des opérateurs, sans trou dans la trace : chaque transfert est enregistré, chiffré, audité et refusable par politique, dans chaque sens séparément.
- (+) L'auditeur voit ce qui est entré et sorti, à l'heure près, à côté de l'écran.
- (+) Éteint ou sans droit, rien ne change : la négociation d'aujourd'hui.
- (−) Une voie de sortie de données existe, même bornée et enregistrée : c'est le prix d'un presse-papiers. La politique `from-target` est ce qui la ferme.
- (−) Le texte du presse-papiers est dans l'enregistrement : un mot de passe collé par l'opérateur y sera, chiffré. C'est voulu (enregistrer ou refuser), et c'est à dire aux opérateurs.
- (−) Une surface d'entrée de plus, venue de la cible : les PDU de MS-RDPECLIP. Bornée, fuzzée, mais nouvelle.
- (−) VNC a son propre presse-papiers (ClientCutText, ServerCutText), en Latin-1 : hors de cette décision.
- (−) Coller demande un geste et une permission du navigateur : pas de Ctrl+V direct vers la cible.

## Alternatives envisagées

- **B, coller seulement** : gardée comme premier pas possible de A, pas comme décision à part. Les deux sens ont la même mécanique ; c'est la politique qui choisit.
- **C, auditer sans enregistrer** : écartée. Elle affaiblit « enregistrer ou refuser » sur la voie même où une donnée sort.
- **Laisser le navigateur synchroniser le presse-papiers en continu** : écartée. Ce serait lire le presse-papiers de l'opérateur sans geste de sa part, et transférer ce qu'il n'a pas choisi d'envoyer.
