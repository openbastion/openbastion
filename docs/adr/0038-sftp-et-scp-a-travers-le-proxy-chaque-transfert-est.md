# ADR-0038 — SFTP et SCP à travers le proxy : chaque transfert est enregistré, avant d'être transmis


**Contexte**
Le MVP prévoit un « SSH/SFTP/SCP Proxy » (`docs/roadmap.md` §2). Le proxy n'acceptait que le shell interactif et refusait `exec` et les sous-systèmes : sûr, mais sans transfert de fichiers. Depuis OpenSSH 9.0, `scp` passe par défaut par le sous-système SFTP ; l'ancien protocole SCP (`scp -O`) existe encore. Bony Kiss a choisi d'**enregistrer chaque transfert** — sens, chemin, taille, SHA-256 du contenu — sans en garder le contenu, et, pour les tests, la bibliothèque `github.com/pkg/sftp` v1.13.7 (la plus récente compatible avec `golang.org/x/crypto` v0.24 du dépôt), **dans les tests seulement**.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — enregistrer chaque transfert et `pkg/sftp` dans les tests seulement sont ses choix ; le reste est renversable)*
1. **Ce que le proxy accepte sur un canal de session** : un shell (comme avant), le sous-système `sftp`, ou une commande exactement `scp -t <chemin>` / `scp -f <chemin>` (avec les options `-r -p -d -v` de l'ancien protocole). Toute autre commande, tout autre sous-système : refusé, comme avant.
2. **Enregistrer ou refuser s'applique aux transferts** (ADR-0008) : chaque événement ci-dessous est écrit au Command Recorder et **acquitté avant** que le paquet qui le déclenche soit transmis à la cible ; non acquitté, le paquet n'est pas transmis et la session s'arrête, comme une commande.
3. **SFTP** — le proxy lit le protocole (version 3) dans les deux sens :
   - **avant** de transmettre une ouverture de fichier : `sftp open <chemin> for <reading|writing|reading and writing>` ;
   - **avant** de transmettre une modification : `sftp remove`, `rename`, `mkdir`, `rmdir`, `setstat`, `symlink`, `hardlink`, et toute requête étendue par son nom ;
   - **avant** de transmettre la fermeture d'un fichier ouvert : `sftp upload|download <chemin> (<n> bytes, sha256 <hex>)` — le SHA-256 des octets écrits ou lus, dans l'ordre des décalages ; si les écritures ou lectures ne sont pas contiguës depuis zéro, `sha256 not computed: non-sequential` ;
   - les lectures de métadonnées (`stat`, `readdir`, `realpath`…) ne sont pas enregistrées ;
   - un paquet de plus de 1 Mio, ou qui ne se lit pas, arrête la session.
4. **SCP (ancien protocole)** — **avant** d'exécuter : `scp upload to <chemin>` ou `scp download from <chemin>` ; **avant** de transmettre chaque en-tête de fichier : `scp upload|download <nom> into|from <chemin> (<n> bytes)` ; **avant** de transmettre l'octet qui clôt son contenu : la même ligne avec `sha256 <hex>`. Le nom est celui que le protocole porte et le chemin celui de la commande, écrits séparément : le proxy ne sait pas si le chemin est un fichier ou un répertoire.
5. **Les chemins sont écrits entre guillemets, échappés** (`strconv.Quote`) : un nom de fichier ne forge pas de ligne dans l'enregistrement.
6. **Le contenu n'est pas gardé** : l'enregistrement dit quoi, combien et l'empreinte ; une copie servirait de preuve complète, mais son volume n'est pas borné et elle contiendrait les secrets transférés.

**Conséquences**
- (+) **Mesuré** : avant (rouge, sur le commit qui précède ADR-0038, huit processus et les vrais clients OpenSSH 9.6), `sftp`, `scp` et `scp -O` échouaient. Après : `sftp` (envoi, réception, `mkdir`, `rename`), `scp` (par SFTP) et `scp -O` (envoi et réception) passent, le fichier arrive intact, et un auditeur relit chaque transfert avec sa taille et un SHA-256 **égal à celui du fichier** ; `ssh … id` reste refusé. L'ordre « enregistré, puis transmis » est vérifié paquet par paquet ; un enregistrement refusé arrête l'ouverture, la modification ou la fermeture ; un nom de fichier qui tente de forger une ligne reste une ligne ; treize commandes `scp` d'injection (`;`, `$( )`, deux chemins, `-o ProxyCommand`…) sont refusées. **17 mutations, 17 tuées** (dont une survivante — « pas de borne de taille » — que mon test ne voyait pas faute de corps de paquet, maintenant vue). Le proxy envoie le statut de sortie **puis ferme le canal**, comme un sshd : sans cela, un `scp -O` attendait cinq secondes de trop.
- (+) Un fichier ne passe plus à travers le bastion sans laisser son nom, sa taille et son empreinte dans l'enregistrement, avant de partir.
- (−) L'empreinte d'un transfert parallèle ou par blocs non contigus n'est pas calculée (la taille l'est).
- (−) Le contenu n'est pas gardé : l'empreinte prouve ce qui a été transféré à qui détient le fichier, elle ne le restitue pas.
- (−) Un téléchargement est enregistré à la fermeture du fichier, quand les octets sont déjà partis vers le client ; l'ouverture, elle, est enregistrée avant.
- (−) `pkg/sftp` (et ses dépendances de test) entre dans le module des tests d'intégration.

**Alternatives envisagées**
- **Garder le contenu** (chiffré) : écarté par le propriétaire.
- **Refuser les transferts** : écarté par le propriétaire.
- **Enregistrer chaque bloc écrit** : des milliers d'aller-retours par fichier, pour une information que l'empreinte finale porte déjà.
