# ADR-0082 — rsync distant passe par le proxy SSH, sans shell arbitraire

- **Statut** : Proposé
- **Date** : 2026-11-08
- **Décideurs** : Mainteneurs OpenBastion
- **Périmètre** : SSH Proxy, Session Broker, Command Recorder, documentation d'administration et tests d'intégration

## Contexte

Le proxy SSH prend déjà en charge le shell interactif, le sous-système SFTP et l'ancien protocole SCP (scp -O). ADR-0038 impose l'enregistrement des opérations de transfert avant leur transmission. Le chemin actuel est volontairement strict : le proxy n'accepte qu'un sous-ensemble précis de requêtes SSH et refuse les autres commandes exec.

Le refus est explicite dans docs/administration/privileged-accounts.md (« rsync… refusée ») et couvert par TestParseSCPCommand_OnlyTheLegacySinkOrSource_NothingAShellCouldReadOtherwise dans services/proxy/ssh-proxy/internal/sshcodec/transfer_test.go, qui vérifie que rsync --server . n'est pas accepté.

Le mode distant de rsync s'appuie sur SSH exec : le client démarre un processus distant rsync --server (avec --sender pour un téléchargement depuis la cible), puis échange le protocole rsync binaire sur le canal standard. Ce flux n'est ni SFTP ni SCP. Il contient des métadonnées et des blocs différentiels dont l'interprétation varie selon les versions et les options rsync. Le relayer comme un shell ou le traiter comme un flux SCP serait incorrect et dangereux.

Le mode daemon rsync:// est un protocole distinct et n'est pas nécessaire au premier périmètre.

## Décision

1. **Ajouter un mode de session SSH dédié rsync**, sélectionné uniquement après validation d'une requête SSH exec correspondant au protocole distant rsync. Le mode est distinct de ModeShell, ModeSFTP et ModeSCP.
2. **N'accepter que le rôle serveur rsync** : la commande distante doit être une invocation rsync --server conforme à une grammaire documentée et testée. --sender détermine le sens distant :
   - avec --sender, la cible envoie les données vers le client (download/pull) ;
   - sans --sender, le client envoie les données vers la cible (upload/push).
3. **Analyser la commande sans interpréteur shell** :
   - parser la chaîne SSH exec avec un tokenizer dédié, borné et testé ; ne jamais exécuter sh -c, bash -c, eval ou une expansion shell côté proxy ;
   - valider --server, les options de protocole admises, le séparateur de chemin . et le chemin distant selon une politique explicite ;
   - reconstruire une commande canonique à partir des arguments validés, avec échappement POSIX correct, avant l'appel à ssh.Session.Start ;
   - refuser les options inconnues, les options qui changent le mode d'exécution, les commandes multiples, les métacaractères non interprétables sans ambiguïté, les chemins non conformes et les formes qui masquent le chemin dans le flux (--secluded-args / -s) dans le premier incrément.
4. **N'autoriser aucun shell générique** : toute commande autre que le sous-ensemble rsync explicitement admis reste refusée. Le mode daemon rsync://, les tunnels arbitraires, les options --rsync-path libres et les commandes distantes personnalisées restent hors périmètre.
5. **Enregistrer avant d'exécuter** : avant session.Start, le Command Recorder doit acquitter un événement contenant au minimum l'identité de session, le sens, la cible, le chemin distant validé, la version/les options rsync reconnues lorsqu'elles sont disponibles et le fait qu'il s'agit d'un transfert rsync. En cas de refus ou d'absence d'acquittement, le processus distant ne démarre pas et aucun octet de transfert n'est relayé.
6. **Enregistrer le résultat** : à la fin, écrire un événement de clôture indiquant le statut de sortie, la durée et les compteurs d'octets reçus/envoyés par le proxy. Le flux doit être relayé en streaming, avec limites de débit/temps et annulation immédiate sur révocation, expiration ou erreur fatale.
7. **Ne pas prétendre à une inspection fichier par fichier dans le premier incrément** :
   - les compteurs et empreintes éventuelles du flux sont des métriques du flux rsync encodé au niveau applicatif, jamais des tailles ou SHA-256 des fichiers ;
   - les noms, attributs, suppressions et résultats par fichier ne sont annoncés que si un décodeur rsync versionné les extrait et les fait acquitter avant les octets correspondants ;
   - aucune capture du contenu des fichiers n'est conservée par défaut.
8. **Préserver les invariants existants** :
   - secret cible obtenu uniquement dans le chemin de données du proxy, jamais dans le control plane (ADR-0003) ;
   - clé d'hôte cible vérifiée avant authentification (ADR-0039 et ADR-0048) ;
   - session admise, enregistrée ou refusée ; révocation et expiration coupent le flux (ADR-0008, ADR-0018) ;
   - événements de transfert échappés, bornés et associés à la session ; l'échec d'enregistrement avant démarrage bloque le transfert (ADR-0008, ADR-0025, ADR-0068) ;
   - aucun accès direct à la cible n'est ajouté au client : l'unique connexion cible reste celle établie par le SSH Proxy.
9. **Activer la fonctionnalité par défaut uniquement après validation de bout en bout** avec des versions rsync déclarées, clients OpenSSH réels et cible SSH réelle. Tant que les tests ne sont pas verts, rsync reste refusé et la documentation doit le dire.

## Contrat de première version

| Élément | Contrat |
|---|---|
| Transport | SSH session channel, requête exec |
| Commande distante | Sous-ensemble validé de rsync --server |
| Upload | --server sans --sender |
| Download | --server --sender |
| Données | Flux binaire bidirectionnel, streaming, sans shell interactif |
| Audit préalable | Sens, chemin distant validé, options reconnues, session et cible |
| Audit final | Statut de sortie, durée et octets par direction |
| Enregistrement | Obligatoire selon ADR-0008 ; refus avant démarrage si non acquitté |
| Non inclus | rsync://, daemon, --rsync-path libre, --secluded-args, inspection fichier par fichier et capture du contenu |

Les noms des événements d'audit et leurs champs exacts seront fixés dans les contrats du SSH Proxy/Command Recorder au moment de l'implémentation, sans introduire une nouvelle API publique si le mécanisme RecordEvent existant suffit.

## Conséquences

### Positives

- Les opérations rsync distantes passent par le même point de contrôle et d'audit que les autres sessions SSH.
- Les transferts volumineux et différentiels sont relayés en streaming, sans bufferiser les fichiers en mémoire.
- Le périmètre exec reste une allow-list fermée, sans ouverture d'un shell arbitraire.
- Les administrateurs ne reçoivent jamais le secret de la cible.

### Limites et coûts

- La première version ne fournit pas la même visibilité par fichier que SFTP/SCP : elle audite l'intention et le résultat global du transfert.
- Les options et syntaxes rsync évoluent ; la grammaire admise doit être versionnée, bornée et testée contre plusieurs versions supportées.
- Le support de chemins contenant espaces ou caractères spéciaux exige un tokenizer et un échappement testés ; aucune interprétation shell approximative n'est acceptable.
- La reprise après interruption dépend du comportement de rsync et des options autorisées ; elle doit être validée, pas supposée.
- Les compteurs de flux ne prouvent ni le nombre d'octets écrits sur disque ni l'intégrité finale des fichiers.
- Le protocole daemon rsync:// et les redirections de chemin personnalisées ne sont pas couverts.

## Plan de validation requis avant activation

1. Tests unitaires positifs : upload, download, chemins relatifs/absolus autorisés, options supportées, tokenizer et reconstruction canonique.
2. Tests négatifs : sh -c, --rsync-path, --secluded-args, options inconnues, injection par guillemets, substitutions, séparateurs, nouvelles lignes, chemins .., commandes multiples et arguments surdimensionnés.
3. Tests d'intégration avec deux versions rsync supportées au minimum et un serveur OpenSSH réel : fichier simple, arborescence, delta après modification, suppression si autorisée, compression, gros fichier, interruption et reprise.
4. Tests d'ordre : événement de démarrage acquitté avant session.Start ; aucun octet envoyé si l'acquittement échoue ; événement de fin écrit avec le code de sortie réel.
5. Tests de sécurité et de résilience : limites mémoire, débit, durée, backpressure, annulation, révocation, expiration, cible à clé d'hôte incorrecte, recorder indisponible, fuzzing du tokenizer et des options.
6. Mise à jour de docs/security/known-limitations.md, docs/administration/privileged-accounts.md, docs/roadmap.md et des exemples uniquement après les validations correspondantes.

## Alternatives envisagées

- **Autoriser toutes les commandes SSH exec** : rejeté, car cela transforme le proxy en shell distant et contourne la politique d'allow-list.
- **Lancer rsync dans un shell local au proxy** : rejeté, car cela déplace l'exécution et les privilèges hors de la cible et crée un second chemin d'accès.
- **Traiter le flux rsync comme SCP** : rejeté, car les formats de contrôle et de données sont différents.
- **Implémenter immédiatement un décodeur complet du protocole rsync** : différé ; sa complexité/versionnalité ne doit pas bloquer un premier transport contrôlé, mais l'absence de visibilité par fichier doit rester explicite.
- **Supporter rsync:// dès le départ** : rejeté pour ce périmètre ; il s'agit d'un protocole et d'une surface d'exposition distincts.

## Références

- [ADR-0003 — Les secrets ne traversent jamais le control plane](0003-les-secrets-ne-traversent-jamais-le-control-plane.md)
- [ADR-0008 — Enregistrer ou refuser](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md)
- [ADR-0018 — Terminaison effective d'une session](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md)
- [ADR-0025 — Forme et taille des événements d'audit](0025-l-audit-service-ne-prend-dans-la-trace-que-ce-qu-un-emetteur.md)
- [ADR-0038 — SFTP et SCP à travers le proxy](0038-sftp-et-scp-a-travers-le-proxy-chaque-transfert-est.md)
- [ADR-0039 — Clé d'hôte épinglée](0039-la-cle-d-hote-de-chaque-cible-est-epinglee-au-vault-et.md)
- [ADR-0048 — Autorité de certificats SSH](0048-une-cible-peut-etre-reconnue-par-une-autorite-de-certificats-ssh.md)
- [ADR-0068 — Détails d'audit bornés et protégés](0068-les-details-d-un-evenement-d-audit-sont-bornes-et-proteges-par-le-hash.md)
- [Limites connues](../security/known-limitations.md)
- [Documentation des comptes privilégiés](../administration/privileged-accounts.md)
