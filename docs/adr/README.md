# Architecture Decision Records

Les décisions structurantes d'OpenBastion, une par fichier. Un ADR `Accepté` ne se réécrit pas : il se remplace par un nouvel ADR (« Remplacé par ADR-NNNN »).

## Format retenu

Chaque ADR suit un gabarit léger (inspiré de Michael Nygard / MADR) : **Contexte, Décision, Conséquences, Alternatives envisagées**. Statuts possibles : `Proposé`, `Accepté`, `Déprécié`, `Remplacé par ADR-NNNN`. Chaque ADR est un fichier `NNNN-titre-kebab-case.md` de ce dossier ; un nouvel ADR part de [`template.md`](template.md), prend le numéro suivant et ajoute sa ligne aux **deux** index ci-dessous : dans sa catégorie, à sa place dans l'ordre de mise en œuvre, et à la fin de l'index numérique.

## Index par catégorie

Les ADR sont regroupés par domaine. Dans chaque domaine, ils sont rangés dans l'**ordre logique de mise en œuvre** : un ADR suppose ceux qui le précèdent dans sa catégorie. Les numéros ne changent pas, puisqu'ils sont cités partout ; seul l'ordre de lecture est donné ici. L'index numérique, plus bas, reste la référence pour retrouver un numéro.

| # | Catégorie | ADR |
|---|---|---|
| 1 | [Fondations du code](#1-fondations-du-code) | 6 |
| 2 | [Communication entre services](#2-communication-entre-services) | 3 |
| 3 | [Invariants de sécurité transverses](#3-invariants-de-sécurité-transverses) | 4 |
| 4 | [Identité et authentification](#4-identité-et-authentification) | 10 |
| 5 | [Coffre, secrets et confiance dans les cibles](#5-coffre-secrets-et-confiance-dans-les-cibles) | 13 |
| 6 | [Sessions : cycle de vie et contrôle](#6-sessions--cycle-de-vie-et-contrôle) | 8 |
| 7 | [Break-glass](#7-break-glass) | 4 |
| 8 | [Proxy SSH](#8-proxy-ssh) | 5 |
| 9 | [Proxy écran RDP et VNC](#9-proxy-écran-rdp-et-vnc) | 13 |
| 10 | [Chaîne d'audit](#10-chaîne-daudit) | 9 |
| 11 | [Lectures auditées](#11-lectures-auditées) | 5 |
| 12 | [Enregistrement et relecture](#12-enregistrement-et-relecture) | 4 |
| 13 | [Interfaces et notifications](#13-interfaces-et-notifications) | 5 |
| 14 | [Déploiement, CI et chaîne d'approvisionnement](#14-déploiement-ci-et-chaîne-dapprovisionnement) | 8 |

### 1. Fondations du code

Langage, organisation du dépôt, accès aux données, schéma, binaires et versions.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0004](0004-go-comme-langage-unique-des-microservices-backend.md) | Go comme langage unique des microservices backend | Accepté |
| 2 | [ADR-0002](0002-organisation-en-monorepo-multi-module-go.md) | Organisation en monorepo multi-module Go | Accepté |
| 3 | [ADR-0029](0029-l-acces-aux-donnees-reste-en-database-sql-et-sql-ecrit-a-la.md) | L'accès aux données reste en `database/sql` et SQL écrit à la main ; pas d'ORM | Accepté |
| 4 | [ADR-0030](0030-des-migrations-de-schema-versionnees-appliquees-une-fois.md) | Des migrations de schéma versionnées, appliquées une fois, sous verrou, et dont le texte appliqué ne change plus | Accepté |
| 5 | [ADR-0072](0072-la-cli-cobra-et-une-version-homogene-pour-chaque-binaire.md) | Les exécutables OpenBastion adoptent Cobra et exposent une version de build homogène | Accepté |
| 6 | [ADR-0063](0063-le-projet-suit-semantic-versioning-version-dans-un-fichier-estampillee-a-la-construction.md) | Le projet suit Semantic Versioning : un fichier `VERSION`, estampillé dans chaque binaire, vérifié par la CI, et un tag `vX.Y.Z` pour chaque release | Accepté |

### 2. Communication entre services

Comment les services se parlent et s'identifient.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0001](0001-double-bus-nats-temps-reel-kafka-streaming-durable.md) | Double bus NATS (temps réel) + Kafka (streaming durable) | Accepté |
| 2 | [ADR-0010](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md) | mTLS interne : l'identité de l'appelant vient du certificat, et chaque route a sa liste d'appelants | Accepté |
| 3 | [ADR-0050](0050-le-transport-interne-reste-http-json-sous-mtls.md) | Le transport entre services reste HTTP/JSON sous mTLS, avec les noms des messages de `proto/`, et un test empêche les deux de diverger | Accepté |

### 3. Invariants de sécurité transverses

Les règles que tout le reste respecte : secrets, enregistrement, refus.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0003](0003-les-secrets-ne-traversent-jamais-le-control-plane.md) | Les secrets ne traversent jamais le control plane | Accepté |
| 2 | [ADR-0008](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md) | Enregistrer ou refuser : une session qui ne peut pas être enregistrée n'a pas lieu | Accepté |
| 3 | [ADR-0042](0042-un-refus-dit-son-motif-a-l-operateur-par-un-code-stable-et.md) | Un refus dit son motif à l'opérateur par un code stable, et une panne ne dit jamais sa cause | Accepté |
| 4 | [ADR-0043](0043-aucune-route-publique-ne-rend-le-texte-d-une-erreur-interne.md) | Aucune route publique ne rend le texte d'une erreur interne ; une session ne se crée que sur un compte qui existe et dont la clé est épinglée | Accepté |

### 4. Identité et authentification

Qui se connecte, par quel fournisseur, avec quel second facteur ; l'audit des connexions.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0007](0007-keycloak-comme-idp-de-plateforme-federation-externe-en.md) | Keycloak comme IdP de plateforme, fédération externe en complément | Accepté |
| 2 | [ADR-0035](0035-le-connecteur-oidc-un-code-d-autorisation-avec-pkce-un-jeton.md) | Le connecteur OIDC : un code d'autorisation avec PKCE, un jeton d'identité vérifié champ par champ, des rôles tirés d'une table de groupes déclarée | Accepté |
| 3 | [ADR-0076](0076-plusieurs-fournisseurs-d-identite-chaque-compte-lie-au-sien.md) | Plusieurs fournisseurs d'identité à la fois, chaque compte lié au sien | Accepté |
| 4 | [ADR-0078](0078-chaque-fournisseur-oidc-garde-son-emetteur-un-changement-se-declare.md) | Chaque fournisseur OIDC garde son émetteur ; un changement se déclare | Accepté |
| 5 | [ADR-0079](0079-entra-id-est-un-profil-oidc-lie-a-un-tenant-declare.md) | Entra ID est un profil OIDC lié à un tenant déclaré | Accepté |
| 6 | [ADR-0061](0061-connexion-par-annuaire-ldap-et-active-directory.md) | Un utilisateur d'annuaire (LDAP ou Active Directory) se connecte avec son mot de passe d'annuaire ; seuls ses groupes déclarés lui donnent des rôles | Accepté |
| 7 | [ADR-0062](0062-un-second-facteur-totp-exige-par-role-enrole-par-un-code-d-administrateur.md) | Un second facteur TOTP est exigé pour les rôles déclarés ; on l'enrôle avec un code à usage unique qu'un administrateur a émis | Accepté |
| 8 | [ADR-0065](0065-webauthn-second-facteur-qui-resiste-a-l-hameconnage-exige-pour-les-roles-stricts.md) | WebAuthn est un second facteur à côté de TOTP ; pour les rôles déclarés stricts, il est le seul qui compte, parce qu'il résiste à l'hameçonnage | Accepté |
| 9 | [ADR-0066](0066-une-cle-de-secours-s-ajoute-avec-la-cle-actuelle-et-un-code-d-administrateur.md) | Une clé de secours s'ajoute avec la signature de la clé actuelle et un code d'administrateur ; un administrateur révoque une seule clé | Accepté |
| 10 | [ADR-0064](0064-les-connexions-et-les-gestes-d-administration-du-second-facteur-sont-ecrits-a-l-audit.md) | Les connexions et les gestes d'administration du second facteur sont écrits à l'audit ; un jeton n'est émis qu'une fois sa connexion écrite | Accepté |

### 5. Coffre, secrets et confiance dans les cibles

Où vivent les secrets, comment la cible est reconnue, comment les secrets tournent et sont scellés.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0005](0005-separation-password-vault-secrets-manager.md) | Séparation Password Vault / Secrets Manager | Accepté |
| 2 | [ADR-0039](0039-la-cle-d-hote-de-chaque-cible-est-epinglee-au-vault-et.md) | La clé d'hôte de chaque cible est épinglée au Vault, et livrée au proxy avec le secret | Accepté |
| 3 | [ADR-0048](0048-une-cible-peut-etre-reconnue-par-une-autorite-de-certificats-ssh.md) | Une cible peut être reconnue par une autorité de certificats SSH épinglée au compte, à la place de sa clé | Accepté |
| 4 | [ADR-0054](0054-une-cle-d-hote-certifiee-peut-etre-revoquee.md) | Une clé d'hôte certifiée peut être révoquée au compte, comme dans `known_hosts`, et ne reçoit plus rien même avec un certificat valable | Accepté |
| 5 | [ADR-0037](0037-la-rotation-d-un-secret-atteint-la-cible-un-compte-de.md) | La rotation d'un secret atteint la cible : un compte de réconciliation, une version en attente, une vérification avant de la rendre courante | Accepté |
| 6 | [ADR-0040](0040-les-rotations-planifiees-sont-executees-un-intervalle-par.md) | Les rotations planifiées sont exécutées : un intervalle par compte, un balayage du Vault, une prise par compare-échange | Accepté |
| 7 | [ADR-0041](0041-une-rotation-planifiee-qui-echoue-se-voit-echecs-comptes.md) | Une rotation planifiée qui échoue se voit : échecs comptés, alerte à l'audit ; et elle peut être tenue dans une fenêtre horaire | Accepté |
| 8 | [ADR-0044](0044-une-rotation-apres-usage-est-une-dette-enregistree-reglee.md) | Une rotation après usage est une dette enregistrée, réglée jusqu'au bout : le Broker la remet, le Vault la paie | Accepté |
| 9 | [ADR-0049](0049-les-cles-de-chiffrement-gardees-par-transit.md) | Les clés de chiffrement du Vault et du Command Recorder sont gardées par le moteur Transit d'OpenBao, et les anciennes lignes restent lisibles | Accepté |
| 10 | [ADR-0053](0053-le-jeton-transit-se-renouvelle-de-lui-meme.md) | Le jeton Transit se renouvelle de lui-même, à mi-vie, et le dit quand il ne le peut pas | Accepté |
| 11 | [ADR-0056](0056-un-jeton-transit-remplace-sur-disque-est-pris-sans-redemarrer.md) | Un jeton Transit remplacé sur disque est pris sans redémarrer, après avoir été vérifié auprès de Transit | Accepté |
| 12 | [ADR-0058](0058-le-vault-et-le-recorder-se-connectent-a-transit-par-approle.md) | Le Vault et le Recorder peuvent se connecter à Transit par AppRole, et reprennent un jeton neuf quand le leur atteint sa fin | Accepté |
| 13 | [ADR-0055](0055-ce-que-la-cle-locale-protege-encore-est-rescelle-sous-transit.md) | Ce que la clé locale protège encore est rescellé sous la clé courante, en tâche de fond, jusqu'à ce que la clé locale puisse partir | Accepté |

### 6. Sessions : cycle de vie et contrôle

Créer, approuver, borner, lire, terminer une session ; limiter les demandes.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0067](0067-une-session-vers-un-compte-qui-l-exige-attend-l-approbation-d-une-autre-personne-avec-un-ticket.md) | Une session vers un compte qui l'exige attend l'approbation d'une autre personne, et porte un ticket au format déclaré | Accepté |
| 2 | [ADR-0014](0014-une-limitation-de-debit-par-identite-sur-les-demandes-de.md) | Une limitation de débit par identité sur les demandes de session, au Gateway — et un limiteur dont les unités et la mémoire sont justes | Accepté |
| 3 | [ADR-0015](0015-qui-est-le-client-derriere-l-arete-une-confiance-a-x.md) | Qui est « le client » derrière l'arête : une confiance à `X-Forwarded-For` limitée aux proxys déclarés, et des limites par adresse réglables | Accepté |
| 4 | [ADR-0016](0016-un-budget-par-identite-sur-les-actions-de-session-qui.md) | Un budget par identité sur les actions de session qui écrivent à chaque appel (`approve`, `reject`, `connect`) — et pas sur ce qui n'écrit qu'une fois ou rien | Accepté |
| 5 | [ADR-0017](0017-mettre-fin-a-une-session-son-demandeur-ou-une-autorite.md) | Mettre fin à une session : son demandeur ou une autorité déclarée, et au nom de celui qui le demande | Accepté |
| 6 | [ADR-0018](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md) | Rendre la terminaison réelle côté proxy : le Broker fait couper les connexions et jeter les tickets avant de marquer la session terminée | Accepté |
| 7 | [ADR-0034](0034-une-session-ou-une-demande-arrivee-a-echeance-est-marquee.md) | Une session ou une demande arrivée à échéance est marquée expirée, une fois, et l'expiration est écrite dans la trace | Accepté |
| 8 | [ADR-0019](0019-qui-peut-lire-une-session-son-demandeur-celui-qui-l-a.md) | Qui peut lire une session : son demandeur, celui qui l'a décidée, ou le titulaire d'une politique `session-read` — et une lecture n'écrit rien | Accepté (règle 6 amendée par ADR-0020) |

### 7. Break-glass

La dérogation d'urgence à « enregistrer ou refuser », bornée et validée.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0009](0009-break-glass-une-derogation-d-urgence-bornee-et-auditee-a.md) | Break-glass : une dérogation d'urgence, bornée et auditée, à « enregistrer ou refuser » | Accepté |
| 2 | [ADR-0011](0011-break-glass-double-validation-une-demande-en-attente.md) | Break-glass : double validation — une demande en attente, approuvée par une autre personne | Accepté |
| 3 | [ADR-0012](0012-break-glass-l-approbateur-decouvre-les-demandes-en-attente.md) | Break-glass : l'approbateur découvre les demandes en attente (liste filtrée par son droit) et en est prévenu (webhook, au mieux) | Accepté |
| 4 | [ADR-0013](0013-break-glass-un-plafond-de-demandes-en-attente-par-demandeur.md) | Break-glass : un plafond de demandes en attente par demandeur (atomique) et un message de notification signé (HMAC) | Accepté |

### 8. Proxy SSH

Le pipeline proxy partagé, les transferts, la mise à l'échelle et la bibliothèque SSH.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0006](0006-pipeline-proxy-partage-factorise-en-bibliotheque-interne.md) | Pipeline proxy partagé factorisé en bibliothèque interne | Accepté |
| 2 | [ADR-0038](0038-sftp-et-scp-a-travers-le-proxy-chaque-transfert-est.md) | SFTP et SCP à travers le proxy : chaque transfert est enregistré, avant d'être transmis | Accepté |
| 3 | [ADR-0046](0046-plusieurs-instances-du-proxy-ssh-le-broker-les-connait-toutes.md) | Plusieurs instances du proxy SSH : le Broker les connaît toutes, émet un ticket chez l'une, et fait révoquer chez toutes | Accepté |
| 4 | [ADR-0083](0083-bibliotheque-ssh-openbastion-avec-politiques-capture-et-audit.md) | La bibliothèque SSH OpenBastion intègre politiques, capture et audit au cycle protocolaire | Proposé |
| 5 | [ADR-0082](0082-rsync-distant-passe-par-le-proxy-ssh-sans-shell-arbitraire.md) | rsync distant passe par le proxy SSH, sans shell arbitraire | Proposé |

### 9. Proxy écran RDP et VNC

Terminer la cible graphique, servir un flux acquitté, ouvrir RDP, puis l'étendre.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0069](0069-le-proxy-rdp-verifie-la-cible-et-refuse-les-sessions-non-enregistrees.md) | Le proxy RDP vérifie la cible et refuse les sessions non enregistrées | Accepté |
| 2 | [ADR-0071](0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md) | Le proxy RDP/VNC termine la cible en Go pur et sert un flux écran acquitté | Accepté, mise en œuvre en cours |
| 3 | [ADR-0086](0086-le-client-rdp-decode-15-et-16-bpp-pour-les-cibles-windows-par-defaut.md) | Le client RDP décode 15 et 16 bpp, pour les cibles Windows laissées par défaut | Accepté, mise en œuvre en cours |
| 4 | [ADR-0088](0088-rdp-ouvert-aux-operateurs-par-la-route-ecran-derriere-un-interrupteur.md) | RDP est ouvert aux opérateurs par la route écran de VNC, derrière un interrupteur éteint par défaut | Accepté, mise en œuvre en cours |
| 5 | [ADR-0089](0089-le-texte-rdp-reste-rendu-par-bitmaps-sans-cache-de-glyphes.md) | Le texte RDP reste rendu par bitmaps : le cache de glyphes n'est pas implémenté tant qu'une mesure ne le demande pas | Accepté |
| 6 | [ADR-0091](0091-le-pointeur-est-dessine-dans-l-image-enregistree.md) | Le pointeur est dessiné dans l'image, celle que l'opérateur voit et que l'auditeur rejoue | Accepté |
| 7 | [ADR-0081](0081-veille-rdp-externe-et-integration-selective.md) | Veille RDP externe et intégration sélective des enseignements | Proposé |
| 8 | [ADR-0084](0084-bibliotheque-rdp-openbastion-moteur-protocolaire-instrumente.md) | La bibliothèque RDP OpenBastion sépare le moteur protocolaire des contrôles PAM | Proposé |
| 9 | [ADR-0085](0085-bibliotheque-vnc-openbastion-moteur-rfb-instrumente.md) | La bibliothèque VNC OpenBastion sépare RFB des contrôles PAM et de l'enregistrement | Proposé |
| 10 | [ADR-0087](0087-contrats-transverses-des-bibliotheques-protocolaires-ssh-rdp-vnc.md) | Les bibliothèques SSH, RDP et VNC partagent des contrats PAM sans partager leurs moteurs protocolaires | Proposé |
| 11 | [ADR-0090](0090-rdp-v002-glyphes-ordres-canaux-et-protocoles.md) | RDP en v0.0.2 : glyphes, ordres graphiques, canaux virtuels et protocoles, par incréments prouvés | Proposé |
| 12 | [ADR-0095](0095-le-proxy-rdp-ouvre-les-canaux-virtuels-d-une-liste-fermee-en-commencant-par-le-redimensionnement.md) | Le proxy RDP ouvre les canaux virtuels d'une liste fermée, en commençant par le redimensionnement | Accepté |
| 13 | [ADR-0096](0096-le-presse-papiers-rdp-texte-par-sens-enregistre-et-audite.md) | Le presse-papiers RDP passe du texte, dans chaque sens selon une politique, enregistré et audité | Accepté |

### 10. Chaîne d'audit

La trace : ce qu'elle accepte, comment elle est chaînée, ancrée, archivée, et ses alertes.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0025](0025-l-audit-service-ne-prend-dans-la-trace-que-ce-qu-un-emetteur.md) | L'Audit Service ne prend dans la trace que ce qu'un émetteur peut vouloir dire (forme et taille de chaque champ, corps borné) | Accepté |
| 2 | [ADR-0068](0068-les-details-d-un-evenement-d-audit-sont-bornes-et-proteges-par-le-hash.md) | Les détails d'un événement d'audit sont bornés et protégés par le hash | Accepté |
| 3 | [ADR-0026](0026-le-hash-d-un-evenement-d-audit-couvre-chaque-champ-comme-un.md) | Le hash d'un événement d'audit couvre chaque champ comme un champ : un format versionné, et l'ancien seulement pour vérifier | Accepté |
| 4 | [ADR-0027](0027-la-chaine-d-audit-est-a-cle-hmac-et-chaque-evenement-dit.md) | La chaîne d'audit est à clé (HMAC), et chaque événement dit quel service l'a écrit | Accepté |
| 5 | [ADR-0028](0028-la-tete-de-la-chaine-d-audit-est-ancree-hors-de-la-base-et.md) | La tête de la chaîne d'audit est ancrée hors de la base, et la chaîne se vérifie contre ses ancres | Accepté |
| 6 | [ADR-0031](0031-audit-events-n-est-pas-partitionne-tant-qu-une-retention-ne.md) | `audit_events` n'est pas partitionné tant qu'une rétention ne garde pas la chaîne vérifiable | Accepté |
| 7 | [ADR-0032](0032-archiver-la-chaine-d-audit-hors-de-la-base-sans-la-rendre.md) | Archiver la chaîne d'audit hors de la base sans la rendre invérifiable : un point de contrôle ancré | Accepté |
| 8 | [ADR-0045](0045-une-alerte-ecrite-a-l-audit-est-poussee-par-un-webhook-signe.md) | Une alerte écrite à l'audit est poussée par un webhook signé, et seulement si celui qui l'écrit a le droit de la dire | Accepté |
| 9 | [ADR-0057](0057-les-alertes-en-attente-survivent-a-un-redemarrage.md) | Avec une base, les alertes en attente d'un renvoi survivent à un redémarrage de l'Audit Service | Accepté |

### 11. Lectures auditées

Toute lecture servie (session, enregistrement, demandes) est écrite avant d'être servie ; les refus sont budgétés.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0020](0020-auditer-les-refus-de-lecture-d-une-session-au-nom-de-celui.md) | Auditer les refus de lecture d'une session, au nom de celui qui lit, dans la limite d'un budget par identité | Accepté (règle 2 amendée par ADR-0021) |
| 2 | [ADR-0021](0021-une-lecture-servie-a-un-titulaire-de-politique-s-enregistre.md) | Une lecture servie à un titulaire de politique s'enregistre avant d'être servie — et sans enregistrement, elle n'est pas servie | Accepté |
| 3 | [ADR-0022](0022-chaque-page-d-un-enregistrement-servie-s-enregistre-avant-d.md) | Chaque page d'un enregistrement du Command Recorder servie s'enregistre avant d'être servie, au nom de celui que le Gateway a vérifié — et sans enregistrement, elle n'est pas servie | Accepté (règle 6 amendée par ADR-0024) |
| 4 | [ADR-0023](0023-chaque-demande-servie-par-la-liste-des-demandes-en-attente-s.md) | Chaque demande servie par la liste des demandes en attente s'enregistre avant d'être servie — et sans enregistrement, la liste n'est pas servie | Accepté |
| 5 | [ADR-0024](0024-auditer-les-refus-de-lecture-d-un-enregistrement-dans-un.md) | Auditer les refus de lecture d'un enregistrement, dans un budget par identité — et un seul seau à jetons, partagé (`pkg/refusalbudget`) | Accepté |

### 12. Enregistrement et relecture

Le stockage des sessions enregistrées, leur relecture et leur recherche.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0070](0070-le-video-recorder-acquitte-des-segments-chiffres-avant-de-les-servir.md) | Le Video Recorder acquitte des segments chiffrés avant de les servir | Accepté |
| 2 | [ADR-0092](0092-l-ecran-s-enregistre-en-images-partielles-ancrees-sur-des-images-cles.md) | L'écran s'enregistre en images partielles, ancrées sur des images clés | Accepté |
| 3 | [ADR-0093](0093-une-relecture-lit-plusieurs-segments-par-requete.md) | Une relecture lit plusieurs segments par requête | Accepté |
| 4 | [ADR-0080](0080-la-recherche-plein-texte-dechiffre-a-la-volee-dans-une-fenetre-bornee.md) | La recherche plein texte déchiffre à la volée, dans une fenêtre bornée, sans index en clair | Accepté, mise en œuvre en cours |

### 13. Interfaces et notifications

Admin UI, portail utilisateur, système de conception, notifications vers les messageries.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0036](0036-l-admin-ui-react-vite-et-typescript-servie-par-la-gateway.md) | L'Admin UI : React, Vite et TypeScript, servie par la Gateway sous `/ui/`, de même origine que l'API, sous une CSP stricte | Accepté |
| 2 | [ADR-0073](0073-l-admin-ui-adopte-un-systeme-de-conception-et-une-experience-operateur-progressive.md) | L'Admin UI adopte un système de conception cohérent et une expérience opérateur progressive | Accepté, mise en œuvre en cours |
| 3 | [ADR-0075](0075-architecture-du-user-portal-et-socle-frontend-partage.md) | Architecture du User Portal et socle frontend partagé | Proposé |
| 5 | [ADR-0074](0074-slack-et-teams-recoivent-les-notifications-dans-leur-format-sans-nouveau-service.md) | Slack et Teams reçoivent les notifications dans leur format, sans nouveau service | Accepté |

### 14. Déploiement, CI et chaîne d'approvisionnement

Installer, vérifier à chaque commit, épingler, analyser et mettre à jour les dépendances.

| Ordre | ID | Titre | Statut |
|---|---|---|---|
| 1 | [ADR-0033](0033-un-deploiement-docker-compose-reproductible-sous-mtls-une.md) | Un déploiement `docker-compose` reproductible, sous mTLS, une base par service, et le premier outil du CLI | Accepté |
| 2 | [ADR-0047](0047-une-ci-github-actions-qui-rejoue-la-verification-complete.md) | Une CI GitHub Actions qui rejoue la vérification complète, sur des actions et une image épinglées par empreinte | Accepté |
| 3 | [ADR-0077](0077-modulariser-les-workflows-github-actions-derriere-une-porte-de-validation-stable.md) | Modulariser les workflows GitHub Actions derrière une porte de validation stable | Accepté |
| 4 | [ADR-0051](0051-les-images-tirees-sont-epinglees-par-empreinte.md) | Toute image tirée d'un registre est épinglée par son empreinte, et un test refuse celle qui ne l'est pas | Accepté |
| 5 | [ADR-0052](0052-les-vulnerabilites-connues-se-cherchent-a-chaque-commit-et-chaque-semaine.md) | Les vulnérabilités connues se cherchent à chaque commit et chaque semaine, sur les modules sous leur vrai nom | Accepté |
| 6 | [ADR-0059](0059-dependabot-propose-une-dependance-a-la-fois-la-ci-decide.md) | Dependabot propose les mises à jour, une dépendance à la fois et après sept jours ; la CI décide | Accepté |
| 7 | [ADR-0060](0060-les-images-sont-analysees-par-trivy-verifie-contre-son-empreinte.md) | Les images sont analysées par Trivy, un binaire vérifié contre son empreinte, jamais par ses actions ; ce qui est accepté l'est par écrit, par chemin et jusqu'à une date | Accepté |
| 8 | [ADR-0094](0094-provenance-sbom-signature-et-verification-des-artefacts.md) | La chaîne de livraison atteste la provenance et le SBOM, signe les artefacts publiés et impose leur vérification au déploiement | Accepté |

## Index numérique

Dans l'ordre des numéros, c'est-à-dire l'ordre où les décisions ont été prises.

| ID | Titre | Statut | Catégorie |
|---|---|---|---|
| [ADR-0001](0001-double-bus-nats-temps-reel-kafka-streaming-durable.md) | Double bus NATS (temps réel) + Kafka (streaming durable) | Accepté | Communication entre services |
| [ADR-0002](0002-organisation-en-monorepo-multi-module-go.md) | Organisation en monorepo multi-module Go | Accepté | Fondations du code |
| [ADR-0003](0003-les-secrets-ne-traversent-jamais-le-control-plane.md) | Les secrets ne traversent jamais le control plane | Accepté | Invariants de sécurité transverses |
| [ADR-0004](0004-go-comme-langage-unique-des-microservices-backend.md) | Go comme langage unique des microservices backend | Accepté | Fondations du code |
| [ADR-0005](0005-separation-password-vault-secrets-manager.md) | Séparation Password Vault / Secrets Manager | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0006](0006-pipeline-proxy-partage-factorise-en-bibliotheque-interne.md) | Pipeline proxy partagé factorisé en bibliothèque interne | Accepté | Proxy SSH |
| [ADR-0007](0007-keycloak-comme-idp-de-plateforme-federation-externe-en.md) | Keycloak comme IdP de plateforme, fédération externe en complément | Accepté | Identité et authentification |
| [ADR-0008](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md) | Enregistrer ou refuser : une session qui ne peut pas être enregistrée n'a pas lieu | Accepté | Invariants de sécurité transverses |
| [ADR-0009](0009-break-glass-une-derogation-d-urgence-bornee-et-auditee-a.md) | Break-glass : une dérogation d'urgence, bornée et auditée, à « enregistrer ou refuser » | Accepté | Break-glass |
| [ADR-0010](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md) | mTLS interne : l'identité de l'appelant vient du certificat, et chaque route a sa liste d'appelants | Accepté | Communication entre services |
| [ADR-0011](0011-break-glass-double-validation-une-demande-en-attente.md) | Break-glass : double validation — une demande en attente, approuvée par une autre personne | Accepté | Break-glass |
| [ADR-0012](0012-break-glass-l-approbateur-decouvre-les-demandes-en-attente.md) | Break-glass : l'approbateur découvre les demandes en attente (liste filtrée par son droit) et en est prévenu (webhook, au mieux) | Accepté | Break-glass |
| [ADR-0013](0013-break-glass-un-plafond-de-demandes-en-attente-par-demandeur.md) | Break-glass : un plafond de demandes en attente par demandeur (atomique) et un message de notification signé (HMAC) | Accepté | Break-glass |
| [ADR-0014](0014-une-limitation-de-debit-par-identite-sur-les-demandes-de.md) | Une limitation de débit par identité sur les demandes de session, au Gateway — et un limiteur dont les unités et la mémoire sont justes | Accepté | Sessions : cycle de vie et contrôle |
| [ADR-0015](0015-qui-est-le-client-derriere-l-arete-une-confiance-a-x.md) | Qui est « le client » derrière l'arête : une confiance à `X-Forwarded-For` limitée aux proxys déclarés, et des limites par adresse réglables | Accepté | Sessions : cycle de vie et contrôle |
| [ADR-0016](0016-un-budget-par-identite-sur-les-actions-de-session-qui.md) | Un budget par identité sur les actions de session qui écrivent à chaque appel (`approve`, `reject`, `connect`) — et pas sur ce qui n'écrit qu'une fois ou rien | Accepté | Sessions : cycle de vie et contrôle |
| [ADR-0017](0017-mettre-fin-a-une-session-son-demandeur-ou-une-autorite.md) | Mettre fin à une session : son demandeur ou une autorité déclarée, et au nom de celui qui le demande | Accepté | Sessions : cycle de vie et contrôle |
| [ADR-0018](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md) | Rendre la terminaison réelle côté proxy : le Broker fait couper les connexions et jeter les tickets avant de marquer la session terminée | Accepté | Sessions : cycle de vie et contrôle |
| [ADR-0019](0019-qui-peut-lire-une-session-son-demandeur-celui-qui-l-a.md) | Qui peut lire une session : son demandeur, celui qui l'a décidée, ou le titulaire d'une politique `session-read` — et une lecture n'écrit rien | Accepté (règle 6 amendée par ADR-0020) | Sessions : cycle de vie et contrôle |
| [ADR-0020](0020-auditer-les-refus-de-lecture-d-une-session-au-nom-de-celui.md) | Auditer les refus de lecture d'une session, au nom de celui qui lit, dans la limite d'un budget par identité | Accepté (règle 2 amendée par ADR-0021) | Lectures auditées |
| [ADR-0021](0021-une-lecture-servie-a-un-titulaire-de-politique-s-enregistre.md) | Une lecture servie à un titulaire de politique s'enregistre avant d'être servie — et sans enregistrement, elle n'est pas servie | Accepté | Lectures auditées |
| [ADR-0022](0022-chaque-page-d-un-enregistrement-servie-s-enregistre-avant-d.md) | Chaque page d'un enregistrement du Command Recorder servie s'enregistre avant d'être servie, au nom de celui que le Gateway a vérifié — et sans enregistrement, elle n'est pas servie | Accepté (règle 6 amendée par ADR-0024) | Lectures auditées |
| [ADR-0023](0023-chaque-demande-servie-par-la-liste-des-demandes-en-attente-s.md) | Chaque demande servie par la liste des demandes en attente s'enregistre avant d'être servie — et sans enregistrement, la liste n'est pas servie | Accepté | Lectures auditées |
| [ADR-0024](0024-auditer-les-refus-de-lecture-d-un-enregistrement-dans-un.md) | Auditer les refus de lecture d'un enregistrement, dans un budget par identité — et un seul seau à jetons, partagé (`pkg/refusalbudget`) | Accepté | Lectures auditées |
| [ADR-0025](0025-l-audit-service-ne-prend-dans-la-trace-que-ce-qu-un-emetteur.md) | L'Audit Service ne prend dans la trace que ce qu'un émetteur peut vouloir dire (forme et taille de chaque champ, corps borné) | Accepté | Chaîne d'audit |
| [ADR-0026](0026-le-hash-d-un-evenement-d-audit-couvre-chaque-champ-comme-un.md) | Le hash d'un événement d'audit couvre chaque champ comme un champ : un format versionné, et l'ancien seulement pour vérifier | Accepté | Chaîne d'audit |
| [ADR-0027](0027-la-chaine-d-audit-est-a-cle-hmac-et-chaque-evenement-dit.md) | La chaîne d'audit est à clé (HMAC), et chaque événement dit quel service l'a écrit | Accepté | Chaîne d'audit |
| [ADR-0028](0028-la-tete-de-la-chaine-d-audit-est-ancree-hors-de-la-base-et.md) | La tête de la chaîne d'audit est ancrée hors de la base, et la chaîne se vérifie contre ses ancres | Accepté | Chaîne d'audit |
| [ADR-0029](0029-l-acces-aux-donnees-reste-en-database-sql-et-sql-ecrit-a-la.md) | L'accès aux données reste en `database/sql` et SQL écrit à la main ; pas d'ORM | Accepté | Fondations du code |
| [ADR-0030](0030-des-migrations-de-schema-versionnees-appliquees-une-fois.md) | Des migrations de schéma versionnées, appliquées une fois, sous verrou, et dont le texte appliqué ne change plus | Accepté | Fondations du code |
| [ADR-0031](0031-audit-events-n-est-pas-partitionne-tant-qu-une-retention-ne.md) | `audit_events` n'est pas partitionné tant qu'une rétention ne garde pas la chaîne vérifiable | Accepté | Chaîne d'audit |
| [ADR-0032](0032-archiver-la-chaine-d-audit-hors-de-la-base-sans-la-rendre.md) | Archiver la chaîne d'audit hors de la base sans la rendre invérifiable : un point de contrôle ancré | Accepté | Chaîne d'audit |
| [ADR-0033](0033-un-deploiement-docker-compose-reproductible-sous-mtls-une.md) | Un déploiement `docker-compose` reproductible, sous mTLS, une base par service, et le premier outil du CLI | Accepté | Déploiement, CI et chaîne d'approvisionnement |
| [ADR-0034](0034-une-session-ou-une-demande-arrivee-a-echeance-est-marquee.md) | Une session ou une demande arrivée à échéance est marquée expirée, une fois, et l'expiration est écrite dans la trace | Accepté | Sessions : cycle de vie et contrôle |
| [ADR-0035](0035-le-connecteur-oidc-un-code-d-autorisation-avec-pkce-un-jeton.md) | Le connecteur OIDC : un code d'autorisation avec PKCE, un jeton d'identité vérifié champ par champ, des rôles tirés d'une table de groupes déclarée | Accepté | Identité et authentification |
| [ADR-0036](0036-l-admin-ui-react-vite-et-typescript-servie-par-la-gateway.md) | L'Admin UI : React, Vite et TypeScript, servie par la Gateway sous `/ui/`, de même origine que l'API, sous une CSP stricte | Accepté | Interfaces et notifications |
| [ADR-0037](0037-la-rotation-d-un-secret-atteint-la-cible-un-compte-de.md) | La rotation d'un secret atteint la cible : un compte de réconciliation, une version en attente, une vérification avant de la rendre courante | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0038](0038-sftp-et-scp-a-travers-le-proxy-chaque-transfert-est.md) | SFTP et SCP à travers le proxy : chaque transfert est enregistré, avant d'être transmis | Accepté | Proxy SSH |
| [ADR-0039](0039-la-cle-d-hote-de-chaque-cible-est-epinglee-au-vault-et.md) | La clé d'hôte de chaque cible est épinglée au Vault, et livrée au proxy avec le secret | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0040](0040-les-rotations-planifiees-sont-executees-un-intervalle-par.md) | Les rotations planifiées sont exécutées : un intervalle par compte, un balayage du Vault, une prise par compare-échange | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0041](0041-une-rotation-planifiee-qui-echoue-se-voit-echecs-comptes.md) | Une rotation planifiée qui échoue se voit : échecs comptés, alerte à l'audit ; et elle peut être tenue dans une fenêtre horaire | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0042](0042-un-refus-dit-son-motif-a-l-operateur-par-un-code-stable-et.md) | Un refus dit son motif à l'opérateur par un code stable, et une panne ne dit jamais sa cause | Accepté | Invariants de sécurité transverses |
| [ADR-0043](0043-aucune-route-publique-ne-rend-le-texte-d-une-erreur-interne.md) | Aucune route publique ne rend le texte d'une erreur interne ; une session ne se crée que sur un compte qui existe et dont la clé est épinglée | Accepté | Invariants de sécurité transverses |
| [ADR-0044](0044-une-rotation-apres-usage-est-une-dette-enregistree-reglee.md) | Une rotation après usage est une dette enregistrée, réglée jusqu'au bout : le Broker la remet, le Vault la paie | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0045](0045-une-alerte-ecrite-a-l-audit-est-poussee-par-un-webhook-signe.md) | Une alerte écrite à l'audit est poussée par un webhook signé, et seulement si celui qui l'écrit a le droit de la dire | Accepté | Chaîne d'audit |
| [ADR-0046](0046-plusieurs-instances-du-proxy-ssh-le-broker-les-connait-toutes.md) | Plusieurs instances du proxy SSH : le Broker les connaît toutes, émet un ticket chez l'une, et fait révoquer chez toutes | Accepté | Proxy SSH |
| [ADR-0047](0047-une-ci-github-actions-qui-rejoue-la-verification-complete.md) | Une CI GitHub Actions qui rejoue la vérification complète, sur des actions et une image épinglées par empreinte | Accepté | Déploiement, CI et chaîne d'approvisionnement |
| [ADR-0048](0048-une-cible-peut-etre-reconnue-par-une-autorite-de-certificats-ssh.md) | Une cible peut être reconnue par une autorité de certificats SSH épinglée au compte, à la place de sa clé | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0049](0049-les-cles-de-chiffrement-gardees-par-transit.md) | Les clés de chiffrement du Vault et du Command Recorder sont gardées par le moteur Transit d'OpenBao, et les anciennes lignes restent lisibles | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0050](0050-le-transport-interne-reste-http-json-sous-mtls.md) | Le transport entre services reste HTTP/JSON sous mTLS, avec les noms des messages de `proto/`, et un test empêche les deux de diverger | Accepté | Communication entre services |
| [ADR-0051](0051-les-images-tirees-sont-epinglees-par-empreinte.md) | Toute image tirée d'un registre est épinglée par son empreinte, et un test refuse celle qui ne l'est pas | Accepté | Déploiement, CI et chaîne d'approvisionnement |
| [ADR-0052](0052-les-vulnerabilites-connues-se-cherchent-a-chaque-commit-et-chaque-semaine.md) | Les vulnérabilités connues se cherchent à chaque commit et chaque semaine, sur les modules sous leur vrai nom | Accepté | Déploiement, CI et chaîne d'approvisionnement |
| [ADR-0053](0053-le-jeton-transit-se-renouvelle-de-lui-meme.md) | Le jeton Transit se renouvelle de lui-même, à mi-vie, et le dit quand il ne le peut pas | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0054](0054-une-cle-d-hote-certifiee-peut-etre-revoquee.md) | Une clé d'hôte certifiée peut être révoquée au compte, comme dans `known_hosts`, et ne reçoit plus rien même avec un certificat valable | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0055](0055-ce-que-la-cle-locale-protege-encore-est-rescelle-sous-transit.md) | Ce que la clé locale protège encore est rescellé sous la clé courante, en tâche de fond, jusqu'à ce que la clé locale puisse partir | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0056](0056-un-jeton-transit-remplace-sur-disque-est-pris-sans-redemarrer.md) | Un jeton Transit remplacé sur disque est pris sans redémarrer, après avoir été vérifié auprès de Transit | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0057](0057-les-alertes-en-attente-survivent-a-un-redemarrage.md) | Avec une base, les alertes en attente d'un renvoi survivent à un redémarrage de l'Audit Service | Accepté | Chaîne d'audit |
| [ADR-0058](0058-le-vault-et-le-recorder-se-connectent-a-transit-par-approle.md) | Le Vault et le Recorder peuvent se connecter à Transit par AppRole, et reprennent un jeton neuf quand le leur atteint sa fin | Accepté | Coffre, secrets et confiance dans les cibles |
| [ADR-0059](0059-dependabot-propose-une-dependance-a-la-fois-la-ci-decide.md) | Dependabot propose les mises à jour, une dépendance à la fois et après sept jours ; la CI décide | Accepté | Déploiement, CI et chaîne d'approvisionnement |
| [ADR-0060](0060-les-images-sont-analysees-par-trivy-verifie-contre-son-empreinte.md) | Les images sont analysées par Trivy, un binaire vérifié contre son empreinte, jamais par ses actions ; ce qui est accepté l'est par écrit, par chemin et jusqu'à une date | Accepté | Déploiement, CI et chaîne d'approvisionnement |
| [ADR-0061](0061-connexion-par-annuaire-ldap-et-active-directory.md) | Un utilisateur d'annuaire (LDAP ou Active Directory) se connecte avec son mot de passe d'annuaire ; seuls ses groupes déclarés lui donnent des rôles | Accepté | Identité et authentification |
| [ADR-0062](0062-un-second-facteur-totp-exige-par-role-enrole-par-un-code-d-administrateur.md) | Un second facteur TOTP est exigé pour les rôles déclarés ; on l'enrôle avec un code à usage unique qu'un administrateur a émis | Accepté | Identité et authentification |
| [ADR-0063](0063-le-projet-suit-semantic-versioning-version-dans-un-fichier-estampillee-a-la-construction.md) | Le projet suit Semantic Versioning : un fichier `VERSION`, estampillé dans chaque binaire, vérifié par la CI, et un tag `vX.Y.Z` pour chaque release | Accepté | Fondations du code |
| [ADR-0064](0064-les-connexions-et-les-gestes-d-administration-du-second-facteur-sont-ecrits-a-l-audit.md) | Les connexions et les gestes d'administration du second facteur sont écrits à l'audit ; un jeton n'est émis qu'une fois sa connexion écrite | Accepté | Identité et authentification |
| [ADR-0065](0065-webauthn-second-facteur-qui-resiste-a-l-hameconnage-exige-pour-les-roles-stricts.md) | WebAuthn est un second facteur à côté de TOTP ; pour les rôles déclarés stricts, il est le seul qui compte, parce qu'il résiste à l'hameçonnage | Accepté | Identité et authentification |
| [ADR-0066](0066-une-cle-de-secours-s-ajoute-avec-la-cle-actuelle-et-un-code-d-administrateur.md) | Une clé de secours s'ajoute avec la signature de la clé actuelle et un code d'administrateur ; un administrateur révoque une seule clé | Accepté | Identité et authentification |
| [ADR-0067](0067-une-session-vers-un-compte-qui-l-exige-attend-l-approbation-d-une-autre-personne-avec-un-ticket.md) | Une session vers un compte qui l'exige attend l'approbation d'une autre personne, et porte un ticket au format déclaré | Accepté | Sessions : cycle de vie et contrôle |
| [ADR-0068](0068-les-details-d-un-evenement-d-audit-sont-bornes-et-proteges-par-le-hash.md) | Les détails d'un événement d'audit sont bornés et protégés par le hash | Accepté | Chaîne d'audit |
| [ADR-0069](0069-le-proxy-rdp-verifie-la-cible-et-refuse-les-sessions-non-enregistrees.md) | Le proxy RDP vérifie la cible et refuse les sessions non enregistrées | Accepté | Proxy écran RDP et VNC |
| [ADR-0070](0070-le-video-recorder-acquitte-des-segments-chiffres-avant-de-les-servir.md) | Le Video Recorder acquitte des segments chiffrés avant de les servir | Accepté | Enregistrement et relecture |
| [ADR-0071](0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md) | Le proxy RDP/VNC termine la cible en Go pur et sert un flux écran acquitté | Accepté, mise en œuvre en cours | Proxy écran RDP et VNC |
| [ADR-0072](0072-la-cli-cobra-et-une-version-homogene-pour-chaque-binaire.md) | Les exécutables OpenBastion adoptent Cobra et exposent une version de build homogène | Accepté | Fondations du code |
| [ADR-0073](0073-l-admin-ui-adopte-un-systeme-de-conception-et-une-experience-operateur-progressive.md) | L'Admin UI adopte un système de conception cohérent et une expérience opérateur progressive | Accepté, mise en œuvre en cours | Interfaces et notifications |
| [ADR-0074](0074-slack-et-teams-recoivent-les-notifications-dans-leur-format-sans-nouveau-service.md) | Slack et Teams reçoivent les notifications dans leur format, sans nouveau service | Accepté | Interfaces et notifications |
| [ADR-0075](0075-architecture-du-user-portal-et-socle-frontend-partage.md) | Architecture du User Portal et socle frontend partagé | Proposé | Interfaces et notifications |
| [ADR-0076](0076-plusieurs-fournisseurs-d-identite-chaque-compte-lie-au-sien.md) | Plusieurs fournisseurs d'identité à la fois, chaque compte lié au sien | Accepté | Identité et authentification |
| [ADR-0077](0077-modulariser-les-workflows-github-actions-derriere-une-porte-de-validation-stable.md) | Modulariser les workflows GitHub Actions derrière une porte de validation stable | Accepté | Déploiement, CI et chaîne d'approvisionnement |
| [ADR-0078](0078-chaque-fournisseur-oidc-garde-son-emetteur-un-changement-se-declare.md) | Chaque fournisseur OIDC garde son émetteur ; un changement se déclare | Accepté | Identité et authentification |
| [ADR-0079](0079-entra-id-est-un-profil-oidc-lie-a-un-tenant-declare.md) | Entra ID est un profil OIDC lié à un tenant déclaré | Accepté | Identité et authentification |
| [ADR-0080](0080-la-recherche-plein-texte-dechiffre-a-la-volee-dans-une-fenetre-bornee.md) | La recherche plein texte déchiffre à la volée, dans une fenêtre bornée, sans index en clair | Accepté, mise en œuvre en cours | Enregistrement et relecture |
| [ADR-0081](0081-veille-rdp-externe-et-integration-selective.md) | Veille RDP externe et intégration sélective des enseignements | Proposé | Proxy écran RDP et VNC |
| [ADR-0082](0082-rsync-distant-passe-par-le-proxy-ssh-sans-shell-arbitraire.md) | rsync distant passe par le proxy SSH, sans shell arbitraire | Proposé | Proxy SSH |
| [ADR-0083](0083-bibliotheque-ssh-openbastion-avec-politiques-capture-et-audit.md) | La bibliothèque SSH OpenBastion intègre politiques, capture et audit au cycle protocolaire | Proposé | Proxy SSH |
| [ADR-0084](0084-bibliotheque-rdp-openbastion-moteur-protocolaire-instrumente.md) | La bibliothèque RDP OpenBastion sépare le moteur protocolaire des contrôles PAM | Proposé | Proxy écran RDP et VNC |
| [ADR-0085](0085-bibliotheque-vnc-openbastion-moteur-rfb-instrumente.md) | La bibliothèque VNC OpenBastion sépare RFB des contrôles PAM et de l'enregistrement | Proposé | Proxy écran RDP et VNC |
| [ADR-0086](0086-le-client-rdp-decode-15-et-16-bpp-pour-les-cibles-windows-par-defaut.md) | Le client RDP décode 15 et 16 bpp, pour les cibles Windows laissées par défaut | Accepté, mise en œuvre en cours | Proxy écran RDP et VNC |
| [ADR-0087](0087-contrats-transverses-des-bibliotheques-protocolaires-ssh-rdp-vnc.md) | Les bibliothèques SSH, RDP et VNC partagent des contrats PAM sans partager leurs moteurs protocolaires | Proposé | Proxy écran RDP et VNC |
| [ADR-0088](0088-rdp-ouvert-aux-operateurs-par-la-route-ecran-derriere-un-interrupteur.md) | RDP est ouvert aux opérateurs par la route écran de VNC, derrière un interrupteur éteint par défaut | Accepté, mise en œuvre en cours | Proxy écran RDP et VNC |
| [ADR-0089](0089-le-texte-rdp-reste-rendu-par-bitmaps-sans-cache-de-glyphes.md) | Le texte RDP reste rendu par bitmaps : le cache de glyphes n'est pas implémenté tant qu'une mesure ne le demande pas | Accepté | Proxy écran RDP et VNC |
| [ADR-0090](0090-rdp-v002-glyphes-ordres-canaux-et-protocoles.md) | RDP en v0.0.2 : glyphes, ordres graphiques, canaux virtuels et protocoles, par incréments prouvés | Proposé | Proxy écran RDP et VNC |
| [ADR-0091](0091-le-pointeur-est-dessine-dans-l-image-enregistree.md) | Le pointeur est dessiné dans l'image, celle que l'opérateur voit et que l'auditeur rejoue | Accepté | Proxy écran RDP et VNC |
| [ADR-0092](0092-l-ecran-s-enregistre-en-images-partielles-ancrees-sur-des-images-cles.md) | L'écran s'enregistre en images partielles, ancrées sur des images clés | Accepté | Enregistrement et relecture |
| [ADR-0093](0093-une-relecture-lit-plusieurs-segments-par-requete.md) | Une relecture lit plusieurs segments par requête | Accepté | Enregistrement et relecture |
| [ADR-0094](0094-provenance-sbom-signature-et-verification-des-artefacts.md) | La chaîne de livraison atteste la provenance et le SBOM, signe les artefacts publiés et impose leur vérification au déploiement | Accepté | Déploiement, CI et chaîne d’approvisionnement |
| [ADR-0095](0095-le-proxy-rdp-ouvre-les-canaux-virtuels-d-une-liste-fermee-en-commencant-par-le-redimensionnement.md) | Le proxy RDP ouvre les canaux virtuels d'une liste fermée, en commençant par le redimensionnement | Accepté | Proxy écran RDP et VNC |
| [ADR-0096](0096-le-presse-papiers-rdp-texte-par-sens-enregistre-et-audite.md) | Le presse-papiers RDP passe du texte, dans chaque sens selon une politique, enregistré et audité | Accepté | Proxy écran RDP et VNC |
