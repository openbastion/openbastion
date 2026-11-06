# Architecture Decision Records

Les décisions structurantes d'OpenBastion, une par fichier. Un ADR `Accepté` ne se réécrit pas : il se remplace par un nouvel ADR (« Remplacé par ADR-NNNN »).

## Format retenu

Chaque ADR suit un gabarit léger (inspiré de Michael Nygard / MADR) : **Contexte, Décision, Conséquences, Alternatives envisagées**. Statuts possibles : `Proposé`, `Accepté`, `Déprécié`, `Remplacé par ADR-NNNN`. Chaque ADR est un fichier `NNNN-titre-kebab-case.md` de ce dossier ; un nouvel ADR part de [`template.md`](template.md), prend le numéro suivant et ajoute sa ligne à l'index.

## Index

| ID | Titre | Statut |
|---|---|---|
| [ADR-0001](0001-double-bus-nats-temps-reel-kafka-streaming-durable.md) | Double bus NATS (temps réel) + Kafka (streaming durable) | Accepté |
| [ADR-0002](0002-organisation-en-monorepo-multi-module-go.md) | Organisation en monorepo multi-module Go | Accepté |
| [ADR-0003](0003-les-secrets-ne-traversent-jamais-le-control-plane.md) | Les secrets ne traversent jamais le control plane | Accepté |
| [ADR-0004](0004-go-comme-langage-unique-des-microservices-backend.md) | Go comme langage unique des microservices backend | Accepté |
| [ADR-0005](0005-separation-password-vault-secrets-manager.md) | Séparation Password Vault / Secrets Manager | Accepté |
| [ADR-0006](0006-pipeline-proxy-partage-factorise-en-bibliotheque-interne.md) | Pipeline proxy partagé factorisé en bibliothèque interne | Accepté |
| [ADR-0007](0007-keycloak-comme-idp-de-plateforme-federation-externe-en.md) | Keycloak comme IdP de plateforme, fédération externe en complément | Accepté |
| [ADR-0008](0008-enregistrer-ou-refuser-une-session-qui-ne-peut-pas-etre.md) | Enregistrer ou refuser : une session qui ne peut pas être enregistrée n'a pas lieu | Accepté |
| [ADR-0009](0009-break-glass-une-derogation-d-urgence-bornee-et-auditee-a.md) | Break-glass : une dérogation d'urgence, bornée et auditée, à « enregistrer ou refuser » | Accepté |
| [ADR-0010](0010-mtls-interne-l-identite-de-l-appelant-vient-du-certificat-et.md) | mTLS interne : l'identité de l'appelant vient du certificat, et chaque route a sa liste d'appelants | Accepté |
| [ADR-0011](0011-break-glass-double-validation-une-demande-en-attente.md) | Break-glass : double validation — une demande en attente, approuvée par une autre personne | Accepté |
| [ADR-0012](0012-break-glass-l-approbateur-decouvre-les-demandes-en-attente.md) | Break-glass : l'approbateur découvre les demandes en attente (liste filtrée par son droit) et en est prévenu (webhook, au mieux) | Accepté |
| [ADR-0013](0013-break-glass-un-plafond-de-demandes-en-attente-par-demandeur.md) | Break-glass : un plafond de demandes en attente par demandeur (atomique) et un message de notification signé (HMAC) | Accepté |
| [ADR-0014](0014-une-limitation-de-debit-par-identite-sur-les-demandes-de.md) | Une limitation de débit par identité sur les demandes de session, au Gateway — et un limiteur dont les unités et la mémoire sont justes | Accepté |
| [ADR-0015](0015-qui-est-le-client-derriere-l-arete-une-confiance-a-x.md) | Qui est « le client » derrière l'arête : une confiance à `X-Forwarded-For` limitée aux proxys déclarés, et des limites par adresse réglables | Accepté |
| [ADR-0016](0016-un-budget-par-identite-sur-les-actions-de-session-qui.md) | Un budget par identité sur les actions de session qui écrivent à chaque appel (`approve`, `reject`, `connect`) — et pas sur ce qui n'écrit qu'une fois ou rien | Accepté |
| [ADR-0017](0017-mettre-fin-a-une-session-son-demandeur-ou-une-autorite.md) | Mettre fin à une session : son demandeur ou une autorité déclarée, et au nom de celui qui le demande | Accepté |
| [ADR-0018](0018-rendre-la-terminaison-reelle-cote-proxy-le-broker-fait.md) | Rendre la terminaison réelle côté proxy : le Broker fait couper les connexions et jeter les tickets avant de marquer la session terminée | Accepté |
| [ADR-0019](0019-qui-peut-lire-une-session-son-demandeur-celui-qui-l-a.md) | Qui peut lire une session : son demandeur, celui qui l'a décidée, ou le titulaire d'une politique `session-read` — et une lecture n'écrit rien | Accepté (règle 6 amendée par ADR-0020) |
| [ADR-0020](0020-auditer-les-refus-de-lecture-d-une-session-au-nom-de-celui.md) | Auditer les refus de lecture d'une session, au nom de celui qui lit, dans la limite d'un budget par identité | Accepté (règle 2 amendée par ADR-0021) |
| [ADR-0021](0021-une-lecture-servie-a-un-titulaire-de-politique-s-enregistre.md) | Une lecture servie à un titulaire de politique s'enregistre avant d'être servie — et sans enregistrement, elle n'est pas servie | Accepté |
| [ADR-0022](0022-chaque-page-d-un-enregistrement-servie-s-enregistre-avant-d.md) | Chaque page d'un enregistrement du Command Recorder servie s'enregistre avant d'être servie, au nom de celui que le Gateway a vérifié — et sans enregistrement, elle n'est pas servie | Accepté (règle 6 amendée par ADR-0024) |
| [ADR-0023](0023-chaque-demande-servie-par-la-liste-des-demandes-en-attente-s.md) | Chaque demande servie par la liste des demandes en attente s'enregistre avant d'être servie — et sans enregistrement, la liste n'est pas servie | Accepté |
| [ADR-0024](0024-auditer-les-refus-de-lecture-d-un-enregistrement-dans-un.md) | Auditer les refus de lecture d'un enregistrement, dans un budget par identité — et un seul seau à jetons, partagé (`pkg/refusalbudget`) | Accepté |
| [ADR-0025](0025-l-audit-service-ne-prend-dans-la-trace-que-ce-qu-un-emetteur.md) | L'Audit Service ne prend dans la trace que ce qu'un émetteur peut vouloir dire (forme et taille de chaque champ, corps borné) | Accepté |
| [ADR-0026](0026-le-hash-d-un-evenement-d-audit-couvre-chaque-champ-comme-un.md) | Le hash d'un événement d'audit couvre chaque champ comme un champ : un format versionné, et l'ancien seulement pour vérifier | Accepté |
| [ADR-0027](0027-la-chaine-d-audit-est-a-cle-hmac-et-chaque-evenement-dit.md) | La chaîne d'audit est à clé (HMAC), et chaque événement dit quel service l'a écrit | Accepté |
| [ADR-0028](0028-la-tete-de-la-chaine-d-audit-est-ancree-hors-de-la-base-et.md) | La tête de la chaîne d'audit est ancrée hors de la base, et la chaîne se vérifie contre ses ancres | Accepté |
| [ADR-0029](0029-l-acces-aux-donnees-reste-en-database-sql-et-sql-ecrit-a-la.md) | L'accès aux données reste en `database/sql` et SQL écrit à la main ; pas d'ORM | Accepté |
| [ADR-0030](0030-des-migrations-de-schema-versionnees-appliquees-une-fois.md) | Des migrations de schéma versionnées, appliquées une fois, sous verrou, et dont le texte appliqué ne change plus | Accepté |
| [ADR-0031](0031-audit-events-n-est-pas-partitionne-tant-qu-une-retention-ne.md) | `audit_events` n'est pas partitionné tant qu'une rétention ne garde pas la chaîne vérifiable | Accepté |
| [ADR-0032](0032-archiver-la-chaine-d-audit-hors-de-la-base-sans-la-rendre.md) | Archiver la chaîne d'audit hors de la base sans la rendre invérifiable : un point de contrôle ancré | Accepté |
| [ADR-0033](0033-un-deploiement-docker-compose-reproductible-sous-mtls-une.md) | Un déploiement `docker-compose` reproductible, sous mTLS, une base par service, et le premier outil du CLI | Accepté |
| [ADR-0034](0034-une-session-ou-une-demande-arrivee-a-echeance-est-marquee.md) | Une session ou une demande arrivée à échéance est marquée expirée, une fois, et l'expiration est écrite dans la trace | Accepté |
| [ADR-0035](0035-le-connecteur-oidc-un-code-d-autorisation-avec-pkce-un-jeton.md) | Le connecteur OIDC : un code d'autorisation avec PKCE, un jeton d'identité vérifié champ par champ, des rôles tirés d'une table de groupes déclarée | Accepté |
| [ADR-0036](0036-l-admin-ui-react-vite-et-typescript-servie-par-la-gateway.md) | L'Admin UI : React, Vite et TypeScript, servie par la Gateway sous `/ui/`, de même origine que l'API, sous une CSP stricte | Accepté |
| [ADR-0037](0037-la-rotation-d-un-secret-atteint-la-cible-un-compte-de.md) | La rotation d'un secret atteint la cible : un compte de réconciliation, une version en attente, une vérification avant de la rendre courante | Accepté |
| [ADR-0038](0038-sftp-et-scp-a-travers-le-proxy-chaque-transfert-est.md) | SFTP et SCP à travers le proxy : chaque transfert est enregistré, avant d'être transmis | Accepté |
| [ADR-0039](0039-la-cle-d-hote-de-chaque-cible-est-epinglee-au-vault-et.md) | La clé d'hôte de chaque cible est épinglée au Vault, et livrée au proxy avec le secret | Accepté |
| [ADR-0040](0040-les-rotations-planifiees-sont-executees-un-intervalle-par.md) | Les rotations planifiées sont exécutées : un intervalle par compte, un balayage du Vault, une prise par compare-échange | Accepté |
| [ADR-0041](0041-une-rotation-planifiee-qui-echoue-se-voit-echecs-comptes.md) | Une rotation planifiée qui échoue se voit : échecs comptés, alerte à l'audit ; et elle peut être tenue dans une fenêtre horaire | Accepté |
| [ADR-0042](0042-un-refus-dit-son-motif-a-l-operateur-par-un-code-stable-et.md) | Un refus dit son motif à l'opérateur par un code stable, et une panne ne dit jamais sa cause | Accepté |
| [ADR-0043](0043-aucune-route-publique-ne-rend-le-texte-d-une-erreur-interne.md) | Aucune route publique ne rend le texte d'une erreur interne ; une session ne se crée que sur un compte qui existe et dont la clé est épinglée | Accepté |
| [ADR-0044](0044-une-rotation-apres-usage-est-une-dette-enregistree-reglee.md) | Une rotation après usage est une dette enregistrée, réglée jusqu'au bout : le Broker la remet, le Vault la paie | Accepté |
| [ADR-0045](0045-une-alerte-ecrite-a-l-audit-est-poussee-par-un-webhook-signe.md) | Une alerte écrite à l'audit est poussée par un webhook signé, et seulement si celui qui l'écrit a le droit de la dire | Accepté |
| [ADR-0046](0046-plusieurs-instances-du-proxy-ssh-le-broker-les-connait-toutes.md) | Plusieurs instances du proxy SSH : le Broker les connaît toutes, émet un ticket chez l'une, et fait révoquer chez toutes | Accepté |
| [ADR-0047](0047-une-ci-github-actions-qui-rejoue-la-verification-complete.md) | Une CI GitHub Actions qui rejoue la vérification complète, sur des actions et une image épinglées par empreinte | Accepté |
| [ADR-0048](0048-une-cible-peut-etre-reconnue-par-une-autorite-de-certificats-ssh.md) | Une cible peut être reconnue par une autorité de certificats SSH épinglée au compte, à la place de sa clé | Accepté |
| [ADR-0049](0049-les-cles-de-chiffrement-gardees-par-transit.md) | Les clés de chiffrement du Vault et du Command Recorder sont gardées par le moteur Transit d'OpenBao, et les anciennes lignes restent lisibles | Accepté |
| [ADR-0050](0050-le-transport-interne-reste-http-json-sous-mtls.md) | Le transport entre services reste HTTP/JSON sous mTLS, avec les noms des messages de `proto/`, et un test empêche les deux de diverger | Accepté |
| [ADR-0051](0051-les-images-tirees-sont-epinglees-par-empreinte.md) | Toute image tirée d'un registre est épinglée par son empreinte, et un test refuse celle qui ne l'est pas | Accepté |
| [ADR-0052](0052-les-vulnerabilites-connues-se-cherchent-a-chaque-commit-et-chaque-semaine.md) | Les vulnérabilités connues se cherchent à chaque commit et chaque semaine, sur les modules sous leur vrai nom | Accepté |
| [ADR-0053](0053-le-jeton-transit-se-renouvelle-de-lui-meme.md) | Le jeton Transit se renouvelle de lui-même, à mi-vie, et le dit quand il ne le peut pas | Accepté |
| [ADR-0054](0054-une-cle-d-hote-certifiee-peut-etre-revoquee.md) | Une clé d'hôte certifiée peut être révoquée au compte, comme dans `known_hosts`, et ne reçoit plus rien même avec un certificat valable | Accepté |
| [ADR-0055](0055-ce-que-la-cle-locale-protege-encore-est-rescelle-sous-transit.md) | Ce que la clé locale protège encore est rescellé sous la clé courante, en tâche de fond, jusqu'à ce que la clé locale puisse partir | Accepté |
| [ADR-0056](0056-un-jeton-transit-remplace-sur-disque-est-pris-sans-redemarrer.md) | Un jeton Transit remplacé sur disque est pris sans redémarrer, après avoir été vérifié auprès de Transit | Accepté |
| [ADR-0057](0057-les-alertes-en-attente-survivent-a-un-redemarrage.md) | Avec une base, les alertes en attente d'un renvoi survivent à un redémarrage de l'Audit Service | Accepté |
| [ADR-0058](0058-le-vault-et-le-recorder-se-connectent-a-transit-par-approle.md) | Le Vault et le Recorder peuvent se connecter à Transit par AppRole, et reprennent un jeton neuf quand le leur atteint sa fin | Accepté |
| [ADR-0059](0059-dependabot-propose-une-dependance-a-la-fois-la-ci-decide.md) | Dependabot propose les mises à jour, une dépendance à la fois et après sept jours ; la CI décide | Accepté |
| [ADR-0060](0060-les-images-sont-analysees-par-trivy-verifie-contre-son-empreinte.md) | Les images sont analysées par Trivy, un binaire vérifié contre son empreinte, jamais par ses actions ; ce qui est accepté l'est par écrit, par chemin et jusqu'à une date | Accepté |
| [ADR-0061](0061-connexion-par-annuaire-ldap-et-active-directory.md) | Un utilisateur d'annuaire (LDAP ou Active Directory) se connecte avec son mot de passe d'annuaire ; seuls ses groupes déclarés lui donnent des rôles | Accepté |
| [ADR-0062](0062-un-second-facteur-totp-exige-par-role-enrole-par-un-code-d-administrateur.md) | Un second facteur TOTP est exigé pour les rôles déclarés ; on l'enrôle avec un code à usage unique qu'un administrateur a émis | Accepté |
| [ADR-0063](0063-le-projet-suit-semantic-versioning-version-dans-un-fichier-estampillee-a-la-construction.md) | Le projet suit Semantic Versioning : un fichier `VERSION`, estampillé dans chaque binaire, vérifié par la CI, et un tag `vX.Y.Z` pour chaque release | Accepté |
| [ADR-0064](0064-les-connexions-et-les-gestes-d-administration-du-second-facteur-sont-ecrits-a-l-audit.md) | Les connexions et les gestes d'administration du second facteur sont écrits à l'audit ; un jeton n'est émis qu'une fois sa connexion écrite | Accepté |
| [ADR-0065](0065-webauthn-second-facteur-qui-resiste-a-l-hameconnage-exige-pour-les-roles-stricts.md) | WebAuthn est un second facteur à côté de TOTP ; pour les rôles déclarés stricts, il est le seul qui compte, parce qu'il résiste à l'hameçonnage | Accepté |
| [ADR-0066](0066-une-cle-de-secours-s-ajoute-avec-la-cle-actuelle-et-un-code-d-administrateur.md) | Une clé de secours s'ajoute avec la signature de la clé actuelle et un code d'administrateur ; un administrateur révoque une seule clé | Accepté |
| [ADR-0067](0067-une-session-vers-un-compte-qui-l-exige-attend-l-approbation-d-une-autre-personne-avec-un-ticket.md) | Une session vers un compte qui l'exige attend l'approbation d'une autre personne, et porte un ticket au format déclaré | Accepté |
| [ADR-0068](0068-les-details-d-un-evenement-d-audit-sont-bornes-et-proteges-par-le-hash.md) | Les détails d'un événement d'audit sont bornés et protégés par le hash | Accepté |
| [ADR-0069](0069-le-proxy-rdp-verifie-la-cible-et-refuse-les-sessions-non-enregistrees.md) | Le proxy RDP vérifie la cible et refuse les sessions non enregistrées | Accepté |
| [ADR-0070](0070-le-video-recorder-acquitte-des-segments-chiffres-avant-de-les-servir.md) | Le Video Recorder acquitte des segments chiffrés avant de les servir | Accepté |
| [ADR-0071](0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md) | Le proxy RDP/VNC termine la cible en Go pur et sert un flux écran acquitté | Accepté |
| [ADR-0072](0072-la-cli-cobra-et-une-version-homogene-pour-chaque-binaire.md) | Les exécutables OpenBastion adoptent Cobra et exposent une version de build homogène | Accepté |
| [ADR-0073](0073-l-admin-ui-adopte-un-systeme-de-conception-et-une-experience-operateur-progressive.md) | L'Admin UI adopte un système de conception cohérent et une expérience opérateur progressive | Proposé |
| [ADR-0074](0074-architecture-du-user-portal-et-socle-frontend-partage.md) | Architecture du User Portal et socle frontend partagé | Proposé |
