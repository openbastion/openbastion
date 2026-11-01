# ADR-0069 — Le proxy RDP vérifie la cible et refuse les sessions non enregistrées

**Statut** `Proposé` · 1ᵉʳ novembre 2026 · à valider avant toute implémentation

## Contexte

La feuille de route v0.0.1 prévoit un proxy RDP/VNC et le replay vidéo des sessions (`docs/roadmap.md`). Le dépôt n'implémente aujourd'hui que SSH. `pkg/proxycore.Codec` mutualise le relais et le cycle de vie, mais le credential ne transporte qu'une adresse et une clé d'hôte SSH (`pkg/proxycore/credential_fetcher.go`). RDP demande une identité de cible adaptée à TLS, une authentification NLA/CredSSP et l'enregistrement d'un flux graphique.

Les invariants concernés sont : aucun secret dans le control plane (ADR-0003), enregistrer ou refuser (ADR-0008), reconnaître la cible avant de lui envoyer le secret (ADR-0039), identité de service par mTLS (ADR-0010) et révocation effective (ADR-0018). ADR-0050 maintient HTTP/JSON pour les appels internes, mais nomme explicitement un flux réel comme motif de réexamen.

## Décision

1. **Le premier proxy supplémentaire est RDP seulement.** Un service `rdp-proxy` dédié route les sessions dont le compte Vault est de protocole `rdp`. Il réutilise `pkg/proxycore` pour l'admission, l'échange du scope à usage unique directement avec le Vault, la purge du credential, l'expiration et la révocation. VNC est hors de cet ADR et nécessite sa propre décision avant implémentation.
2. **Le proxy termine les deux connexions RDP.** La connexion du client aboutit au proxy ; le proxy ouvre celle vers la cible. Le client ne choisit pas l'adresse de la cible et ne fournit jamais le credential de celle-ci. Le proxy utilise uniquement le credential remis par le Vault, après l'admission d'enregistrement et la vérification de l'identité de la cible. Le contrat de rattachement du client à une session doit être à usage unique, lié à cette session et ne doit placer aucun secret dans une URL ou un journal ; sa forme exacte est un contrat à définir avant le code.
3. **NLA/CredSSP est obligatoire pour la cible.** La première version n'accepte que l'authentification par mot de passe provenant du Vault, avec TLS 1.2 au minimum. Aucun repli vers une connexion RDP sans NLA, une authentification fournie par le client ou un relais transparent n'est permis.
4. **Le Vault épingle le certificat TLS de chaque cible RDP.** Une migration versionnée étend les protocoles de compte acceptés à `rdp` et ajoute une empreinte SHA-256 du certificat feuille, distincte de la clé SSH. Un administrateur autorisé la configure explicitement ; le changement est audité avant d'être appliqué, comme l'épinglage SSH (ADR-0039). L'empreinte est renvoyée avec le credential au proxy. Celui-ci vérifie l'empreinte et l'adresse attendues avant toute présentation du mot de passe. Une absence ou une différence refuse la session et est auditée. Ni confiance au premier usage ni repli sur les autorités système ou le nom DNS. Un renouvellement de certificat exige un nouvel épinglage autorisé.
5. **L'enregistrement vidéo est obligatoire.** Le proxy s'appuie sur le Video Recorder, distinct du Command Recorder. Il refuse d'admettre une session si le recorder n'est pas prêt et termine les deux connexions si l'enregistrement devient indisponible ; aucun mode `best-effort` ni dérogation break-glass n'est prévu pour RDP. Le contenu vidéo est chiffré au repos et toute lecture est auditée avant d'être servie.
6. **La première version n'ouvre pas les canaux secondaires RDP** (presse-papiers, lecteurs, imprimantes et audio). Ils restent refusés jusqu'à ce qu'une décision définisse leur enregistrement, leur protection et leur audit. Le replay porte sur l'affichage ; les frappes clavier ne sont pas enregistrées.
7. **Le flux vidéo a besoin d'une décision de transport avant le code.** Le proxy ne détourne pas HTTP/JSON en un flux implicite et n'ajoute pas de tampon local en cas de panne. Un ADR complémentaire définit le transport, le format des unités, leur ordre et l'acquittement durable du Video Recorder sous mTLS ; sans cet ADR et sans recorder disponible, aucune session RDP n'est activée.

## Conséquences

- (+) Les secrets restent dans le proxy et ne sont envoyés qu'à une cible dont le certificat est épinglé ; une session sans enregistrement vidéo ne démarre pas. Ces garanties restent à prouver par les tests d'attaque et leurs contre-épreuves avant livraison.
- (+) Le périmètre initial peut être testé sur un parcours client → proxy → cible : certificat imposteur, absence ou panne du recorder, révocation, purge du credential, absence de secret dans les traces et replay vidéo.
- (−) Cette proposition n'est pas une implémentation : aucun résultat de test ni mesure de performance RDP n'est revendiqué.
- (−) Le Video Recorder et son contrat de flux ne sont pas implémentés. Le proxy ne pourra pas offrir de sessions utilisables avant leur conception, leur implémentation et leur déploiement.
- (−) Le rejeu est visuel seulement ; il ne reconstitue pas les frappes clavier. Les canaux secondaires, les cartes à puce, Remote Credential Guard et toute authentification autre que le mot de passe Vault sont exclus.
- (−) Une rotation du certificat cible bloque l'accès jusqu'à un nouvel épinglage. Le TLS 1.2 minimal écarte les serveurs qui ne le prennent pas en charge.
- (−) La terminaison TLS côté proxy implique que le proxy voit le flux graphique en clair. Les images peuvent contenir des données sensibles affichées par la cible ; elles restent des enregistrements à accès contrôlé, chiffrés et audités.
- (−) La bibliothèque RDP n'est pas choisie ici. Toute nouvelle dépendance devra être examinée et approuvée selon la policy des dépendances avant son ajout.

## Alternatives envisagées

- **Tunnel RDP transparent de bout en bout** : écarté ; il ne permet ni d'injecter le credential Vault ni de capturer le flux graphique au proxy.
- **Réutiliser le Command Recorder pour la vidéo** : écarté ; il stocke des entrées textuelles et ne définit ni transport ni stockage pour un flux vidéo.
- **Faire confiance aux autorités système ou accepter la première clé vue** : écarté ; ces choix ne prouvent pas que le serveur est la cible autorisée au compte.
- **Accepter RDP sans NLA ou avec le mot de passe fourni par le client** : écarté ; cela introduirait un chemin d'authentification distinct du secret autorisé et tenu par le Vault.
- **Implémenter RDP et VNC dans le même incrément** : écarté ; les protocoles et leurs mécanismes d'authentification diffèrent, et VNC élargirait le périmètre avant que le pipeline RDP soit éprouvé.
- **Continuer sans recorder ou tamponner localement** : écarté ; une panne permettrait une session sans trace garantie ou transformerait le proxy en stockage secondaire de données de session.
