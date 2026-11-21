# ADR-0100 — CredSSP accepte Kerberos à côté de NTLMv2, pour les domaines qui ferment NTLM

**Statut** `Accepté` · 13 novembre 2026 · accepté le même jour par le propriétaire du projet : « ADR-0100 l'option A Une bibliothèque Go éprouvée, soumise à la policy des dépendances ». La revue de gokrb5 selon `.agents/policies/dependencies-and-supply-chain.md` (besoin, licence, maintenance, alternative écartée, empreinte) lui sera soumise avant toute ligne de code. Le domaine de test en CI et les champs de compte du Vault restent à confirmer à leur incrément.

## Contexte

Le client CredSSP de `pkg/rdp` ne parle que NTLMv2, avec SPNEGO ou en NTLM direct. Kerberos, `mechListMIC` (hors du cas NTLM mesuré), la carte à puce et Remote Guard sont refusés. Un domaine Active Directory qui interdit NTLM (stratégie « Restrict NTLM ») ferme donc toutes ses cibles à OpenBastion. C'est la recommandation de sécurité courante, et Microsoft retire NTLM progressivement.

Ce que Kerberos demande au proxy, en plus de NTLM :
- joindre un contrôleur de domaine, le KDC, sur le port 88 ;
- obtenir un ticket pour l'utilisateur (AS-REQ, avec le mot de passe tiré du Vault), puis un ticket de service pour `TERMSRV/<cible>` (TGS-REQ) ;
- mener l'échange GSS-API Kerberos (AP-REQ et AP-REP) dans SPNEGO ;
- protéger `pubKeyAuth` et `authInfo` par les jetons d'enveloppe de la RFC 4121, avec la sous-clé négociée.

La cryptographie (AES-CTS-HMAC-SHA1, RC4-HMAC) et les messages ASN.1 de Kerberos sont un chantier de la taille de tout NTLM.

## Options

- **A. Une bibliothèque Go éprouvée** : `github.com/jcmturner/gokrb5/v8`, Apache-2.0, en Go pur, utilisée par d'autres projets. Ce serait une **nouvelle dépendance**, donc soumise à la policy des dépendances et à ton go : revue de licence, de maintenance et de vulnérabilités, version épinglée.
- **B. Une implémentation dans le dépôt**, comme NTLM : aucune dépendance, mais un chantier long et une cryptographie délicate.
- **C. Statu quo** : documenter que les domaines sans NTLM ne sont pas pris en charge.

## Décision proposée

**A, sous conditions** :
1. gokrb5 sert seulement à obtenir les tickets (AS et TGS) et à la cryptographie de la RFC 3961/3962. SPNEGO, CredSSP et l'enveloppe RFC 4121 restent dans `pkg/rdp`, sous ses bornes.
2. **Configuration** : le KDC et le royaume viennent du compte privilégié, tenus par le Vault avec le compte, jamais de l'opérateur. Le canal vers le KDC est explicite, sans découverte DNS implicite.
3. **Le secret** : le mot de passe ne sert qu'à l'AS-REQ, puis il est effacé ; les tickets restent en mémoire, le temps de la session. Le secret reste au Vault (invariant « secrets jamais dans le control plane »).
4. **Ordre** : Kerberos d'abord quand le compte a un royaume, NTLMv2 sinon. Aucun repli silencieux de Kerberos vers NTLM sur un compte qui demande Kerberos.
5. **Preuve** : un domaine en CI. Un contrôleur Samba AD en conteneur, avec la cible Windows jointe au domaine et NTLM interdit par stratégie. C'est une cible Windows de plus en CI.

## Ce qui demande ton go

- la nouvelle dépendance gokrb5, après la revue de la policy ;
- le domaine de test en CI (Samba AD et une cible jointe) ;
- les champs de compte nouveaux au Vault (royaume, KDC) : un ajout au contrat des comptes, additif.

## Conséquences

- (+) Les domaines qui ferment NTLM deviennent joignables, ce qui va dans le sens de leur sécurité.
- (−) Le proxy doit pouvoir joindre les KDC : un flux réseau de plus à ouvrir et à surveiller.
- (−) Une dépendance de cryptographie à suivre (vulnérabilités, mises à jour).

## Alternatives envisagées

- **Carte à puce ou Remote Guard** : écartées pour cet ADR. Remote Guard ne délègue aucun secret, ce qui contredit la saisie du secret par le proxy ; la carte à puce demande un matériel côté proxy.
- **Laisser NTLM rouvert par l'exploitant** : c'est le statu quo, il affaiblit le domaine.

## Mise en œuvre

### Incrément 1 — les tickets, le contexte GSS-API et ses jetons d'enveloppe (20 novembre 2026)

- **Dépendance** : `github.com/go-krb5/krb5` v0.1.0, choisie par le propriétaire le 13 novembre 2026 (« go-krb5/krb5 v0.1.0 »), seule version publiée (15 février 2026), Apache-2.0, épinglée par `go.sum`. Elle tire `go-crypt/x`, `go-krb5/x` et `google/uuid`. `gorilla/sessions`, requis par son module, n'est pas compilé : seuls ses paquets HTTP l'importent, et `pkg/rdp` ne les importe pas. `govulncheck` (v1.9.0) ne trouve aucune vulnérabilité dans le code appelé. Il signale `GO-2026-5932` dans `golang.org/x/crypto` v0.58.0, déjà requis par `main`, non appelé, et sans rapport avec cette dépendance.
- **Fait** (`pkg/rdp/kerberos.go`, non branché à CredSSP) :
  - `KerberosConfig` : le royaume, ses KDC (`host:port`, quatre au plus) et le principal de service `TERMSRV/<hôte>`, vérifiés avant tout envoi. La configuration de la bibliothèque est tirée de là seulement : ni `krb5.conf`, ni découverte DNS, ni canonicalisation du nom d'hôte. Les requêtes passent en TCP, et seul AES est permis (RFC 3962), RC4 et DES étant refusés.
  - les tickets : l'échange AS, puis l'échange TGS, par la bibliothèque. La clé de session doit être AES.
  - le jeton initial : un AP-REQ qui exige l'authentification mutuelle, avec une sous-clé et un numéro de séquence. Sa somme GSS-API (RFC 4121 §4.1.1) demande l'authentification mutuelle, le séquencement, la confidentialité et l'intégrité, jamais la délégation. Le jeton est encadré pour GSS-API (RFC 1964 §1.1) par `pkg/rdp`.
  - l'AP-REP : déchiffré sous la clé de session, il doit répéter l'heure de l'authentificateur à la microseconde. La sous-clé de l'accepteur doit être AES. Un KRB-ERROR est refusé avec son code.
  - les jetons d'enveloppe scellés (RFC 4121 §4.2.6.2), écrits dans `pkg/rdp`, car celui de la bibliothèque ne fait que l'intégrité. Ils utilisent la sous-clé de l'accepteur, sinon celle de l'initiateur. À la lecture : numéros de séquence vérifiés, rotation (RRC) défaite, remplissage (EC) retiré, et l'en-tête chiffré doit être l'en-tête en clair.
- **Trouvé par le fuzzer** : le `DecryptMessage` de la bibliothèque panique sur un chiffré plus court que son HMAC. La longueur est désormais bornée avant tout déchiffrement, et une panique de la bibliothèque devient un refus (`kerberosDecrypt`). L'entrée du corpus est gardée.
- **Le mot de passe** : la bibliothèque le prend comme une chaîne Go, que `pkg/rdp` ne peut pas effacer. C'est la limite déjà connue d'ADR-0115. Le client est détruit dès les tickets obtenus.
- **Prouvé** :
  - sans KDC : un accepteur écrit à part dans le test lit l'AP-REQ et y répond, et les jetons d'enveloppe circulent dans les deux sens, en AES-256 et AES-128, avec ou sans sous-clé de l'accepteur, avec rotation de 28 octets, rotation plus longue que le jeton, et remplissage ;
  - 31 refus, un fuzzer (`FuzzKerberosAcceptReplyAndUnwrap`), et 20 mutations tuées sur 21. La survivante, l'octet de remplissage, est équivalente : l'en-tête chiffré refuse déjà le même jeton.
- **Contre un vrai KDC** (`TestKerberos_AgainstAnMITKDC`, `KERBEROS_INTEROP=1`, MIT krb5 sous Docker, `test/integration/testdata/kerberos/mit-kdc`) :
  - les tickets sont obtenus en TCP, avec la pré-authentification exigée ;
  - un accepteur qui ne détient que la clé du service vérifie le ticket et l'authentificateur avec l'accepteur de la bibliothèque ;
  - les jetons d'enveloppe circulent ;
  - un mauvais mot de passe est refusé à l'échange AS, et un service inconnu à l'échange TGS.
- **Reste** :
  - **incrément 2** : CredSSP choisit Kerberos quand le compte a un royaume, sans aucun repli vers NTLM, et SPNEGO propose Kerberos (avec `mechListMIC` si la cible l'exige) ;
  - **incrément 3** : les champs du compte au Vault (royaume, KDC), qui ajoutent au contrat des comptes ;
  - **incrément 4** : la preuve contre Windows, avec un contrôleur Samba AD en CI, la cible jointe au domaine et NTLM interdit. Cette cible Windows de plus en CI sera soumise au propriétaire à cet incrément, comme l'ADR le prévoit.

### Incrément 2 — CredSSP et SPNEGO avec Kerberos (20 novembre 2026)

- **Fait** (`pkg/rdp`, non branché au service) :
  - `CredSSPClientConfig.Kerberos` : quand elle est posée, l'échange passe par Kerberos (`credssp_kerberos.go`). NTLM n'est alors ni proposé ni envoyé. Un KDC ou une cible qui refuse Kerberos refuse la session, sans aucun repli.
  - le jeton initial : un NegTokenInit qui propose Kerberos 5 seul, avec l'AP-REQ. Ni NTLM, ni l'alias Microsoft de Kerberos ne sont proposés.
  - la réponse de la cible doit nommer Kerberos 5 et porter un AP-REP. Son `mechListMIC`, quand elle en envoie un, est vérifié. Le client répond alors par le sien (RFC 4178 §5), comme il le fait quand la cible demande un MIC ou n'a pas terminé.
  - les jetons MIC de la RFC 4121 (`getMIC`, `verifyMIC`), qui partagent leurs numéros de séquence avec les jetons d'enveloppe, comme la RFC le veut.
  - `pubKeyAuth`, celui de la cible et `authInfo` passent sous le contexte Kerberos. L'échange de liaison de CredSSP est désormais commun aux deux mécanismes, par une petite interface que le contexte NTLM satisfait déjà ; les fonctions exportées gardent leur signature.
  - un refus des identifiants par le KDC (mot de passe faux, compte inconnu, révoqué ou expiré) se dit comme celui de NTLM : `ErrTargetCredentialsRefused`, donc `target_auth_failed` au proxy. La bibliothèque aplatit le KRB-ERROR en texte : le code y est lu (« KRB Error: (24) »), seul endroit qui le garde. Un texte d'une autre forme ne donne pas de code, et le refus reste un refus Kerberos ordinaire.
- **Prouvé** :
  - un faux serveur CredSSP sur TLS épinglé, écrit à part du client. Les MIC de ce serveur sont signés et vérifiés par le code RFC 4121 de la bibliothèque, une implémentation indépendante de la nôtre. L'échange va jusqu'à `authInfo` dans les quatre cas (terminé sans MIC, terminé avec le MIC de la cible, incomplet, MIC demandé) ;
  - six refus : une autre liaison de certificat, NTLM en réponse, pas d'AP-REP, un KRB-ERROR, un MIC forgé, un AP-REP d'une autre heure ;
  - un KDC qui refuse arrête tout avant le moindre octet envoyé à la cible ;
  - 7 mutations tuées sur 10. Les trois survivantes sont équivalentes : le mécanisme annoncé, déjà refusé par l'analyse SPNEGO restreinte à Kerberos ; un AP-REP vide, déjà refusé par la lecture du cadre GSS-API ; et une mutation mal écrite, qui appelait encore la vérification.
  - contre le KDC MIT, qui exige désormais la pré-authentification comme Active Directory, un mauvais mot de passe donne `KDC_ERR_PREAUTH_FAILED` (24), et un utilisateur inconnu `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6). Les deux sont des identifiants refusés.
  - **l'échange CredSSP complet avec de vrais tickets** (`TestCredSSPKerberos_AgainstAnMITKDC`, `KERBEROS_INTEROP=1`) : le client obtient ses tickets du KDC MIT, et le serveur CredSSP du test lit l'AP-REQ avec la seule clé du service, comme Windows. L'échange va jusqu'à `authInfo`, avec et sans le MIC de la cible. Un mauvais mot de passe s'arrête au KDC, sans un octet vers la cible, en identifiants refusés.
- **Corrigé en chemin** : le KDC de test n'exigeait pas la pré-authentification. Dans `kadmin`, `-requires_preauth` retire l'attribut ; c'est `+requires_preauth` qui le pose.
- **Non éprouvé** : contre Windows. Ce qu'un contrôleur de domaine réel envoie (MIC ou non, rotation des jetons, alias Microsoft de Kerberos) se mesurera à l'incrément 4.
- **Reste** : les champs du compte au Vault (incrément 3), puis Windows dans un domaine Samba AD en CI (incrément 4).

### Incrément 3 — le royaume et les KDC du compte, du Vault au proxy (20 novembre 2026)

- **Décidé en autonomie, renversable** (l'ADR laissait « les champs de compte du Vault à confirmer à leur incrément ») :
  - deux champs seulement, le royaume et un à quatre KDC, dans une colonne `kerberos JSONB` (`010_kerberos.sql`) ; NULL veut dire NTLMv2, comme avant ;
  - **le principal de service n'est pas un champ** : le proxy demande `TERMSRV/<targetDomain>`, le nom épinglé contre lequel le certificat de la cible est vérifié (ADR-0071). Un ticket n'est donc jamais demandé pour un autre hôte que celui qui reçoit le secret. Le prix : un compte Kerberos doit être épinglé à un nom d'hôte, pas à une IP ;
  - le nom d'utilisateur du compte est un nom du royaume, sans `DOMAINE\` ni `@royaume` : `pkg/rdp` refuse ces formes avant de joindre le KDC.
- **Fait** :
  - `PUT /vault/accounts/{id}/kerberos` : à la Gateway, seuls le royaume et les KDC sont pris du client ; au Vault, la politique `vault:account:kerberos` sur `vault:account-admin:{id}`, un refus audité au mieux, des réglages normalisés (royaume en majuscules, KDC en `hôte:port`, 88 par défaut), et un compte RDP actif seulement. **L'audit `vault.kerberos_set` précède le changement, et rien ne change sans lui.** `null` retire les réglages ;
  - un nom épinglé qui est une IP ferme Kerberos à trois endroits : au réglage (`409`), au ré-épinglage d'un compte Kerberos (`409`), et à la remise du secret (`409`, aucun secret). Le proxy refuse aussi la session, en défense en profondeur ;
  - des réglages stockés qui ne se valident plus sont une erreur de lecture, jamais « pas de Kerberos », ce qui enverrait le secret par NTLM ;
  - `fetch-credential` remet le royaume et les KDC avec le secret (`kerberos_realm`, `kerberos_kdcs`) ; `pkg/proxycore` les copie et les efface à la purge ; le proxy pose `CredSSPClientConfig.Kerberos` quand le royaume est là.
- **Prouvé** :
  - le Vault : l'autorisation, l'audit d'abord, l'audit absent, la normalisation, RDP seul, les trois gardes de l'IP, le retrait, le compte désactivé ; la route HTTP de bout en bout (champs inconnus refusés, compte, remise au proxy, retour à NTLM) ; PostgreSQL réel (aller-retour, liste, valeur stockée invalide refusée) ;
  - la Gateway : seuls les champs connus passent, jamais un principal de service, l'auteur et les rôles viennent du jeton ;
  - sur les huit processus réels sous TLS mutuel (`TestMTLS_TheWholeProductOverMutualTLS…`), l'opérateur reçoit `403`, un compte SSH `400`, l'épinglage à une IP `409` dans les deux sens ; l'administrateur règle, relit et revient à NTLM ;
  - le proxy, sur TCP et TLS épinglé réels, face à une cible du test : avec un royaume et un KDC muet, la session échoue sans qu'un seul octet CredSSP atteigne la cible. La contre-épreuve, sans royaume, voit la négociation NTLM arriver à la même cible ;
  - 20 mutations tuées sur 21. La seule survivante a montré une branche redondante dans la lecture d'un KDC, retirée depuis.
- **Pas encore fait** :
  - l'Admin UI n'a pas de formulaire Kerberos : la route s'appelle par l'API ;
  - les échecs Kerberos autres que le refus d'identifiants (KDC injoignable, cible qui refuse le ticket) restent `target_unreachable`. Un code à part toucherait le contrat de l'écran et l'UI.
- **Reste** : l'incrément 4, éprouver Kerberos contre Windows en CI.

### Incrément 4 — Kerberos contre un Windows contrôleur de domaine (20 novembre 2026)

- **Décidé en autonomie, renversable** : l'ADR prévoyait un Samba AD et un Windows joint, « à confirmer à son incrément ». J'ai choisi de faire du Windows du test d'interopérabilité (dockur, ADR-0071) **son propre contrôleur de domaine**, `openbastion.test`. Ainsi le KDC qui délivre les tickets est celui de Microsoft, et il n'y a ni image de plus ni réseau entre conteneurs. Samba reste possible pour éprouver un KDC qui ne soit pas de Microsoft.
- **Fait** (`test/integration/testdata/rdp/windows`, `prepare.sh DOMAIN=kerberos`) :
  - `kerberos-dc.ps1` installe le rôle AD DS puis crée la forêt, en toute dernière étape de `rdp-setup.ps1`, car la promotion redémarre Windows ;
  - après ce redémarrage, la tâche de disponibilité exécute `kerberos-ready.ps1` avant d'installer le certificat épinglé, qui signale au test que la cible est prête. Il crée un utilisateur du domaine avec ses clés AES : un compte venu de la base locale à la promotion n'a que son empreinte NT, et le client ne demande que AES. Il pose aussi `TERMSRV/rdp-windows.test` sur la machine et refuse le NTLM entrant (`RestrictReceivingNTLMTraffic` à 2), comme un domaine qui l'a fermé ;
  - `docker-compose.kerberos.yml` publie le KDC (88/tcp) sur la boucle locale, et dockur le relaie à la machine virtuelle ;
  - un job à part dans `windows-rdp.yml` vérifie d'abord la syntaxe PowerShell. Les cinq cibles existantes ne changent pas.
- **Prouvé en CI** (`TestRDPWindowsKerberos`, PR #253) :
  - Windows accepte l'échange CredSSP en Kerberos seul, avec des tickets de son propre KDC ;
  - **le proxy entier** : le credential porte le royaume et le KDC, le ticket est demandé pour le nom épinglé, et **la session de l'utilisateur s'ouvre** (Windows dit qu'il l'a ouverte, 1280×800) ;
  - **contre-épreuve** : la même cible refuse le même utilisateur en NTLM (`0x80090302`, `SEC_E_UNSUPPORTED_FUNCTION`). La session ouverte au point précédent a donc bien été faite par Kerberos ;
  - un mauvais mot de passe s'arrête au KDC (code 24) et ressort en `target_auth_failed`.
- **Constaté en chemin** : le partage invité de dockur continue de fonctionner une fois la machine promue, et les journaux arrivent. Le test n'en dépend pas pour savoir si la cible est prête.
- **ADR-0100 est mise en œuvre.** Reste hors de son périmètre un code d'échec à part pour un KDC injoignable ou un ticket refusé, aujourd'hui `target_unreachable`.

### L'Admin UI : le bouton « Kerberos » d'un compte RDP (21 novembre 2026)

- **Fait** :
  - le bouton « Kerberos » apparaît sur un compte RDP seulement, grisé sans la capacité `accounts.kerberos` (préfixe `vault:account-admin:`, action `vault:account:kerberos`, calculée par la Gateway comme `accounts.screenProfile`). Il affiche le royaume quand Kerberos est posé ;
  - le dialogue demande le royaume, mis en majuscules, et un à quatre KDC, un par ligne. Il montre le nom pour lequel le ticket sera demandé (`TERMSRV/<nom épinglé>`) et propose « Revenir à NTLM » quand Kerberos est posé ;
  - il dit avant tout envoi ce que le Vault refuserait : pas de royaume, pas de KDC ou plus de quatre, un KDC donné deux fois, une cible épinglée à une IP, un utilisateur `DOMAINE\` ou `@royaume`. Le Vault reste l'autorité : un refus de sa part s'affiche dans le dialogue ;
  - `docs/administration/privileged-accounts.md` décrit le réglage, ses prérequis (nom épinglé, utilisateur du royaume, KDC joignables en TCP, AES) et ce que voit l'opérateur.
- **Prouvé** : trois tests du parcours (le bouton n'apparaît que sur RDP, l'envoi correspond au formulaire, le retour à NTLM envoie `null`, le `409` du Vault reste dans le dialogue), et quatre mutations tuées (RDP seul, majuscules, IP, retour à NTLM). Les 297 tests de l'UI et la capacité de la Gateway passent.
- **Non éprouvé** : dans un navigateur réel contre la pile. Le chemin de l'API derrière ce dialogue est celui des incréments 3 et 4.

