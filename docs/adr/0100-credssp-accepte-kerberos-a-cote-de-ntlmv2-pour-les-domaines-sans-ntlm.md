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

