# ADR-0100 — CredSSP accepte Kerberos à côté de NTLMv2, pour les domaines qui ferment NTLM

**Statut** `Proposé` · 13 novembre 2026 · demandé par le propriétaire du projet le 13 novembre 2026 (« ADR proposés d'abord ») pour l'écart « authentification » d'ADR-0071 (ADR-0090, lot E, point 5). `Accepté` seulement avec son go, cité avec sa date.

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
