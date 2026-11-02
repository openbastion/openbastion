# ADR-0071 — Le moteur RDP utilise FreeRDP via cgo

**Statut** `Accepté` · 2 novembre 2026

## Contexte

ADR-0069 exige un proxy qui termine séparément les connexions RDP côté opérateur et côté cible, impose NLA/CredSSP, vérifie l'empreinte du certificat TLS de la cible avant d'envoyer le mot de passe Vault et capture l'affichage pour le Video Recorder. Le relais d'octets `pkg/proxycore.Codec` ne peut pas, seul, remplir ces fonctions.

L'utilisateur a choisi FreeRDP via cgo et confirmé que l'implémentation doit rester dans le périmètre d'ADR-0069. FreeRDP fournit une API client et une API peer serveur, est sous AGPL-3.0 et peut être lié au projet sans importer de code des clients Go évalués précédemment. Le binding doit néanmoins enfermer ses états et ses allocations natives derrière une API Go étroite.

## Décision

1. **`pkg/rdp` est un binding Go de FreeRDP 3.x par cgo.** Le code C d'adaptation reste original et minimal ; il n'embarque ni ne copie le code de clients RDP tiers. Les constructions qui activent ce package exigent les en-têtes et bibliothèques FreeRDP correspondants. La version native est épinglée dans la chaîne de construction et documentée.
2. **Le moteur termine les deux connexions RDP.** L'extrémité cliente utilise l'API peer serveur de FreeRDP et l'extrémité cible son API cliente. `pkg/proxycore` conserve l'admission, l'expiration, la révocation, l'audit et la purge du credential ; le binding natif n'accorde aucune session et ne lit aucun secret hors de celui remis au proxy par le Vault.
3. **La connexion vers la cible exige NLA/CredSSP.** TLS 1.2 est le minimum. Le binding n'active ni l'authentification RDP historique ni le repli TLS seul. Si la cible ne négocie pas NLA, la connexion échoue fermée.
4. **Le certificat cible est vérifié dans le callback TLS du client FreeRDP.** Le binding calcule SHA-256 sur le DER du certificat feuille et compare en temps constant l'empreinte attendue, reçue avec le credential du Vault. Une empreinte absente, mal formée ou différente refuse la connexion avant l'authentification CredSSP ; ni l'autorité système ni la confiance au premier usage ne remplacent l'épinglage.
5. **Le flux graphique est converti en images PNG et acquitté par le Video Recorder avant d'être transmis à l'opérateur.** Une panne, un délai dépassé ou un acquittement ambigu ferme la session. Le moteur ne tamponne pas les images sur disque et ne continue pas en mode best-effort (ADR-0008 et ADR-0070).
6. **Les canaux secondaires sont désactivés.** Presse-papiers, audio, lecteurs, imprimantes, cartes à puce et autres canaux virtuels ne sont pas négociés. Les événements clavier/souris ne sont pas ajoutés à l'enregistrement visuel. VNC, client WASM et interface utilisateur sont hors de cet ADR.
7. **Les appels natifs respectent l'annulation et les échéances.** L'arrêt ferme les deux connexions, arrête les callbacks et libère chaque contexte natif. Aucun pointeur Go ne peut être retenu par FreeRDP ; les buffers de frames et les données de credential copiés en mémoire native ont une durée bornée et sont nettoyés après usage.
8. **Cet ADR couvre le moteur `pkg/rdp`, pas le service proxy complet.** Le routage, le contrat d'attachement à usage unique du client, l'extension du Vault pour le pin TLS et le déploiement d'un binaire utilisant FreeRDP restent des incréments requis avant d'exposer des sessions RDP.

## Conséquences

- (+) Le choix demandé est compatible avec la licence AGPL-3.0 du projet et fournit les rôles client et serveur nécessaires à une terminaison RDP.
- (+) Les contrôles de pin TLS, de NLA sans repli, d'annulation et d'enregistrement peuvent être exercés derrière une API Go testable.
- (−) Cette décision ne constitue pas un proxy RDP opérationnel de bout en bout ; le service, le contrat d'attachement, les métadonnées Vault et le déploiement restent à implémenter.
- (−) cgo impose un compilateur C, les headers FreeRDP et des bibliothèques natives compatibles à la construction. Tout binaire qui lie le moteur devra aussi embarquer les bibliothèques d'exécution FreeRDP ; l'image distroless statique actuelle ne suffit pas sans évolution.
- (−) FreeRDP ajoute une surface native C, des contraintes d'ABI et de maintenance. Les tests Go seuls ne prouvent pas l'absence de corruption mémoire ; les tests sous `-race` ne détectent pas toutes les erreurs natives.
- (−) La connexion RDP entrante, le lecteur vidéo UI, l'audio, le presse-papiers, VNC et les autres canaux restent indisponibles.
- (−) Aucune mesure de latence, de débit, de mémoire ou de compatibilité avec des serveurs Windows réels n'est revendiquée par cette décision.
- (−) L'empreinte épinglée bloque les renouvellements de certificats jusqu'à un nouvel épinglage autorisé dans le Vault.

## Alternatives envisagées

- **Un client RDP Go seul** : écarté ; il ne termine pas le côté client du proxy et ne fournit pas, à lui seul, l'admission et l'enregistrement requis.
- **Un relais TCP transparent** : écarté ; il ne vérifie pas l'identité TLS de la cible avant CredSSP et ne permet pas de capturer les images décodées.
- **Une liaison FreeRDP uniquement côté client** : écartée ; le proxy doit aussi terminer la connexion RDP côté opérateur.
- **Réimplémenter le protocole en Go** : écarté au profit de la bibliothèque native explicitement choisie par l'utilisateur ; la surface de protocole et de cryptographie serait autrement réécrite dans le projet.
- **Autoriser les modes TLS seul ou RDP historique pour compatibilité** : écarté ; ils contredisent ADR-0069.
- **Activer les canaux secondaires** : écarté ; ils restent interdits jusqu'à une décision précisant leur enregistrement, leur protection et leur audit.
- **Intégrer VNC ou le client WASM** : écarté ; VNC est hors d'ADR-0069 et le WASM relève d'un éventuel client distinct.
