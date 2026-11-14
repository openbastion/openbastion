# ADR-0106 — Les agents sont isolés et fonctionnent avec des privilèges minimaux

**Statut** Proposé · 14 novembre 2026

**Contexte**

Network Agent ouvre des sockets vers les cibles ; Security Agent lit des événements système. Les exécuter sous root/SYSTEM donnerait à une vulnérabilité réseau des droits de collecte et d'administration. Aucun agent ne doit devenir un exécuteur de commandes.

**Décision**

1. Network Agent et Security Agent sont des processus distincts, avec comptes, répertoires, clés privées, sockets IPC et profils de confinement séparés.
2. Network Agent n'exige pas root permanent pour des connexions TCP sortantes et ne peut ni administrer l'hôte ni exécuter des processus.
3. Security Agent est en lecture seule. Un collecteur privilégié éventuel est isolé dans un helper étroit, à opérations typées et fermées, sans primitive d'exécution générique.
4. Linux : utilisateur dédié, NoNewPrivileges, capacités supprimées par défaut, seccomp, AppArmor/SELinux si disponibles, système de fichiers en lecture seule hors état nécessaire et limites de ressources.
5. Windows : service dédié, compte à privilèges minimaux, ACL strictes, protection des clés par DPAPI ou magasin adapté, signature des exécutables ; les privilèges sont documentés par collecteur.
6. IPC local authentifié par permissions OS et identité du pair lorsque disponible ; aucun listener local non authentifié.
7. Une mise à jour ne peut élargir les privilèges sans nouvelle version signée et validation explicite.
8. Toute fonction exigeant root/SYSTEM intégral est hors périmètre sans justification et ADR distinct.

**Conséquences**

- (+) Une compromission d'un processus ne donne pas automatiquement les droits de l'autre.
- (+) Permissions et manifests sont testables.
- (−) Les collecteurs Linux et Windows ont des besoins différents.
- (−) Certaines sources système nécessitent des helpers privilégiés.
- (−) Un administrateur root/SYSTEM hostile reste hors protection.

**Alternatives envisagées**

- **Service unique root/SYSTEM** : rejeté, rayon d'impact excessif.
- **Commandes distantes arbitraires** : rejetées, canal RCE.
- **Collecte non privilégiée seulement** : insuffisante pour certaines sources ; préférer des helpers bornés.