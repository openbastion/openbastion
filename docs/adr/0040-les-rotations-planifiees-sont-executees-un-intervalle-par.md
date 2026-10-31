# ADR-0040 — Les rotations planifiées sont exécutées : un intervalle par compte, un balayage du Vault, une prise par compare-échange


**Contexte**
`rotationPolicy: scheduled` est accepté à l'enregistrement depuis le MVP, mais **rien ne l'exécute** (ADR-0037, limite écrite) : un compte réglé ainsi ne change jamais de mot de passe, alors que l'exploitant croit le contraire. Le Scheduler complet de la feuille de route n'existe pas ; la rotation, elle, existe (ADR-0037) et tient déjà ses garanties : réconciliation, version en attente, vérification, clé d'hôte épinglée (ADR-0039), audit avant de toucher la cible.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — exécuter les rotations planifiées, c'est sa demande ; le reste est renversable)*
1. **Un intervalle par compte** : `rotationIntervalDays`, de 1 à 365.
   - Il est **obligatoire** pour `scheduled`, et **refusé** pour les autres politiques (`400`) : un intervalle qu'aucune politique n'exécute serait une promesse vide.
   - Un compte `scheduled` doit nommer son compte de réconciliation dès l'enregistrement (`409` sinon) : sans lui, il ne tournerait jamais.
2. **Les comptes `scheduled` d'avant cette décision** reçoivent 30 jours à la migration (`004_rotation_schedule.sql`). Ils commencent donc à tourner après la mise à jour : c'est ce que leur politique promettait.
3. **Échéance** : dernière rotation, ou création si le compte n'a jamais tourné, plus l'intervalle. Un compte désactivé n'est pas concerné.
4. **Le Vault balaie** toutes les `ROTATION_SWEEP_SECONDS` (300 par défaut, de 1 à 86 400, hors bornes fatal, sans interrupteur). À chaque passage, il prend au plus 20 comptes échus, les plus en retard d'abord, et les tourne **un par un**, par le même chemin qu'une rotation après usage : action du système (acteur vide), `vault.rotate_requested` écrit avant de toucher la cible, `vault.rotate` après.
5. **Une prise par compare-échange** avant chaque rotation (`rotation_attempted_at`) : entre réplicas du Vault, un seul tente un compte donné. Un compte tenté — réussi ou non — n'est **pas** retenté avant une heure : une cible en panne ou un compte mal configuré ne sont pas martelés à chaque balayage, et l'audit n'est pas inondé.
6. **La réponse d'un compte** dit `rotationIntervalDays` et `nextRotationAt` ; l'Admin UI les montre.

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `8d76787`, vraie base PostgreSQL et vraie cible SSH) : un compte `scheduled` en retard de deux jours ne tourne pas — quinze secondes plus tard, la cible a toujours son mot de passe.
- (+) **Mesuré, après**, deux Vaults réels sur la même base, balayage chaque seconde :
  - un compte qui n'est pas échu ne tourne pas ;
  - échu, il tourne **une fois** à travers les deux Vaults (une demande, une rotation à l'audit) : sur la cible, l'ancien mot de passe ne l'ouvre plus, et le Vault injecte ce que la cible prend ;
  - l'audit l'attribue au système (acteur vide) ;
  - un compte manuel aussi ancien, à côté, n'est pas touché.
- (+) **Mesuré en unitaire et sur PostgreSQL** :
  - intervalle absent, nul, négatif ou supérieur à 365 jours : refusé ; intervalle sur une autre politique : refusé ; `scheduled` sans réconciliation : refusé, et rien n'est enregistré ;
  - un compte désactivé, manuel ou après usage ne tourne pas ; un échec n'est pas retenté avant une heure, puis l'est ;
  - sans audit, la cible n'est pas touchée ; deux Vaults au même instant : une seule rotation (`-race` propre) ;
  - ordre du plus en retard ; prise unique ; un compte qui vient de tourner n'est plus échu ;
  - la migration donne 30 jours à un compte `scheduled` d'avant, et rien aux autres.
  - **19 mutations, 19 tuées.** Deux survivaient au départ : une mutation mal écrite (la prise avait lieu avant que je la force), réécrite ; et « l'échéance ignore la dernière rotation », que seul le SQL couvrait : un test du domaine le couvre maintenant.
- (+) Un compte `scheduled` tient enfin sa promesse, par le même chemin, et donc les mêmes garanties, qu'une rotation manuelle.
- (+) L'enregistrement écrit maintenant le compte **en une fois** — clé d'hôte, réconciliation et intervalle compris —, ce qui referme la limite des deux écritures d'ADR-0039.
- (−) ~~La cadence est en jours, sans heure ni fenêtre : un compte peut tourner en pleine journée de travail.~~ Refermé par ADR-0041 (`ROTATION_WINDOW_UTC`). La session ouverte à ce moment garde sa connexion ; la suivante reçoit le nouveau secret.
- (−) Les comptes `scheduled` d'avant ADR-0040 tournent **dès la mise à jour** s'ils ont plus de 30 jours (20 par passage).
- (−) ~~Un compte qui échoue est retenté toutes les heures, sans limite ni alerte autre que le journal et l'événement `vault.rotate` en échec ; un compte sans réconciliation ou sans clé ne laisse qu'une ligne de journal par heure, pas d'événement d'audit.~~ Refermé par ADR-0041 : les échecs sont comptés et `vault.rotation_overdue` est écrit tous les N échecs, y compris pour un compte sans réconciliation ou sans clé.
- (−) Les comptes d'un passage tournent un par un : beaucoup de comptes échus en même temps s'étalent sur plusieurs passages.
- (−) Il n'y a ni modification de la politique ni de l'intervalle d'un compte existant par l'API, comme avant pour la politique.

**Alternatives envisagées**
- **Un Scheduler séparé** (`docs/roadmap.md`) : un service de plus, avec son identité et ses appels au Vault, pour une seule tâche. Il viendra avec la feuille de route ; le balayage du Vault suffit à tenir la promesse aujourd'hui.
- **Un intervalle global** pour tous les comptes : simple, mais un compte de base de données et un compte `root` n'ont pas la même cadence.
- **Une expression cron par compte** : plus riche, mais un analyseur à écrire ou une dépendance, pour un besoin qu'un intervalle couvre.
- **Retenter à chaque balayage** : une cible arrêtée recevrait une tentative toutes les cinq minutes, chacune écrite à l'audit.
