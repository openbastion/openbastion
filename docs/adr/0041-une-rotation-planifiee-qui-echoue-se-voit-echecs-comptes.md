# ADR-0041 — Une rotation planifiée qui échoue se voit : échecs comptés, alerte à l'audit ; et elle peut être tenue dans une fenêtre horaire


**Contexte**
Depuis ADR-0040, un compte `scheduled` échu est tourné par le Vault ; s'il échoue (cible injoignable, compte de réconciliation qui ne se connecte plus, clé d'hôte changée), le Vault retente chaque heure, **sans que personne le sache** autrement qu'en lisant son journal : le secret vieillit en silence, contre la politique que l'exploitant a choisie. Et une rotation peut tomber en pleine journée de travail.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 — « Go pour la prochaine étape » : alerte après plusieurs échecs et fenêtres horaires ; la forme est renversable)*
1. **Chaque compte compte ses échecs consécutifs** de rotation planifiée (`rotation_failures`, migration `005_rotation_failures.sql`). Toute rotation réussie — planifiée, manuelle ou après usage — le remet à zéro.
2. **L'alerte est un événement d'audit** : `vault.rotation_overdue` (acteur système, échec), écrit au N-ième échec consécutif puis tous les N échecs (`ROTATION_ALERT_AFTER_FAILURES`, 3 par défaut, de 1 à 100). L'audit est ce que lit un SIEM ; le rappel tous les N échecs rattrape une alerte perdue si l'audit était coupé à ce moment-là.
3. **La réponse d'un compte** dit `rotationFailures` ; l'Admin UI montre un compte en échec.
4. **Une fenêtre horaire**, une pour la plateforme, en UTC : `ROTATION_WINDOW_UTC=HH:MM-HH:MM` (elle peut passer minuit). Hors de la fenêtre, le balayage ne prend aucun compte ; un compte échu attend la fenêtre suivante. Absente : à toute heure (comportement d'ADR-0040) ; mal formée, ou de durée nulle : le Vault refuse de démarrer. Une rotation demandée par un administrateur n'est pas tenue par la fenêtre.

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `cc081f7`, processus réels et vraie base) : le Vault démarrait avec une fenêtre illisible ; hors de sa fenêtre, il prenait et tournait les deux comptes échus ; un compte dont la cible ne répond pas ne laissait aucune alerte.
- (+) **Mesuré, après** :
  - une fenêtre illisible, de durée nulle, ou un seuil de 0 : le Vault refuse de démarrer, en nommant la variable ;
  - hors de sa fenêtre, aucun compte n'est pris, si en retard soit-il ; un Vault dont la fenêtre est maintenant tourne le compte échu ;
  - un compte dont la cible ne répond pas compte un échec et écrit `vault.rotation_overdue` (acteur système) ; sa réponse dit `rotationFailures: 1`.
- (+) **Mesuré en unitaire et sur PostgreSQL** :
  - lecture des fenêtres, passage de minuit, bornes (début inclus, fin exclue), comparaison en UTC quelle que soit la zone de l'heure donnée ;
  - une alerte au N-ième échec, aucune entre deux, une perdue (audit coupé) rattrapée au 2N-ième ;
  - une rotation réussie, planifiée ou manuelle, remet le compte à zéro ; le compteur avance d'un `UPDATE` à la fois.
  - **17 mutations, 17 tuées.** Deux survivaient d'abord, et c'étaient mes tests : un exemple de fuseau qui tombait dans la fenêtre dans les deux lectures, et des alertes comptées par sous-chaîne, qui laissaient passer un acteur ajouté.
- (+) Un secret qui vieillit contre sa politique se voit dans l'audit, et dans l'Admin UI (« en échec (N) »).
- (−) Une seule fenêtre pour la plateforme, en UTC ; pas de fenêtre par compte ni de jour de la semaine.
- (−) L'alerte n'est qu'un événement d'audit : il faut un SIEM ou une revue pour la voir. Pas de notification poussée.
- (−) Les comptes échus qui attendent la fenêtre s'y accumulent : 20 par passage, au rythme du balayage.

**Alternatives envisagées**
- **Un webhook d'alerte** (comme la notification du break-glass, ADR-0012) : un canal de plus à sécuriser ; l'audit est déjà le registre que surveille un SIEM.
- **Une fenêtre par compte** : plus fine, mais un champ de plus à l'API et à l'UI pour un besoin que l'exploitant exprime d'abord à l'échelle de la plateforme.
- **Arrêter de retenter après N échecs** : le secret vieillirait plus encore ; on alerte et on continue.
