# ADR-0044 — Une rotation après usage est une dette enregistrée, réglée jusqu'au bout : le Broker la remet, le Vault la paie


**Contexte**
Depuis ADR-0037, quand une session accordée se termine, le Broker prévient le Vault, qui fait tourner le secret d'un compte `post_use`. Deux pertes possibles, aucune vue :
- le Broker prévient dans une goroutine ; un Vault injoignable à ce moment, ou un redémarrage du Broker, et la demande est perdue ;
- le Vault reçoit la demande, mais la rotation échoue (cible injoignable…) : rien ne la réessaie.
Dans les deux cas, le secret qu'un humain vient d'utiliser reste en place jusqu'à la session suivante, sans alerte.

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « Go pour la prochaine étape » : réessayer une rotation après usage échouée ; la forme est renversable)*
1. **Le Broker enregistre ce qu'il doit dire** : la fin d'une session **active** (terminaison ou expiration) écrit `after_use_owed` dans la même écriture que la fin. La tentative immédiate efface la marque si le Vault l'a reçue ; sinon, le balayage du Broker (celui d'ADR-0034) la renvoie, pour les sessions finies depuis plus d'une minute, jusqu'à ce que le Vault réponde. Un compte que le Vault n'a pas (`404`) n'est rien dû.
2. **La demande porte l'heure de fin de la session** (`endedAt`) : un compte déjà tourné depuis ne doit rien. Une demande répétée — deux Broker, un renvoi — ne fait pas tourner deux fois.
3. **Le Vault enregistre la dette avant de la payer** : `rotation_owed_since` (migration `006_rotation_owed.sql`), puis il prend le compte (compare-échange d'ADR-0040) et tente la rotation. Il répond « reçu » que la rotation ait réussi ou non : c'est désormais à lui de la finir. Toute rotation réussie efface la dette.
4. **Le balayage du Vault paie les dettes** comme les échéances planifiées : même prise, même délai d'une heure avant un nouvel essai, mêmes échecs comptés et même alerte (`vault.rotation_overdue`, ADR-0041). **Hors de la fenêtre horaire aussi** : la fenêtre ne tient que les rotations planifiées ; un secret qu'un humain vient d'utiliser n'attend pas la nuit.
5. **La réponse d'un compte** dit `rotationOwedSince` ; l'Admin UI montre « renouvellement dû ».

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `3e2acd4`, processus réels et vraie base) : le Vault arrêté au moment où une session `post_use` se termine, puis relancé — 90 secondes plus tard, la demande était perdue, et le mot de passe utilisé pendant la session ouvrait toujours la cible.
- (+) **Mesuré, après** (même scénario) : le Broker renvoie la demande une fois le Vault revenu ; le Vault fait tourner le secret sur la cible ; l'ancien mot de passe ne l'ouvre plus ; **une** rotation, au nom du système, bien que le Broker puisse la renvoyer.
- (+) **Mesuré en unitaire et sur PostgreSQL** :
  - Vault : une rotation refusée par la cible laisse la dette, compte l'échec, et le balayage la paie après l'heure ; la même demande deux fois ne fait tourner qu'une fois, une session plus tardive à nouveau ; une dette est payée hors de la fenêtre horaire ; la date la plus ancienne est gardée ; une **nouvelle** dette lève le délai d'une tentative passée, une dette qui échoue le garde ;
  - Broker : une terminaison et une expiration d'une session active écrivent la dette, une demande jamais accordée non ; elle n'est renvoyée qu'après une minute, avec la fin de la session, jusqu'à ce que le Vault réponde `200` (ou `404`), puis plus jamais ;
  - **20 mutations, 20 tuées.** Une survivait d'abord (« la base garde la dernière date, pas la plus ancienne ») : mon test enregistrait la date tardive avant l'ancienne ; l'ordre est inversé.
- (+) **Trouvé en écrivant les tests** : la dette d'une seconde session finie moins d'une heure après une rotation attendait l'heure de délai prévue pour les échecs. Une nouvelle dette lève désormais ce délai.
- (−) Un compte en panne est retenté toutes les heures (ADR-0041) : un secret utilisé reste en place jusqu'au retour de la cible. C'est visible (« renouvellement dû », `vault.rotation_overdue`), pas résolu.
- (−) Le Vault fait tourner le secret avant de répondre au Broker : un renvoi peut attendre la cible (60 s au plus par demande).
- (−) Une session break-glass accordée sous l'ancien régime à une personne (sans décideur) est désormais tournée après usage : elle a servi.

**Alternatives envisagées**
- **Réessayer dans le Broker seul** : le Broker ne sait pas si une rotation a échoué sur la cible ; c'est le Vault qui le sait.
- **File de messages** entre Broker et Vault : une dépendance et un service de plus, pour ce qu'une colonne et un balayage tiennent.
- **Rendre la rotation synchrone de la fin de session** : terminer une session attendrait une connexion SSH à la cible, et échouerait avec elle.
