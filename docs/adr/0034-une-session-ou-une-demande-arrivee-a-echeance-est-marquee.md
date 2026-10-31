# ADR-0034 — Une session ou une demande arrivée à échéance est marquée expirée, une fois, et l'expiration est écrite dans la trace


**Contexte**
Le Scheduler du MVP n'a qu'une tâche : l'expiration des sessions (`docs/roadmap.md` §2). Aujourd'hui l'expiration est **paresseuse** : `Session.EffectiveStatus` répond `expired` quand on lit une session passée son échéance, et le proxy coupe une connexion ouverte à l'échéance en écrivant `session.expire` (ADR-0009). Ce qui manque, mesuré sur un vrai Broker et une vraie PostgreSQL (rouge avant) :

- **une session accordée mais jamais connectée, ou une demande break-glass restée sans décision, expire sans aucune trace** — ni événement, ni changement en base (déjà noté comme limite d'ADR-0011 : « l'expiration d'une demande en attente n'est pas auditée ») ;
- **en base, son statut reste `active` ou `pending_approval` pour toujours** : la base dit le contraire de ce que le Broker répond.

**Décision** *(acceptée sur la consigne de Bony Kiss du 30 octobre 2026 de continuer l'implémentation du MVP ; renversable)*
1. **Le Broker balaie** les sessions échues, toutes les `SESSION_EXPIRY_SWEEP_SECONDS` (**30** par défaut, de 1 à 3600, hors bornes fatal), sans interrupteur : une échéance est un fait, pas une option.
2. **Une seule étape atomique par session** : `UPDATE … SET status = 'expired' WHERE id IN (SELECT … WHERE status IN ('active', 'pending_approval') AND expires_at < now … FOR UPDATE SKIP LOCKED) RETURNING …`. Une session expire **une fois**, quel que soit le réplica qui balaie ; une décision ou une terminaison concurrente gagne ou perd son comparer-échanger, jamais les deux.
3. **L'expiration est un événement** `session.expire`, `resource_type = session`, acteur vide (action du système), écrit par le Broker (son émetteur le dit, ADR-0027) — à côté de celui du proxy, qui dit qu'une connexion a été coupée.
4. **Écrit au moins une fois** : la ligne expirée porte `expiry_audited = false` jusqu'à ce que l'événement soit accepté. Un audit en panne laisse la ligne à écrire : le processus qui l'a expirée la réessaie **dès son balayage suivant** ; une ligne qu'un réplica arrêté a laissée est reprise par n'importe quel balayage après `ExpiryAuditGrace` (**30 s**, plus long qu'un balayage, borné à 10 s : pour ne pas doubler ce qu'un réplica écrit à l'instant). Une panne entre l'événement et la marque peut le doubler : c'est voulu plutôt que de le perdre.

   *Note d'implémentation* : le texte proposé disait « reprise après une minute » pour toutes ; un audit revenu aurait attendu une minute pour des expirations que le processus lui-même retenait — d'où les deux chemins.
5. **Le schéma change par une migration numérotée** (ADR-0030) : `002_session_expiry.sql` ajoute `expired_at`, `expiry_audited` et un index partiel des expirations à écrire.
6. **Rien ne change pour un client** : la réponse `expired` était déjà celle de `EffectiveStatus` ; elle est maintenant aussi en base.

**Conséquences**
- (+) **Mesuré** : avant (rouge, vrai Broker, vraie PostgreSQL), la variable était ignorée, une session accordée jamais connectée et une demande jamais décidée restaient `active` et `pending_approval` en base, aucun `session.expire`. Après : toutes deux `expired` en moins d'une seconde ; l'audit coupé, les deux expirations attendent (`expiry_audited = false`) puis sont écrites une fois à son retour, sans acteur ; les sessions en cours, terminées ou refusées restent telles quelles ; deux Brokers qui balaient ensemble 40 sessions les expirent et les écrivent **une fois chacune** (et, au niveau du magasin, huit balayeurs sur deux connexions, 300 sessions, une fois chacune). **12 mutations, 12 tuées.** Deux défauts trouvés par les tests avant de livrer : `RETURNING` ne rend pas les lignes dans l'ordre (trié par une CTE) ; un service construit sans horloge faisait planter le balayage (`s.now` nil → `s.clock()`).
- (+) Chaque expiration est dans la trace, une demande break-glass oubliée comprise.
- (+) La base dit ce que le Broker répond.
- (−) La trace peut porter deux fois la même expiration (panne entre l'écriture et la marque).
- (−) L'expiration d'une demande n'est toujours notifiée à personne (le webhook d'ADR-0012 ne part pas).
- (−) Entre l'échéance et le balayage (30 s au plus par défaut), la base dit encore `active` ; le Broker, lui, répond déjà `expired`.

**Alternatives envisagées**
- **Un service Scheduler à part** : `docs/architecture/system-overview.md` le prévoit ; pour une seule tâche qui touche les seules lignes du Broker, un processus de plus et un appel réseau de plus n'apportent rien — il viendra avec les rotations planifiées.
- **Écrire l'événement puis marquer** (audit d'abord) : deux réplicas écriraient chacun l'expiration de la même session.
- **Expirer à la lecture** (écrire en base dans `Get`) : une session que personne ne relit n'expirerait jamais.
