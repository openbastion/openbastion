# Backlog — priorités par domaine

Le backlog est organisé en trois axes. Les risques de sécurité sont distingués des limitations acceptées et des travaux produit/protocolaires. La source détaillée des preuves et limites reste `NOTES_SANDBOX.md`, `docs/security/known-limitations.md` et les ADR cités.

## 1. Sécurité bloquante

### 1.1 À corriger avant généralisation de l'injection

| Priorité | Sujet | État vérifié | Prochaine action |
|---|---|---|---|
| ~~P1 — bloquant~~ | ~~**SI-02 — révocation/fin de session concurrente à une frappe** (ADR-0097)~~ | **Clôturé** : CI #987, run `45153071885`, job PostgreSQL 16 PASS ; TigerVNC réel, oracle X11, intégration avec base et arrêt de la cible PASS. | Aucune action SI-02 restante dans cette PR ; conserver la preuve dans l’historique CI et `NOTES_SANDBOX.md`. |

### 1.2 Risques traités, preuves livrées et limites résiduelles

| Sujet | État au 22 novembre 2026 | Ce qui reste à respecter |
|---|---|---|
| **SI-03 — résultat ambigu après frappe** (ADR-0112/0113/0119) | Projection cryptographiquement vérifiée, CLI, façade Gateway et panneau Admin UI livrés. Le test multi-processus SSH prouve `outcome_unknown`, une seule frappe et aucun retry. Le parcours PostgreSQL 16 archivage → redémarrage → réconciliation a passé dans la CI de la PR #277 (run `45023573283`). | `failed` et `outcome_unknown` exigent une vérification manuelle de la cible. Aucune réinjection automatique ni retry. `completed` prouve l'audit terminal, pas la réception intégrale par la cible. |
| **ADR-0115 — dumps et copies mémoire** | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` et purge des buffers contrôlés sont livrés pour Vault et proxies Linux. | Les copies Go, GC, TLS, bibliothèques, chaînes immuables, swap et mémoire noyau ne sont pas garanties effaçables. Ne jamais promettre une purge exhaustive ; conserver les limites documentées. |
| **ADR-0116 — intégrité des métadonnées PostgreSQL** | Incréments 1 à 4 livrés : HMAC par ligne, tête indépendante dans l'Audit Service, comparaison à chaque `Get`, refus du rollback, réparation d'une seule révision d'avance, ré-attestation sous la nouvelle clé et rôles PostgreSQL distincts. Le test Compose complet est requis dans la CI et passe dans le run `45023573283`. Le benchmark concurrent mTLS et le profil de blocage local identifient une saturation des pools `database/sql`, principalement celui de l'Audit Service ; essais comparatifs 10/10, 10/20 et 20/20 documentés dans l'ADR et `NOTES_SANDBOX.md`. | Aucun reliquat P0 de rollback ou de rotation identifié. Reste à concevoir des limites de pool configurables par service avec un budget global tenant compte des réplicas, puis à valider ce budget ; défaut 10 conservé, aucune hausse statique retenue. Le benchmark multi-hôtes est différé à la demande de l'utilisateur. Suivi de performance, pas contrôle d'intégrité manquant. |
| **ADR-0133 — mot de passe fourni par l'opérateur** | Parcours VNC et RDP livré. Le navigateur chiffre pour le proxy écran ; la Gateway relaie le chiffré et le Broker ne voit pas le mot de passe. TigerVNC réel et cinq configurations Windows CI passent, dont le clavier `fr-FR` (run Windows RDP `44976798904`). | Risques inhérents acceptés et documentés : une Gateway compromise peut servir une UI hostile avant chiffrement ; une chaîne JavaScript ne peut pas être effacée de façon garantie ; un champ cible visible peut apparaître dans la capture. Garder step-up, jeton à usage unique, avertissement de focus et accès restreint aux replays. |
| **SI-04 — focus distant non masqué** | Limite connue : le proxy ne peut pas vérifier qu'un champ distant est masqué. | Avertissement explicite à chaque saisie ; l'opérateur doit confirmer le focus et le champ cible. Ne pas présenter la saisie comme invisible à l'écran. |
| **SI-01 / SI-07 — compromission d'un service de confiance** | mTLS, identité de service issue du certificat, allowlists par route et autorisations exactes sont en place. | Risque résiduel de compromission d'un service autorisé ; défense en profondeur, durcissement des images, secrets et identités. |
| **SI-06 — rafale MFA et contention de frappe** | Classé P2 dans la revue STRIDE. | Mesurer les temps d'attente du verrou, la durée de frappe et la résistance à une rafale ; ce point ne bloque pas la clôture ADR-0113/ADR-0080. |

## 2. Fonctionnalités produit

### 2.1 À terminer ou à concevoir

| Sujet | État | Prochaine action |
|---|---|---|
| **ADR-0080 — recherche plein texte** | **Terminé côté Admin UI** le 22 novembre 2026 : Historique (`/sessions/search`) et Enregistrements (`/recordings/search`), filtres, pagination, troncature et ouverture du replay. Les tests UI couvrent maintenant ces parcours. | Aucun incrément fonctionnel ouvert. Garder les bornes ADR-0080 : 31 jours, 200 sessions par recherche de commandes, sous-chaîne et déchiffrement à la volée. |
| **ADR-0111 — marqueurs de relecture vidéo** | Contrat et stockage décrits dans la roadmap ; raccordement complet au parcours d'injection et affichage dans la timeline restent à confirmer/livrer sur `main`. | Vérifier le dernier état du code et terminer le raccordement transactionnel et la timeline Admin UI sans exposer le contenu secret. |
| **File d'alertes de session** | L'Admin UI indique explicitement que le contrat API de file, sévérité, compteur non traité et acquittement n'est pas disponible. Aucun compteur fictif n'est affiché. | Définir le contrat API et les règles d'autorisation/audit avant d'implémenter le traitement UI. |
| **Workflow / Approval Engine complet** | L'approbation de session existe, mais le moteur multi-étapes configurable n'est pas livré comme capacité générale. | Concevoir les états, validations N+1/double validation, fenêtre horaire, expiration, justification et intégrations ticketing avant développement. |
| **Reporting, User Portal et moteur de risque/anomalies** | Périmètre de roadmap ultérieur, non livré dans le MVP actuel. | Démarrer par des ADR et des contrats de données/audit ; ne pas présenter ces capacités comme disponibles. |

### 2.2 Historique des incréments produit clôturés

Les lignes ci-dessous sont conservées comme historique de livraison, pas comme tâches ouvertes.

| # | Sujet | Pourquoi | Où c'est écrit |
|---|---|---|---|
| 1 | ~~**Exécuter les rotations `scheduled`**~~ — **fait** (ADR-0040) | ~~acceptées à l'enregistrement, lancées par rien~~ | ADR-0040 |
| 1 bis | ~~Fenêtres horaires et alerte après plusieurs échecs d'une rotation planifiée~~ — **fait** (ADR-0041) | ~~un compte peut tourner en pleine journée ; un échec est retenté chaque heure sans alerte~~ | ADR-0041 |
| 1 ter | ~~Notification poussée des alertes (`vault.rotation_overdue`, …)~~ — **fait** (ADR-0045 ; ~~file durable~~ ADR-0057) | ~~l'alerte n'est visible que dans l'audit~~ | ADR-0045, ADR-0057 |
| 2 | ~~Réessayer une rotation après usage échouée~~ — **fait** (ADR-0044) | ~~un échec laisse l'ancien secret en place jusqu'à la prochaine fin de session~~ | ADR-0044 |
| 3 | ~~Relayer le motif d'un `409` du Vault à l'opérateur~~ — **fait** (ADR-0042) | ~~`connect` dit « authorize-scope: status 409 » sans dire pourquoi~~ | ADR-0042 |
| 3 bis | ~~Revoir les autres routes publiques ; refuser dès `POST /sessions` un compte non épinglé~~ — **fait** (ADR-0043) | ~~les routes d'administration relaient encore le texte des refus d'écriture du Vault~~ | ADR-0043 |
| 4 | ~~Proxy SSH en plusieurs instances~~ — **fait** (ADR-0046) | ~~la révocation n'atteint qu'une instance~~ ; reste : une instance injoignable empêche toute terminaison | ADR-0046 |
| 5 | ~~Pipeline de CI~~ — **fait** (ADR-0047) | ~~aucune porte automatique aujourd'hui~~ ; reste : ~~exiger ses jobs dans la protection de `main`~~ (règle posée, non appliquée sur l'offre gratuite), ~~`govulncheck`/`npm audit`~~ (ADR-0052) | ADR-0047, ADR-0052 |
| 6 | ~~Certificats d'hôte SSH (autorité) à côté de l'épinglage~~ — **fait** (ADR-0048) | ~~une seule clé par compte~~ ; reste : ~~pas de liste de révocation~~ (ADR-0054, par clé), une autorité par compte | ADR-0048, ADR-0054 |
| 7 | ~~Vrai KMS/HSM à la place de `LocalKMS`~~ — **fait** (ADR-0049, Transit d'OpenBao) | ~~la KEK est locale~~ ; reste : ~~renouvellement du jeton~~ (ADR-0053), ~~AppRole~~ (ADR-0058), ~~ré-enveloppement en masse~~ (ADR-0055) | ADR-0049, ADR-0053, ADR-0055, ADR-0058 |
| 8 | ~~gRPC à la place de HTTP/JSON~~ — **écarté** (ADR-0050) : HTTP/JSON sous mTLS décidé, test de contrat ; à rouvrir avec un flux réel, des clients non Go ou une mesure | — | ADR-0050 |
| 9 | ~~Images de base épinglées par empreinte~~ — **fait** (ADR-0051) | ~~reproductible pour le code, pas pour les images~~ ; reste : ~~mise à jour manuelle des empreintes~~ (proposée par Dependabot, ADR-0059, sauf l'image OpenBao des tests) ; images de construction sur Go 1.27.1 depuis le même jour | ADR-0051 |
| 11 | ~~**ADR-0072 accepté — uniformiser les commandes des 12 exécutables** : socle `pkg/buildinfo` / `pkg/command`, CLI opérateur, PKI et dix services migrés vers Cobra ; tests de fumée des douze binaires et intégration des commandes de version dans les gates build/vet/test~~ — **fait** | diagnostic homogène sans initialiser les services ; compatibilité des commandes existantes | ADR-0072 |
| 12 | ~~Ouvrir PostgreSQL avec un délai de connexion qui tient~~ — **fait** : un connecteur lib/pq dans les sept services, 10 s par défaut, le `connect_timeout` du DSN l'emporte | ~~une adresse PostgreSQL qui ne répond pas bloque le démarrage sans fin, malgré le délai de 10 s du `PingContext`~~ (constaté le 12 novembre 2026, NOTES_SANDBOX.md) | — |
| 13 | ~~**ADR-0073 UX-04 — Vue générale et Centre de sécurité** : synthèse des totaux API, contrôles explicites des métadonnées Vault, couverture partielle signalée~~ — **fait** | visibilité opérationnelle sans métriques fictives ni accès hors Gateway ; restent les contrats publics d'audit, d'alertes et de santé des proxies | ADR-0073, `NOTES_SANDBOX.md` |
| 14 | ~~**ADR-0073 UX-05 — Personnalisation** : préférences locales versionnées, favoris de navigation, vues catégorielles de comptes, raccourcis et gestion du focus~~ — **fait** | stockage navigateur sans secrets ni requêtes libres ; vues limitées à la page déjà chargée, sans synchronisation multi-appareils | ADR-0073, `NOTES_SANDBOX.md` |

### 2.3 Capacité PostgreSQL

| Sujet | État | Prochaine action |
|---|---|---|
| **ADR-0135 — budget des pools PostgreSQL** | ADR accepté : plafonds locaux par service, budget par cluster tenant compte des réplicas et de la réserve opérationnelle ; défauts 10/10 inchangés. Aucun validateur ni nouveau réglage n'est encore livré. | Implémenter les parseurs stricts, le manifeste de capacité, le validateur CI et les métriques `DB.Stats()` ; mesurer ensuite avant tout changement des défauts. |

### 2.4 Refonte de l'Admin UI

| Sujet | État | Prochaine action |
|---|---|---|
| **ADR-0136 — navigation adressable** | Contrat proposé : `react-router` seule dépendance de routage, `basename = BASE_URL`, déclaration unique `app/navigation.ts`, 403/404 explicites, filtres en `searchParams`. Aucun code n'est modifié, aucune dépendance n'est ajoutée. L'audit validé est dans `docs/ui/audit-refonte-admin-ui.md`. | Après acceptation de l'ADR, incrément 2 (baseline mesurée), puis les incréments 3 à 6 (shell partagé) avant le routeur (7). |

## 3. Interopérabilité / protocoles

### 3.1 RDP — moteur Go et compatibilité Windows/RDS

| Priorité | Sujet | État vérifié | Reste à faire |
|---|---|---|---|
| P1 | **Codec graphique RDP — incrément 64** | Le sous-ensemble ROP2 est étendu progressivement et testé ; le runtime RDP est raccordé au proxy et la route opérateur est gouvernée par `RDP_ENABLED`. Les parcours Windows Server 2019/2022 sont exécutés en CI. | Terminer `R2_MASKNOTPEN` et la correction normative de `R2_MASKPENNOT`, puis poursuivre les ordres graphiques encore absents et les événements Fast-Path non pris en charge. |
| P2 | **Interopérabilité RDS avancée** | CredSSP/NTLMv2, Kerberos (ADR-0100), MCS/GCC, licences Personal Terminal Server, session et enregistrement sont éprouvés sur les cibles CI couvertes. Le pipeline RDPGFX est derrière `SCREEN_RDPGFX`, désactivé par défaut. | Élargir les scénarios Windows/RDS ; émission et mise à niveau CAL complètes, RD Gateway, carte à puce et Remote Guard restent hors support ; ne pas revendiquer une compatibilité RDP générale. |
| P2 | **Fast-Path et ordres graphiques** | Fragmentation Fast-Path et un sous-ensemble d'ordres sont décodés avec des bornes strictes. | Autres ordres, pointeur/clavier/souris Fast-Path, variantes ROP et clipping restent à concevoir et éprouver avant annonce. |

### 3.2 VNC et autres protocoles

- **VNC** : TigerVNC 1.13.1 est validé de bout en bout. RealVNC/RFB 5.0 n'est pas pris en charge ; le presse-papiers VNC reste absent.
- **SSH/SFTP/SCP** : parcours MVP livré ; SFTP/SCP utilisent le proxy SSH.
- **Non livrés à ce stade** : Telnet, HTTP/HTTPS proxy, Database Proxy, WinRM, Kubernetes Exec, Docker Exec, console série/IPMI, VMware Console, Hyper-V, Proxmox et OpenStack. Chaque famille doit avoir son ADR, son proxy dédié et ses preuves d'interopérabilité avant exposition.
