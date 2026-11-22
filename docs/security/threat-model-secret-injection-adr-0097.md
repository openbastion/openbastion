# Revue de menace STRIDE — injection d’un secret Vault (ADR-0097)

**Date :** 15 novembre 2026

**Périmètre :** parcours A uniquement — injection d’un credential Vault dans une session SSH, VNC ou RDP, confirmée par TOTP/WebAuthn.
**Statut :** revue technique formalisée ; les risques non couverts restent ouverts. Cette revue complète ADR-0097 sans modifier sa décision acceptée.

## 1. Résumé exécutif

Le chemin de confiance reste orienté vers le moindre privilège. **Parcours A (secret Vault)** : le navigateur ne reçoit que les preuves de step-up ; le Session Broker dérive le compte et le protocole depuis la session persistée ; le proxy propriétaire échange un scope Vault à usage unique contre le credential et réalise la frappe. **Parcours B (ADR-0133)** : le mot de passe saisi par l’opérateur existe dans le navigateur puis est chiffré pour le proxy écran avant transport ; la Gateway ne relaie que le chiffré. Dans les deux parcours, l’audit préalable et le marqueur Video Recorder sont acquittés avant la frappe.

Au 22 novembre 2026, les parcours SSH/VNC/RDP, la réconciliation `outcome_unknown`, le rejeu d'archives après redémarrage, l'attestation ADR-0116 et la saisie opérateur ADR-0133 ont des preuves multi-processus ou CI. Le risque technique majeur encore ouvert est la terminaison/révocation déclenchée pendant une frappe déjà en cours (SI-02). Les copies mémoire résiduelles et le focus distant restent des limites documentées, pas des garanties d'effacement ou de masquage.

**Conclusion :** ne pas considérer l’injection comme une fonction de sécurité entièrement close tant que les risques P1 de cette revue n’ont pas été traités ou explicitement acceptés. Cette revue ne lève pas le blocage du parcours B.

## 2. Actifs et objectifs de sécurité

| Actif | Sensibilité / objectif |
|---|---|
| Credential cible (mot de passe, clé ou autre secret supporté) | Confidentialité ; jamais navigateur, Gateway, Broker, logs, audit ou enregistrement |
| Scope Vault à usage unique | Capacité bearer sensible ; limité au proxy propriétaire, au compte et à la session |
| Grant MFA | Capacité éphémère liée à acteur/session/compte/protocole/action ; non réutilisable |
| Identité de l’opérateur | Authentique, vérifiée par jeton et liée à la session |
| Liaison session → compte → cible | Intégrité ; ne peut être choisie ou remplacée par le client |
| Preuve d’audit et marqueur vidéo | Intégrité, ordre, attribution et non-répudiation |
| Images/flux de session | Confidentialité ; peuvent révéler indirectement un secret tapé dans une zone visible |
| Disponibilité du relay et des contrôles | Une panne doit refuser l’injection plutôt que contourner un contrôle |

## 3. Acteurs et frontières de confiance

- **Opérateur / navigateur :** environnement non fiable ; le DOM, les extensions, le poste et les scripts de la page peuvent être compromis.
- **API Gateway :** frontière publique ; valide le bearer token, borne les corps et applique les limites de débit.
- **Authentication :** vérifie TOTP/WebAuthn et délivre un grant d’action lié au contexte.
- **Authorization :** décide sur la ressource et l’action exactes ; indisponibilité = refus.
- **Session Broker :** orchestre la session et route vers l’instance proxy propriétaire ; ne doit jamais lire le credential.
- **Password Vault :** délivre un scope court et le credential correspondant à la cible épinglée.
- **Proxy SSH ou RDP/VNC :** seul composant autorisé à échanger le scope et à taper le secret dans la session active.
- **Command Recorder / Video Recorder et Audit Service :** preuves durables ; leurs indisponibilités doivent empêcher la frappe.
- **Base de données :** contient l’état persistant des sessions et des liaisons compte/protocole/demandeur ; un rôle disposant d’écriture est une autorité de fait sur ces métadonnées.
- **Cible distante :** environnement externe ; elle peut être compromise, malveillante ou afficher le texte dans une zone visible.

~~~mermaid
flowchart LR
  U[Opérateur / navigateur non fiable] -->|Bearer + preuve MFA| G[API Gateway]
  G -->|Identité vérifiée| B[Session Broker]
  B <-->|Challenge / grant| A[Authentication]
  B -->|Décision exacte| Z[Authorization]
  B -->|Scope court, proxy propriétaire| P[Proxy SSH / RDP-VNC]
  P -->|Scope à usage unique| V[Password Vault]
  P -->|Frappe protocolaire| T[Cible distante]
  P -->|Marqueur avant frappe| R[Video / Command Recorder]
  P -->|Audit avant et résultat| L[Audit Service]
  T -->|Écran / sortie| P
  P -->|Flux enregistré| R
~~~

Les flèches représentent les flux logiques, pas une autorisation implicite : les routes internes restent protégées par mTLS et allowlists de certificats.

## 4. Analyse STRIDE

### S — Spoofing (usurpation)

**Scénarios**
1. Un client forge l’acteur, les rôles, le compte, le protocole ou le scope dans le corps HTTP.
2. Un service autre que le Broker appelle la route interne d’injection du proxy.
3. Un opérateur non propriétaire d’une session tente de déclencher le step-up ou de réutiliser une preuve d’un autre acteur.
4. Un proxy ou une cible usurpe l’identité attendue lors de l’échange du secret.

**Contrôles observés**
- La Gateway reconstruit l’acteur et les rôles depuis le bearer token vérifié ; les champs supplémentaires sont rejetés.
- Le Broker reconstruit compte et protocole depuis la session persistée et vérifie le demandeur, le statut et l’expiration.
- Le grant MFA est lié à acteur, session, compte, protocole et action ; sa consommation est atomique et à usage unique.
- Les routes d’injection internes du proxy sont réservées à l’identité mTLS session-broker.
- Le Vault vérifie la cible et son ancre de confiance avant de remettre le credential.

**Preuves disponibles**
- Tests Gateway/Broker de corps strict, identité forgée, demandeur non propriétaire, preuve TOTP invalide, consommation unique et routage SSH/VNC/RDP.
- Tests multi-processus VNC et RDP avec MFA, Broker, Vault, proxy, recorder et audit ; le test VNC vérifie la séquence Unicode reçue par la cible de test.
- Le test Windows de réception Unicode RDP reste exécuté uniquement dans la CI Windows ; il n’a pas été lancé localement.

**Risque résiduel — P1**
- La compromission du Broker ou d’une identité mTLS autorisée reste une compromission de composant de confiance. Le mTLS identifie le service, mais ne prouve pas qu’un Broker compromis respecte l’intention métier.
- La revue ne démontre pas une attestation indépendante de l’acteur humain par l’Audit Service ; l’attribution repose sur l’émetteur de confiance et les contrôles amont.

**Actions**
- Ajouter un test négatif qui appelle chaque route interne avec un certificat valide d’un autre service et vérifie l’absence de fetch Vault et de frappe.
- Conserver les tests Windows CI et exiger leur succès avant toute activation générale de la saisie RDP.

### T — Tampering (altération)

**Scénarios**
1. Substitution de cible, de compte ou de protocole entre l’autorisation et l’injection.
2. Modification ou rejeu du scope Vault, du grant MFA ou du challenge.
3. Intercalation d’entrées opérateur au milieu du secret.
4. Course entre fin/révocation de session et frappe du secret : une preuve cible réelle vérifie désormais l’entrée effective et l’absence d’événement après l’acquittement ; la course concurrente reste ouverte.
5. Modification, réordonnancement ou suppression du marqueur/audit.
6. Un acteur qui a compromis un rôle PostgreSQL modifie l’enregistrement de session (propriétaire, compte, protocole ou état) avant que le Broker ne le relise.

**Contrôles observés**
- Le Broker dérive les attributs depuis la session et réévalue session et Authorization avant l’action.
- Le scope est court, à usage unique, échangé par le proxy propriétaire ; le proxy compare l’identité de cible du credential à celle du relay vivant.
- Le pool proxy utilise une affinité déterministe ; aucune bascule vers une autre instance n’est permise.
- VNC/RDP sérialisent la frappe avec l’entrée opérateur via le verrou d’écriture commun.
- Le proxy attend l’acquittement de l’événement d’audit préalable et du marqueur vidéo avant la frappe.
- Les enregistrements et la chaîne d’audit sont append-only et vérifiables.
- Les services utilisent des identifiants PostgreSQL distincts ; les services n’exposent pas l’accès SQL au navigateur ou au proxy public.

**Preuves disponibles**
- Tests de refus de cible différente, de scope invalide/consommé, de session inactive/ambiguë et d’ordre audit → marqueur → frappe.
- Tests VNC/RDP multi-processus et tests de rejeu ; le replay et les métadonnées n’incluent pas la valeur du secret.

**Risque résiduel — P1**
- Le verrou d’entrée prouve l’absence d’intercalation entre frappes. Un E2E VNC contre TigerVNC réel utilise `xev` comme oracle indépendant : il vérifie les keysyms Unicode réellement reçus et qu’aucun événement ne suit l’acquittement de révocation. Il ne force pas encore une terminaison concurrente au milieu de la frappe ; cette atomicité reste à démontrer.
- Un arrêt après une frappe partielle peut laisser la cible dans un état intermédiaire ; une frappe déjà reçue ne peut pas être annulée.
- Un rôle PostgreSQL compromis avec droit d’écriture peut altérer les métadonnées de session que le Broker relit. La vérification de la cible par le proxy réduit le risque de substitution d’hôte/utilisateur, mais ne constitue pas une attestation cryptographique indépendante de l’enregistrement de session.

**Actions**
- Ajouter un test concurrent terminate/cancel contre InjectVaultSecret sur les proxys SSH et écran, répété sous -race, qui établit les états permis : soit aucun octet n’est envoyé, soit le marqueur préalable existe et le résultat est explicite.
- Vérifier que le registre retire le typer avant que la session ne soit considérée comme terminée et que le contexte d’annulation coupe les frappes en attente.

### R — Repudiation (répudiation)

**Scénarios**
1. Un opérateur nie avoir demandé l’injection.
2. Un service nie avoir exécuté la frappe.
3. La cible reçoit le secret, mais l’audit final échoue ou le client se déconnecte avant la réponse.
4. Un acteur malveillant tente de fabriquer un événement ou d’en effacer la trace.

**Contrôles observés**
- L’audit préalable session.secret_injection_started est acquitté avant la frappe.
- Un identifiant aléatoire 128 bits `injection_id` est créé par tentative et inscrit dans l’audit préalable ainsi que dans le marqueur terminal/vidéo append-only.
- Le résultat est enregistré par session.secret_injected ou session.secret_injection_failed avec le même `injection_id`.
- Si la frappe réussit, ou échoue après une écriture partielle possible, et que l’audit terminal ne peut être acquitté, le proxy renvoie `outcome_unknown` avec l’identifiant ; le Broker et l’UI ne présentent jamais ce cas comme un succès et demandent de ne pas rejouer le secret.
- L’émetteur d’audit est dérivé du certificat mTLS ; les événements sont signés/chaînés selon les invariants d’audit.

**Preuves disponibles**
- Tests d’ordre et de non-divulgation des événements ; parcours multi-processus qui vérifient la présence de l’événement de succès et du marqueur.
- Test SSH multi-processus avec un intermédiaire qui transmet l’événement terminal à l’Audit Service réel, attend son HTTP 200 puis ferme la connexion avant le proxy : le Broker renvoie `outcome_unknown`, la cible reçoit une seule frappe, aucun retry n’est observé et la chaîne reste vérifiable.
- Vérification de la chaîne d’audit dans le parcours SSH multi-processus ; les parcours screen vérifient l’événement émis.

**Risque résiduel — P1**
- En cas de perte de l’accusé final après la frappe, l’état de la cible reste ambigu. L’événement préalable et le marqueur prouvent une tentative, pas la réception complète du secret. Le `injection_id` permet maintenant de rapprocher les preuves de la chaîne retenue et des archives historiques après vérification cryptographique complète (ADR-0112). La projection classe les preuves mais ne prouve toujours pas la réception complète du secret par la cible ; la vérification manuelle reste obligatoire lorsque le résultat est `failed` ou `outcome_unknown`.
- L’attribution de l’acteur humain dépend du service émetteur autorisé ; un service compromis pourrait attribuer faussement un événement.

**Actions**
- Fait (ADR-0112) : la route interne en lecture seule classe chaque `injection_id` à partir de la chaîne retenue et des archives vérifiées par leurs checkpoints ; elle échoue fermé si une archive ne peut être vérifiée et ne mute jamais l’événement préalable. Le CLI `admin-cli` consomme cette projection. La façade Gateway/Admin UI est implémentée dans la Draft PR #217 (ADR-0113), en attente de la validation finale CI/revue ; `completed` n’atteste pas la réception complète par la cible.
- Fait localement : test multi-processus de perte de l’acquittement terminal après commit Audit ; vérifie `outcome_unknown`, l’absence de nouvelle frappe et l’intégrité de la chaîne. Ajouter la preuve PostgreSQL 16 archive/restart ; l’opérateur doit toujours vérifier manuellement la cible.

### I — Information Disclosure (divulgation)

**Scénarios**
1. Le credential ou le scope apparaît dans le navigateur, les réponses HTTP, les traces, logs, dumps ou outils de diagnostic.
2. Le credential est capturé par Command Recorder, Video Recorder, le presse-papiers ou l’historique du navigateur.
3. Le secret tapé est visible sur l’écran distant parce que le focus n’est pas dans un champ masqué.
4. Une extension ou un script compromis lit la preuve TOTP avant son envoi.

**Contrôles observés**
- Le navigateur ne reçoit ni credential Vault, ni scope Vault, ni grant MFA ; les réponses d’injection sont no-store et 204.
- Le corps public n’accepte que challenge et preuve MFA ; les réponses d’erreur ne relaient pas les diagnostics internes.
- Le secret est frappé hors du flux d’entrée opérateur enregistré ; le marqueur ne contient que la référence du compte et le type d’action.
- Aucun presse-papiers n’est utilisé pour l’injection Vault.
- Les buffers du credential sont bornés et purgés après usage.

**Preuves disponibles**
- Tests HTTP de payload strict, absence de scope/grant dans les réponses, tests de non-divulgation logs/recording/object store et marqueurs vidéo.
- Tests UI Vitest vérifiant l’effacement du TOTP avant l’envoi et l’absence de données sensibles dans le payload.
- Le test navigateur Chromium est ajouté séparément dans cette livraison ; son résultat sera indiqué dans le rapport de validation.

**Risque résiduel — P1**
- Le proxy ne sait pas si le focus distant correspond réellement à un champ masqué. Un secret tapé dans un éditeur ou une console peut apparaître dans la capture d’écran ou la sortie distante.
- Le navigateur reste un terminal de confiance pour la preuve MFA ; un XSS ou une extension malveillante peut la voler ou la relayer pendant sa courte durée.
- Go ne garantit pas l’effacement de toutes les copies immuables créées par les bibliothèques, ni des copies dans les dumps mémoire ou les pages mémoire du processus.

**Actions**
- Conserver l’avertissement explicite sur le focus et les champs masqués ; ne pas présenter l’injection comme masquée à l’écran dans tous les cas.
- Ajouter une vérification de non-divulgation dans les logs structurés et traces distribuées avec des sentinelles uniques ; auditer les chemins d’erreur et les diagnostics.
- Fait (ADR-0115) : politique de dumps/crash documentée ; `RLIMIT_CORE=0` et `PR_SET_DUMPABLE=0` appliqués au Vault et aux proxies Linux ; buffers contrôlés purgés au plus tôt.
- Restent : copies immuables Go, buffers internes TLS/bibliothèques, swap et mémoire noyau ; ne pas promettre leur effacement.

### D — Denial of Service (déni de service)

**Scénarios**
1. Un utilisateur déclenche des challenges MFA en rafale.
2. Des injections volumineuses ou concurrentes bloquent le relay ou épuisent les ressources.
3. Un service d’audit, de recording, de Vault ou le proxy propriétaire est indisponible.
4. Un client garde un verrou d’entrée ou abandonne le flux au mauvais moment.

**Contrôles observés**
- Limitation de débit des actions de session au Gateway ; tailles bornées (credential Vault ≤ 4 Kio, UTF-8, mono-ligne, sans contrôle).
- Session active et relay SecretTyper requis ; les sessions ambiguës sont refusées.
- Le parcours est fail-closed si Authorization, Vault, Audit ou Recorder ne répond pas.
- Le verrou d’entrée sérialise les frappes ; la durée du challenge MFA est courte.

**Preuves disponibles**
- Tests de corps trop grand/format invalide, indisponibilité recorder/audit, session inactive/ambiguë et refus de scope.
- Tests d’intégration sur processus réels pour les chemins heureux et les refus MFA.

**Risque résiduel — P2**
- Les limites globales et par acteur ne prouvent pas à elles seules une protection spécifique contre une consommation répétée de ressources par des challenges MFA ou des tentatives d’injection sur plusieurs sessions.
- Le temps d’attente du verrou et la durée maximale de frappe ne sont pas encore caractérisés par un test de charge dédié.

**Actions**
- Mesurer la latence et la contention avec plusieurs injections concurrentes ; définir un plafond de concurrence et un délai d’attente borné.
- Ajouter un test de débit qui démontre que le refus est décidé avant tout appel Authentication/Vault/proxy supplémentaire.

### E — Elevation of Privilege (élévation de privilèges)

**Scénarios**
1. Utiliser une permission de lecture ou de connexion comme permission d’injection.
2. Changer l’identifiant du compte ou la cible après la validation MFA.
3. Réutiliser un grant sur une autre session, un autre protocole ou une autre action.
4. Exploiter une route interne trop largement autorisée pour faire agir le proxy comme confused deputy.

**Contrôles observés**
- Droit exact secret:inject:account:{id} / action secret:inject, refus par défaut ; le droit secret:paste est distinct et n’est pas un fallback.
- Le Broker revalide la session, le demandeur et Authorization ; le compte/protocole viennent de la session persistée.
- Le grant est lié à l’acteur, session, compte, protocole et action, consommé atomiquement.
- Le proxy exige l’identité mTLS du Broker et vérifie la cible exacte avant frappe.

**Preuves disponibles**
- Tests d’autorisation refusée, de liaison du grant, de compte/protocole/session différents, de non-demandeur, de routage vers la bonne famille de proxy et d’absence de failover.

**Risque résiduel — P1**
- Le Broker et les proxys restent des autorités de confiance privilégiées ; leur compromission permet potentiellement d’abuser des identités mTLS qu’ils détiennent.
- La revue ne démontre pas une séparation de privilèges indépendante pour l’approbation de l’injection ; le contrôle repose sur l’identité de l’opérateur, sa politique et son MFA.

**Actions**
- Ajouter des tests de matrice négative pour chaque permutation acteur/session/compte/protocole/action, incluant la tentative de substitution après le challenge.
- Garder le droit secret:paste désactivé tant que son canal chiffré de bout en bout n’a pas fait l’objet d’un ADR et d’une preuve d’intégration distincts.

## 5. Synthèse des risques

| ID | STRIDE | Risque | Sévérité | État |
|---|---|---|---|---|
| SI-01 | S | Compromission/usurpation d’un service de confiance mTLS | P1 | Résiduel, défense en profondeur |
| SI-02 | T | Course entre révocation/fin de session et frappe | P1 | En validation : E2E déterministe ajouté sur TigerVNC réel avec oracle X11 ; le relais retient des enregistrements TLS après un préfixe réellement reçu. La CI doit confirmer fermeture et absence d'événement après acquittement avant clôture |
| SI-03 | R | Résultat cible ambigu si audit final indisponible | P1 | **Contrôle livré et éprouvé** : projection cryptographiquement vérifiée, CLI, Gateway/Admin UI ; test multi-processus `outcome_unknown` sans retry ; archivage → redémarrage → réconciliation passé en PostgreSQL 16 CI dans le run `45023573283`. La cible reste à vérifier manuellement quand le résultat est ambigu. |
| SI-04 | I | Secret visible dans la capture si focus non masqué | P1 | Limite inhérente, avertissement opérateur |
| SI-05 | I | Copie du secret en mémoire/dump/crash | P1 | Partiel : `RLIMIT_CORE=0` et `PR_SET_DUMPABLE=0` vérifiés au démarrage du Vault et des proxies ; buffers contrôlés purgés ; copies Go/TLS/GC et chaîne SSH imposée restent explicitement hors garantie (ADR-0115 accepté) |
| SI-06 | D | Rafale de challenges et contention de frappe | P2 | Mesure et test de charge à ajouter |
| SI-07 | E | Confused deputy si identité interne compromise | P1 | Allowlist mTLS et autorisation exacte ; risque résiduel |
| SI-08 | T | Altération/rejeu des métadonnées de session par un rôle PostgreSQL compromis | P1 | **Contrôle livré — ADR-0116, incréments 1 à 4** : HMAC par ligne, tête Audit, comparaison à chaque lecture, refus du rollback, ré-attestation de rotation et rôles PostgreSQL distincts. Le test Compose complet prouve que le rôle `session_broker` ne peut pas lire/modifier `audit_service`. Reste un benchmark de performance mTLS/concurrence, pas une lacune d'intégrité. |

## 6. Tests et contre-épreuves à maintenir

| Test d’attaque | Contrôle retiré temporairement | Résultat exigé |
|---|---|---|
| Identité/compte/protocole forgés | Reconstruction depuis jeton/session | Refus, aucun scope ni frappe |
| Certificat mTLS d’un autre service | Allowlist de l’appelant | Refus avant lecture du scope |
| Substitution de cible | Comparaison Vault ↔ relay vivant | Refus, aucun événement de frappe |
| Altération d’une session en base | Liaison des métadonnées persistées et contrôle d’accès DB | Refus ou détection avant scope Vault ; aucune frappe |
| Grant rejoué ou consommé concurremment | Consommation atomique | Une seule opération au plus |
| Terminaison pendant injection | `LiveSessions.Revoke` et propagation du contexte relay → registre ; E2E TigerVNC + oracle `xev` indépendant | L’E2E vérifie l’entrée réelle puis l’absence de nouvelle frappe après l’acquittement de révocation ; la course déclenchée pendant la frappe reste à tester |
| Audit préalable indisponible | Fail-closed | Aucun marqueur ni frappe |
| Recorder indisponible | Acquittement préalable | Aucune frappe |
| Audit final perdu après frappe | `injection_id` commun audit/recording et réponse `outcome_unknown` | Aucun retry ; rapprochement par identifiant ; vérification manuelle de la cible |
| Sentinelle secrète dans traces/logs | Filtrage et absence de champs sensibles | Aucun résultat contenant la sentinelle |
| Rafale de demandes MFA | Limiteur de débit | Refus avant dépendances aval |

Ajouter aussi un scénario avec un rôle PostgreSQL de test qui modifie les colonnes de liaison de la session entre création et step-up ; vérifier que le Broker/proxy refuse ou qu’une preuve indépendante détecte l’altération avant le scope Vault.

Les contre-épreuves doivent être réalisées sur des branches de test isolées ; ne jamais affaiblir un contrôle dans le code livré.

## 7. État des preuves au 22 novembre 2026

- **SSH :** parcours multi-processus MFA → Broker → Vault → proxy → cible → Recorder/Audit validé ; la valeur est absente de l’enregistrement et remplacée par un marqueur. Le test de perte d’acquittement terminal transmet l’événement au véritable Audit Service, perd la réponse après commit, vérifie `outcome_unknown`, une seule frappe côté cible, aucun retry et une chaîne valide.
- **VNC :** parcours multi-processus avec TOTP, refus d’un autre acteur et d’une preuve invalide, frappe Unicode vérifiée à la cible RFB, marqueur et audit, absence du secret dans les logs et l’objet enregistré. Un test complet contre TigerVNC réel a également passé dans l’environnement local.
- **RDP :** le parcours CredSSP, scope Vault, audit, marqueur et rejeu est validé. Le test `TestScreenFlow_RDPOperatorPasteInAHeadlessBrowser` passe dans cinq configurations Windows Server 2019/2022, dont `fr-FR`, dans le workflow Windows RDP (run `44976798904`). Cette preuve couvre ces matrices, pas toute compatibilité RDS.
- **Admin UI :** Vitest couvre les formulaires et refus ; le test Chromium avec API simulée vérifie l’effacement du TOTP avant réponse, le payload limité et l’absence de credential/scope et de stockage persistant. Des tests navigateur/processus réels distincts valident le parcours VNC contre TigerVNC et le parcours RDP contre Windows Server 2019/2022 (run Windows RDP `44976798904`).
- **Parcours B (mot de passe fourni par l’opérateur, ADR-0133) :** livré et éprouvé de bout en bout sur TigerVNC réel et Windows Server 2019/2022 en CI. Le navigateur chiffre pour le proxy écran (ECDH P-256, HKDF-SHA-256, AES-256-GCM) ; la Gateway relaie le chiffré et le Broker ne voit pas le secret. Limites documentées : Gateway compromise pouvant servir une UI hostile avant chiffrement, chaîne JavaScript non effaçable de façon garantie, champ cible visible dans la capture.

## 8. Décision et critères de clôture — revue du 22 novembre 2026

| Risque | Classement actuel | Décision / suite |
|---|---|---|
| SI-02 — révocation pendant la frappe | **P1 ouvert, bloquant avant généralisation ; test ajouté, CI en attente** | Le nouveau test retient les octets TLS après un préfixe observé par `xev`, révoque la session et vérifie la fermeture du relais ainsi que l'absence de nouvelle entrée après acquittement. Ne clôturer qu'après preuve CI. |
| SI-03 — audit terminal perdu | Contrôle livré ; risque opérationnel résiduel | `outcome_unknown`, aucune réinjection, rapprochement cryptographique et CI PostgreSQL 16 archivage/redémarrage validée. Vérification manuelle de la cible obligatoire en cas d'ambiguïté. |
| SI-04 — focus distant visible | Limite technique connue | L'opérateur doit confirmer le focus et un champ masqué ; l'avertissement reste obligatoire. Le proxy ne peut pas inspecter le type de contrôle de la cible. |
| SI-05 — copies mémoire | Partiellement mitigé, limite résiduelle | ADR-0115 bloque les core dumps et purge les buffers contrôlés ; aucune promesse d'effacement des copies Go/GC/TLS, chaînes immuables, swap ou mémoire noyau. |
| SI-08 — altération/rollback PostgreSQL | **Contrôle livré, ADR-0116 incréments 1–4** | HMAC, tête Audit, comparaison à chaque `Get`, ré-attestation et rôles séparés sont prouvés. Seul le benchmark mTLS/concurrence reste à faire. |
| ADR-0133 — saisie opérateur | Livré et éprouvé, limites acceptées | Garder step-up, jeton à usage unique, avertissement de focus et accès restreint aux replays. La compromission de la Gateway et les chaînes JavaScript restent dans le modèle de menace. |
| SI-01 / SI-07 — service de confiance compromis | Risque résiduel P1 | Défense en profondeur, mTLS, allowlists, autorisation exacte et intégrité de la chaîne d'approvisionnement. |
| SI-06 — contention / rafale | P2 | Test de charge et mesure des temps d'attente à planifier. |

**Conclusion :** aucun reliquat d'intégrité ADR-0116, de réconciliation SI-03 ou de validation Unicode RDP n'est identifié dans le périmètre audité. Le seul blocage technique restant pour généraliser l'injection est SI-02, la révocation concurrente au milieu de la frappe. SI-04 et SI-05 restent des limites résiduelles explicites ; elles ne doivent pas être masquées par une affirmation de garantie.

### Actions restantes

1. Valider en CI la course déterministe SI-02 ajoutée sur processus réels, avec révocation pendant un flux de frappes TigerVNC et oracle X11 indépendant ; corriger le proxy si une entrée supplémentaire est observée.
2. Mesurer SI-06 (contention du verrou et rafales MFA) ; P2, non bloquant pour les clôtures documentaires.
3. Mesurer le coût ADR-0116 sous charge et mTLS sur un déploiement représentatif ; non bloquant pour l'intégrité.
4. Maintenir l'avertissement de focus et les limites mémoire dans l'Admin UI, la documentation d'exploitation et les procédures d'incident.

Les contrôles ADR-0115, ADR-0116 et ADR-0133 ne sont pas réécrits par cette revue. Les preuves CI citées valident les scénarios explicitement exécutés, pas une compatibilité universelle de toutes les cibles.
