# ADR-0149 — Entrée clavier et souris Fast-Path RDP

**Statut** `Accepté` · 28 novembre 2026

## Contexte

OpenBastion décode déjà les mises à jour graphiques et pointeur Fast-Path émises par le serveur. Les entrées opérateur sont en revanche toujours sérialisées en `TS_INPUT_PDU` slow-path par `CredSSPClientSession.SendInput`. Le chemin couvre les scancodes, Unicode, synchronisation des touches de verrouillage et événements souris absolus.

La spécification MS-RDPBCGR définit `TS_FP_INPUT_PDU`, qui remplace l'enveloppe TPKT/X.224/MCS/Share Data pour transporter des événements client-vers-serveur compacts. Le client annonce cette capacité dans `TS_INPUT_CAPABILITYSET` via `INPUT_FLAG_FASTPATH_INPUT2` (`0x0020`). Le flux RDP OpenBastion utilise TLS comme sécurité externe ; les mécanismes de chiffrement/MAC de la sécurité RDP standard ne doivent donc pas être ajoutés au PDU Fast-Path.

## Décision

1. Ajouter une sérialisation Fast-Path Input uniquement pour les connexions dont le serveur confirme la prise en charge Fast-Path dans son `TS_INPUT_CAPABILITYSET`. Conserver le slow-path comme comportement de repli lorsque la capacité n'est pas confirmée.
2. Annoncer `INPUT_FLAG_FASTPATH_INPUT2` (`0x0020`) dans le `TS_INPUT_CAPABILITYSET` client, sans annoncer les capacités QoE, souris relative ou événements étendus non implémentés. Garder `INPUT_FLAG_SCANCODES` et les capacités Unicode déjà prises en charge.
3. Étendre `SendInput` sans changer son contrat public : préserver l'ordre des événements et leur validation, sélectionner Fast-Path seulement après négociation effective et sérialiser sinon le `TS_INPUT_PDU` actuel. Aucun choix de format ne doit dépendre d'une préférence UI ou d'une hypothèse sur le serveur.
4. Dans ce premier profil Fast-Path, prendre en charge exclusivement :
   - `RDPInputScancode` avec les indicateurs release et extended déjà validés ;
   - `RDPInputUnicode` avec l'indicateur release ;
   - `RDPInputMouse` avec coordonnées absolues et les boutons/molette déjà acceptés ;
   - `RDPInputSync` pour l'état des touches de verrouillage.
   Les événements souris étendus, relatifs, QoE, événements inconnus et drapeaux non couverts restent refusés ou hors annonce.
5. Encoder `TS_FP_INPUT_PDU` conformément à MS-RDPBCGR : action Fast-Path, longueur courte ou étendue, nombre d'événements compact pour 1 à 15 événements et octet de compte étendu au-delà. Respecter une limite de 128 événements par appel, identique à `maxRDPInputEvents`, et une taille maximale PDU de 16 383 octets.
6. Le PDU est transporté dans le flux TLS existant. Ne pas positionner `FASTPATH_INPUT_ENCRYPTED` ni `FASTPATH_INPUT_SECURE_CHECKSUM`, ne pas ajouter de FIPS information ou de signature interne RDP. Si le transport n'est pas TLS avec handshake achevé, `SendInput` refuse l'opération comme aujourd'hui.
7. Conserver `writeMu`, les deadlines, l'annulation de contexte, la fermeture fail-closed après écriture partielle/erreur et l'ordre total des événements. Une erreur de sérialisation ne doit écrire aucun octet.
8. Ajouter des tests binaires de chaque événement, de l'en-tête, des longueurs 127/128 et 16 383, des comptes 1/15/16/128, des champs invalides, de la négociation, du fallback slow-path et de la concurrence lecteur/écrivain. Ajouter des tests d'interopérabilité Windows Server 2019/2022 en CI pour clavier `fr-FR`, Unicode, touches étendues, synchronisation, clics, mouvement et molette.
9. Ne pas modifier le décodage Fast-Path serveur, le proxy écran, l'audit ou le contrat de session. Les événements doivent continuer à passer par le même `SendInput` audité côté proxy ; aucune voie d'accès directe à la cible n'est créée.

## Conséquences

- (+) Réduit l'enveloppe et le volume des entrées clavier/souris tout en conservant une API d'entrée unique.
- (+) Le fallback permet de rester compatible avec les serveurs qui n'annoncent pas Fast-Path Input.
- (+) Le TLS existant reste l'unique couche de sécurité et évite le double chiffrement.
- (−) Le profil initial ne couvre ni souris relative/étendue, ni QoE, ni événements Fast-Path inconnus.
- (−) La négociation et le comportement des serveurs Windows doivent être éprouvés avant activation par défaut.

## Alternatives envisagées

- **Forcer Fast-Path pour tous les serveurs** : écartée, car le support doit être annoncé et confirmé par les capacités négociées.
- **Remplacer le slow-path sans repli** : écartée, car certains serveurs ne prennent pas en charge Fast-Path Input.
- **Ajouter souris relative, QoE et événements étendus au premier incrément** : écartée, car ces types ont des formats et capacités distincts ; ils demandent des contrats et preuves séparés.
- **Ajouter chiffrement/MAC RDP interne en plus de TLS** : écartée, car la connexion utilise Enhanced RDP Security/TLS et ne doit pas appliquer les mécanismes Standard RDP Security en double.

## Références

- [MS-RDPBCGR — Client Fast-Path Input Event PDU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133)
- [MS-RDPBCGR — Input Capability Set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b3bc76ae-9ee5-454f-b197-ede845ca69cc)
- [MS-RDPBCGR — Sending Fast-Path Input Event PDU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/37879f07-d502-4426-b218-c6119f58349c)
- [MS-RDPBCGR — Processing Fast-Path Input Event PDU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/178aef78-2606-4e44-a94a-6ee6f6dc5cc6)
