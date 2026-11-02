# Sauvegardes

| Donnée | Où | Fréquence recommandée |
|---|---|---|
| PostgreSQL (comptes, politiques, sessions, audit et métadonnées vidéo) | Snapshot + WAL continu | Continu |
| Stockage objet S3-compatible (segments vidéo chiffrés) | Réplication/sauvegarde du bucket ; restaurer les objets et les lignes `video_recording_segments` de façon cohérente | Continu |
| Clé KMS/HSM | **Jamais dans la même sauvegarde que les données chiffrées** | Selon la politique du KMS externe |
| Le fichier `deploy/docker-compose/.env` d'une installation Compose (ADR-0033) | **Hors de l'hôte**, chiffré, jamais dans git : il porte les clés du Vault, du Command Recorder, les identifiants S3, la chaîne et la signature des jetons | À l'installation, puis à chaque rotation |
| Transit (clé et identifiants du Video Recorder) | Sauvegarde/réplication propre au KMS ; restaurer la clé Transit et les identifiants d'accès indépendamment des données | Selon la politique du KMS externe |
| Archives de l'audit (`AUDIT_ARCHIVE_DIR`, ADR-0032) | Un stockage en ajout seul (WORM), avec la durée de conservation légale, **pas avec les sauvegardes de la base** ; ce qu'elles contiennent n'est plus en base | À chaque archive (horaire au plus) |
| Fichier d'ancres de la chaîne (`AUDIT_ANCHOR_FILE`, ADR-0028) | **Jamais avec les sauvegardes de la base** : restaurer les deux ensemble rendrait une réécriture indétectable ; copie en ajout seul (WORM) | Continu (réplication du fichier) |
| Clés de la chaîne d'audit (`AUDIT_CHAIN_KEY_HEX` et les précédentes, ADR-0027) | **Hors de la base et hors de ses sauvegardes** ; une clé perdue rend invérifiable l'histoire qu'elle a signée | À chaque rotation, conservées toute la rétention de l'audit |

La procédure complète de bascule en cas de sinistre, y compris la question de savoir si un site sauvegardé doit être traité comme potentiellement compromis, est couverte par `docs/deployment/disaster-recovery.md` §4 — ce document ne couvre que la sauvegarde courante, pas la reprise.
