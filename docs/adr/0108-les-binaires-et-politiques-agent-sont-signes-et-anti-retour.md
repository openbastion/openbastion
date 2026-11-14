# ADR-0108 — Les binaires et politiques agent sont signés et protégés contre le retour arrière

**Statut** Proposé · 14 novembre 2026

**Contexte**

Un agent de site peut être remplacé par un binaire malveillant ou ramené à une version vulnérable. ADR-0094 définit déjà provenance, SBOM, signature des artefacts et vérification au déploiement. Les politiques locales doivent bénéficier des mêmes garanties.

**Décision**

1. Chaque binaire publié est lié à un tag SemVer et un commit, accompagné d'un SBOM et d'une attestation de provenance, puis signé selon ADR-0094.
2. L'agent vérifie signature, dépôt, provenance, canal, version et chaîne de confiance avant exécution. Une signature d'un autre dépôt/canal ne suffit pas.
3. La mise à jour est téléchargée dans une zone non exécutable, vérifiée puis activée atomiquement.
4. Un compteur monotone protégé contre l'écriture par le compte de service empêche le rollback sous le plancher de sécurité. Si l'hôte ne protège pas ce compteur contre l'administrateur local, cette limite est signalée.
5. Les politiques sont versionnées, signées par une clé de politique distincte des clés de signature des binaires, et liées à l'agent. La clé de politique est épinglée à l'enrôlement et renouvelée uniquement par une chaîne de confiance déjà approuvée. Une politique invalide, expirée, plus ancienne ou destinée à un autre agent est refusée ; à échéance, aucun nouveau tunnel n'est ouvert.
6. Une mise à jour ne peut élargir les capacités sans politique signée distincte.
7. Stable, préversion et développement ont des racines de confiance distinctes ; un binaire de développement n'est jamais accepté en production.

**Conséquences**

- (+) La chaîne de livraison existante est réutilisée.
- (+) Un artefact ou une politique altérés sont refusés.
- (−) L'anti-retour matériel n'est pas garanti sur tous les hôtes.
- (−) Une clé de signature compromise exige rotation et réémission.
- (−) Déploiement progressif et compatibilité nécessitent une matrice de versions.

**Alternatives envisagées**

- **HTTPS sans signature** : rejeté, TLS ne prouve pas la provenance.
- **Signature sans provenance/SBOM** : insuffisant au regard d'ADR-0094.
- **Mise à jour automatique sans validation** : rejetée, elle pourrait élargir les capacités.