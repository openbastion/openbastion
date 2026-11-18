# ADR-0120 — La santé des composants est publiée sans exposer la topologie interne

**Statut** `Proposé` · 2026-11-18 · soumis à validation du propriétaire du projet ; aucun code n'est autorisé par cet ADR seul.

**Contexte** — Plusieurs services exposent déjà des sondes techniques `/healthz` et certains `/readyz`, utilisées notamment par les déploiements ou les proxys. Ces sondes répondent à la vie du processus ou à sa capacité technique à servir ; elles ne constituent pas un contrat de supervision administrateur. La page Sécurité ne peut donc pas présenter un état fiable de la Gateway, de l'Authentication, de l'Authorization, du Session Broker, des proxys, du Vault, du Recorder ou de l'Audit Service. Une sonde interne ne doit pas devenir une fuite de topologie ou de détails opérationnels.

**Décision**

1. Chaque service reste propriétaire de sa liveness et de sa readiness. Un agrégateur de supervision en lecture seule collecte les états déclarés par une liste de composants configurée au déploiement ; il ne sonde pas arbitrairement des adresses fournies par un utilisateur.
2. La Gateway expose `GET /security/components/health` aux administrateurs autorisés. La réponse présente un identifiant logique stable, un état `healthy|degraded|unavailable|unknown`, `checked_at`, `last_success_at` et un code de motif public borné. Elle ne révèle ni adresse IP, port, DNS interne, stack trace, nom de pod, secret, certificat ni configuration.
3. La distinction entre liveness et readiness est conservée. Un processus vivant mais non prêt est `degraded` ou `unavailable` selon la politique déclarée ; une sonde expirée devient `unknown`, jamais `healthy`.
4. Les dépendances critiques sont déclarées dans une configuration opérateur validée au démarrage. Aucun endpoint de health check ne permet de choisir une URL, un hostname, un chemin ou un protocole : protection SSRF par conception.
5. L'agrégateur applique des timeouts stricts, un parallélisme borné, une fréquence minimale et un cache court. Il ne bloque jamais le chemin d'une session PAM et ne modifie pas la décision d'autorisation ou d'admission d'une session.
6. Permission dédiée `security-components:read` selon ADR-0114. Les détails techniques complets restent dans l'observabilité d'exploitation (Prometheus/Grafana/Tempo/Loki), pas dans l'API de posture.
7. Le SVG Sécurité ne présente que les composants configurés et leur fraîcheur. En l'absence de configuration ou de réponse, il affiche `Non configuré` ou `Inconnu`, pas un état vert.

**Conséquences**

- (+) Les administrateurs voient une synthèse exploitable sans accès aux détails réseau internes.
- (+) La supervision est séparée du plan de données et ne peut pas ralentir les connexions privilégiées.
- (−) **Aucun agrégateur ni contrat public n'est livré** ; les sondes existantes ne suffisent pas à revendiquer cette fonction.
- (−) Les composants non équipés de readiness explicite restent `unknown` jusqu'à leur instrumentation.
- (−) La fraîcheur dépend du cycle de collecte et doit être affichée à côté de chaque état.

**Alternatives envisagées**

- **Exposer directement tous les `/healthz` au navigateur** : rejeté, cela divulgue la topologie et mélange liveness et readiness.
- **Accepter des URL de sondes configurables depuis l'API** : rejeté, cela créerait une primitive SSRF.
- **Faire dépendre l'admission des sessions de l'agrégateur** : rejeté, la supervision ne doit pas devenir une dépendance synchrone du chemin critique PAM.

**Critères de validation**

- Tests couvrent healthy, degraded, timeout, absence de configuration et indisponibilité de l'agrégateur.
- Les URLs et destinations de sondes ne sont jamais contrôlables via une requête publique.
- Les timeouts et le nombre de sondes simultanées sont bornés ; aucune sonde ne retarde le chemin d'ouverture d'une session.
- Les réponses publiques ne contiennent aucune adresse ou donnée interne sensible.
