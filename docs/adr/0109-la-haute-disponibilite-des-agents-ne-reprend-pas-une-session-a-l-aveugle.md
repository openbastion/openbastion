# ADR-0109 — La haute disponibilité des agents ne reprend pas une session à l'aveugle

**Statut** Proposé · 14 novembre 2026

**Contexte**

Les agents doivent survivre à la perte d'un replica Agent Control, mais une reconnexion ne doit pas ressusciter une session révoquée ou rejouer des données. La disponibilité ne prime pas sur l'autorisation et l'enregistrement.

**Décision**

1. L'agent connaît une liste d'endpoints déclarés avec identité serveur épinglée. Le basculement ne désactive jamais TLS ni le pinning.
2. Les replicas partagent registre, révocations et générations de politique. Un certificat/génération ne peut avoir qu'un flux de contrôle actif.
3. Une nouvelle connexion authentifiée remplace l'ancienne après validation ; l'ancien flux et ses tunnels sont fermés.
4. La perte du flux de contrôle ferme immédiatement les tunnels. Aucune session ne continue hors ligne ; Broker et proxy terminent la session selon ADR-0018.
5. Une reprise exige une nouvelle décision du Broker, une autorisation encore valide, un recorder prêt (ADR-0008) et une capacité neuve à usage unique.
6. Le heartbeat expose version, état, dernière séquence acquittée, échéance du certificat, génération de politique et compteurs bornés ; aucun secret ni contenu de session.
7. Les reconnexions utilisent backoff exponentiel avec jitter, limites de débit et délais.
8. Le registre distingue online, degraded, offline, disabled et revoked ; un état inconnu est indisponible, jamais autorisé.

**Conséquences**

- (+) Une bascule ne ressuscite pas une autorisation ni un tunnel ancien.
- (+) Révocation et terminaison restent cohérentes.
- (−) Une panne de contrôle interrompt les sessions légitimes.
- (−) La reprise nécessite une nouvelle session opérateur et peut redemander MFA/approbation.
- (−) Le registre partagé devient une dépendance HA.

**Alternatives envisagées**

- **Maintenir les tunnels hors ligne** : rejeté, révocation et expiration inapplicables.
- **Reprendre les flux au dernier numéro** : rejeté, risque de rejeu après révocation.
- **Endpoint unique** : possible en petit site, insuffisant comme cible HA.