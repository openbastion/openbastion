# ADR-0113 — Exposer le rapprochement des injections à l'Admin UI sous autorisation explicite

- **Statut :** Accepté
- **Date :** 15 novembre 2026
- **Contexte :** ADR-0010, ADR-0019, ADR-0112, ADR-0097 / SI-03
- **Licence :** AGPL-3.0

## Contexte

ADR-0112 expose `GET /audit/v1/secret-injections` uniquement à l'identité mTLS `admin-cli`. C'est une frontière volontaire : l'Admin UI est un client navigateur de l'API publique Gateway et ne détient aucune identité mTLS interne. Lui fournir le certificat `admin-cli`, sa clé privée ou un accès direct au port Audit Service ferait sortir une identité d'administration du poste de confiance et contournerait la séparation des services.

Le rapprochement est maintenant disponible dans le CLI, mais l'Admin UI ne peut pas le consommer sans définir un nouveau chemin d'autorisation. Le résultat contient des métadonnées de toutes les injections et constitue donc une lecture d'audit transverse, pas une simple lecture de session.

## Décision acceptée

**Décision retenue :** créer une façade publique en lecture seule dans la Gateway, derrière le jeton utilisateur vérifié et une politique Authorization dédiée.

- Route publique proposée : `GET /audit/secret-injections` ; elle relaie uniquement `limit` et `before` vers l'Audit Service.
- Appel interne : la Gateway utilise son identité mTLS `api-gateway`. L'Audit Service ajoute cette identité à la liste d'appelants de la seule route `GET /audit/v1/secret-injections` ; `admin-cli` reste autorisé pour le CLI.
- Autorisation utilisateur : la Gateway appelle l'Authorization Service avec l'acteur et les rôles issus du jeton vérifié, action `audit:secret-injections:read`, ressource exacte `audit:secret-injections:all`. La décision est appliquée sur les deux dimensions par Authorization (ADR-0114) ; une politique qui ne correspond qu’à la ressource ne suffit pas. Aucun droit implicite n'est accordé à `platform-admin` ou `session-auditor` ; la politique est refusée par défaut et doit être attribuée explicitement. Le préfixe `audit:` est distinct des ressources de session, d'enregistrement et du Vault.
- Le navigateur reçoit uniquement la projection métadonnée définie par ADR-0112 : aucun credential, scope Vault, grant MFA, preuve MFA ou contenu de frappe. Réponse `Cache-Control: no-store`, limite 500, pagination par `next_before`.
- La Gateway ne transmet jamais d'identité utilisateur dans le corps. L'Audit Service authentifie le service appelant par mTLS ; la décision utilisateur est prise par la Gateway après vérification du jeton et de la politique.
- La consultation reste strictement en lecture seule : elle ne crée aucun événement dans la chaîne consultée et ne modifie ni événement, archive, ancre ni checkpoint, conformément à ADR-0112.

## Conséquences et risques à accepter

- L'Admin UI peut afficher le même rapprochement que le CLI sans posséder de certificat interne.
- Une compromission de la Gateway peut abuser de sa capacité mTLS à lire cette projection ; le contrôle Authorization limite les appels normaux, mais l'Audit Service ne peut pas distinguer les utilisateurs derrière l'identité `api-gateway`.
- La permission est transverse à toutes les injections. Elle ne filtre pas par compte ou session ; l'attribution doit donc être réservée à un rôle d'audit explicitement approuvé.
- La consultation ne sera pas ajoutée à la chaîne d'audit qu'elle consulte, car cela modifierait la source append-only et contredirait ADR-0112. Si une preuve indépendante de consultation est exigée, elle doit être définie dans un journal de sécurité distinct, hors de cette chaîne.
- L'UI doit présenter `completed` comme un résultat terminal journalisé, jamais comme une preuve de réception complète par la cible. `failed` et `outcome_unknown` imposent une vérification manuelle ; aucun bouton de retry ou de réinjection ne sera proposé.

## Alternatives envisagées

1. **Conserver le CLI uniquement.** Sûr et conforme à ADR-0112, mais ne répond pas au besoin de consultation depuis l'Admin UI.
2. **Distribuer le certificat `admin-cli` au navigateur ou à l'Admin UI.** Rejeté : la clé privée interne serait exposée à un environnement client et l'interface pourrait contourner la Gateway et les politiques utilisateur.
3. **Créer un service BFF / audit-operator dédié.** Possible, mais ajoute un service, une identité, un déploiement et une frontière de confiance pour une lecture qui peut être relayée par la Gateway existante.
4. **Autoriser directement les utilisateurs sur l'Audit Service.** Rejeté : l'Audit Service ne valide pas les jetons utilisateurs et ne doit pas devenir un second point d'authentification publique.

## Validation et critères de mise en œuvre

Le propriétaire a accepté les trois éléments : façade Gateway + politique dédiée, portée transverse sur toutes les injections et tous les comptes, et absence d’événement de consultation dans la chaîne d’audit consultée. Aucun journal distinct n’est ajouté dans cette décision.

La mise en œuvre doit prouver : refus sans politique correspondant simultanément à la ressource et à l’action (ADR-0114), identité et rôles tirés exclusivement du jeton vérifié, appelant mTLS refusé hors `api-gateway`/`admin-cli`, panne Authorization en `503`, pagination stable, `Cache-Control: no-store`, réponse bornée, et parcours Admin UI avec états chargement/vide/erreur et avertissement `outcome_unknown`. Le CLI reste indépendant et utilise toujours `admin-cli`.
