# ADR-0136 — Attribuer l’émetteur d’un événement à l’appelant mTLS immédiat

**Statut** `Accepté` · 2026-11-24 · clarification additive d’ADR-0027 et d’ADR-0117 §8.

## Contexte

La policy `.agents/policies/audit-logging.md` §3 impose que l’acteur soit l’identité vérifiée et que l’émetteur soit celui du certificat. ADR-0027 établit déjà que l’émetteur provient du certificat mTLS, jamais du corps de la requête.

ADR-0117 §8 décrit correctement l’acteur humain de l’acquittement, mais attribue l’émetteur au certificat de l’Audit Service. Cette formulation confond le service qui reçoit et signe l’événement avec le workload qui a effectué l’appel ayant causé l’événement. Pour l’acquittement exposé par la Gateway, l’Audit Service reçoit un appel mTLS dont le certificat vérifié est celui de `api-gateway`.

Il faut conserver la séparation entre l’identité humaine à l’origine de l’action, l’identité technique de l’appelant immédiat et le service qui conserve et signe la chaîne. La clarification ne doit ni déplacer la route, ni modifier les permissions, ni ouvrir l’accès direct à PostgreSQL.

## Décision

1. **`actor_id` désigne le principal à l’origine de l’action.** À la frontière publique, la Gateway l’obtient du bearer token après vérification par Authentication. La Gateway reconstruit le corps interne avec cet identifiant ; elle ignore toute identité ou tout rôle fourni par le client. Pour l’acquittement d’une alerte, `actor_id` est donc l’utilisateur vérifié.
2. **`emitter` désigne le workload appelant immédiat authentifié par mTLS.** L’Audit Service le lit exclusivement depuis le contexte établi par `mtls.Guard` (`mtls.CallerFrom`), qui dérive du certificat client vérifié et de la règle d’appel de la route. Il ne l’accepte jamais dans le corps, la query ou un en-tête applicatif. Pour un acquittement relayé par la Gateway, `emitter=api-gateway`.
3. **L’Audit Service reste le propriétaire de l’événement et de la chaîne.** Il valide l’acteur et l’émetteur, construit l’événement, le signe avec sa clé d’audit (`key_id`), puis écrit l’événement et la projection d’acquittement dans la même transaction PostgreSQL. Le service qui signe/conserve la preuve n’est donc pas automatiquement la valeur de `emitter`.
4. **La chaîne conserve les deux identités.** L’événement `session.alert.acknowledged` porte l’utilisateur vérifié dans `actor_id` et l’identité mTLS de la Gateway dans `emitter`. Les détails métier ne peuvent pas remplacer ces champs d’attribution.
5. **La Gateway n’accède pas directement à PostgreSQL.** Elle appelle exclusivement l’API interne de l’Audit Service en mTLS, après authentification et décision ABAC exacte `session-alerts:acknowledge` sur `session-alerts:{id}`. `CallerRules` n’autorise que `api-gateway` sur la route d’acquittement. Les identifiants, le pool et les permissions PostgreSQL restent dans le périmètre de l’Audit Service.
6. **Clarification ciblée d’ADR-0117 §8.** Pour l’acquittement, la phrase « l’émetteur est le certificat mTLS de l’Audit Service » est remplacée par la règle suivante : « l’acteur provient de l’identité utilisateur vérifiée par la Gateway ; l’émetteur provient du certificat mTLS de l’appelant immédiat de l’Audit Service (ici `api-gateway`) ; l’Audit Service signe et persiste l’événement ». Toutes les autres décisions d’ADR-0117 restent inchangées.

## Conséquences

- (+) La provenance identifie séparément l’utilisateur responsable, le workload qui a appelé l’Audit Service et le service qui a signé la preuve.
- (+) Le champ `emitter` est conforme à la policy d’audit et ne peut pas être usurpé par le corps HTTP.
- (+) La Gateway demeure une façade sans accès PostgreSQL ; l’Audit Service conserve la responsabilité transactionnelle et cryptographique.
- (+) La même règle s’applique aux autres événements internes : l’émetteur est toujours le certificat de l’appelant immédiat autorisé, tandis que l’acteur est l’identité vérifiée pertinente pour l’action.
- (−) Un événement relayé n’identifie pas à lui seul tous les sauts antérieurs. La corrélation interservices doit s’appuyer sur les identifiants de corrélation/causation existants, sans falsifier `emitter`.

## Alternatives rejetées

- **Utiliser le certificat de l’Audit Service comme `emitter` :** rejeté, car il identifie le service qui reçoit/signe, pas l’appelant immédiat, et contredit la policy §3.
- **Faire confiance à un `emitter` transmis par la Gateway dans le corps :** rejeté, car une donnée applicative ne constitue pas une preuve d’identité mTLS.
- **Faire écrire la Gateway directement dans PostgreSQL :** rejeté, car cela contournerait l’API propriétaire, la transaction chaîne/projection et la frontière d’accès de l’Audit Service.
- **Faire émettre directement l’événement par la Gateway :** rejeté, car l’Audit Service demeure l’unique propriétaire de la chaîne et la Gateway n’est pas autorisée à appeler `emit-event`.

## Validation attendue

- Un acquittement via Gateway produit un événement signé dont `actor_id` est l’utilisateur issu du bearer token vérifié et dont `emitter` vaut `api-gateway`, obtenu du contexte mTLS.
- Un corps public contenant un faux `actor_id`, `emitter` ou des rôles ne peut modifier aucune attribution.
- Un certificat autre que `api-gateway` est refusé par `CallerRules` sur la route d’acquittement.
- La Gateway ne possède ni route ni identifiants PostgreSQL pour cette opération ; la transaction est exécutée par le magasin de l’Audit Service.
- L’événement et la projection restent atomiques, idempotents et vérifiables par `VerifyChain`.
