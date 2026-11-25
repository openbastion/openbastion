# Database Proxy — PostgreSQL

Implémentation progressive de l'ADR-0139. Ce module constitue le noyau protocolaire et le plan de contrôle initial ; il n'est pas encore un endpoint PostgreSQL déployable tant que le listener TLS, le raccordement Vault/Recorder et le relais amont ne sont pas intégrés.

## Déjà implémenté

- Décodage borné des paquets Startup, SSLRequest, GSSENCRequest et CancelRequest.
- Décodage borné des messages frontend PostgreSQL v3 et génération des réponses backend essentielles.
- Validation stricte de l'identité `user`/`database` et refus des options de démarrage non autorisées.
- Refus de COPY dans le premier profil.
- Normalisation SQL limitée aux espaces/commentaires hors littéraux et empreinte HMAC-SHA-256 par session ; le texte SQL n'est pas inclus dans l'événement.
- Client SCRAM-SHA-256 amont avec vérification obligatoire de la preuve serveur, borne d'itérations et purge best-effort des intermédiaires. Les mots de passe non ASCII sont refusés jusqu'à l'intégration d'une préparation SASLprep Unicode complète.
- Tickets opaques de 256 bits, stockés par digest, consommés atomiquement et invalidés à la révocation/expiration.
- Limiteur de connexions borné (instance, cible, acteur, session) et registre CancelRequest à clés opaques, lié à l'adresse IP du client et à l'adresse IP amont déjà résolue.
- Routes internes d'établissement/révocation, réservées à l'identité mTLS `session-broker`, avec admission Recorder fail-closed.

## Limites actuelles

- Aucun listener TCP/TLS ni binaire `database-proxy` n'est encore livré.
- Aucun accès cible n'est encore ouvert par ce module ; aucun tunnel TCP générique n'existe.
- Le contrat et l'adaptateur de persistance des événements Database Operation restent à raccorder au Command Recorder.
- L'intégration du champ `database_name` dans le Password Vault et dans le Session Broker reste à réaliser.
- Les tests d'interopérabilité avec un vrai PostgreSQL 16 et les drivers libpq restent à réaliser.

Les paquets sont autonomes et testés sans service PostgreSQL externe. Ne pas publier ni utiliser ce module comme proxy opérationnel avant la fermeture des limites ci-dessus.
