# Transport, contrats, identité

Comment les services se parlent, et ce qui ne doit pas être « réparé » sans demande. Les règles d'écriture des routes sont dans `rules/api-contracts.md`.

- **Le transport entre services est HTTP/JSON sous mTLS — une décision (ADR-0050), plus un écart.** `proto/` décrit les contrats (noms des messages et des champs), sans code généré. Les routes internes portent les champs de leur message ; `test/integration/contract_test.go` le vérifie dans les deux sens, et toute divergence y est déclarée avec sa raison. **Une nouvelle route interne, ou un champ qui change, se déclare dans ce test** (`contractPairs` ou `notMirrored`) ; ne passe pas à gRPC sans un nouvel ADR (le pilote commencerait par `AuditIngestion.EmitEvent`).
- TLS 1.3 mutuel entre services, `INTERNAL_TLS=required` par défaut. Le listener public du Gateway reste en HTTP (le TLS se termine à l'arête).
- Un client HTTP interne n'est construit que pour des pairs déclarés (`mtls.Peer{URL, Service}`) : l'identité du pair est épinglée.
- Les contrats évoluent **de façon additive** uniquement (`docs/api/grpc/README.md` §1) ; une rupture exige un package `v2`. Un numéro de champ Protobuf supprimé est `reserved`, jamais réutilisé.
