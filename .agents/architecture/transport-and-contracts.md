# Transport, contrats, identité

Comment les services se parlent, et ce qui ne doit pas être « réparé » sans demande. Les règles d'écriture des routes sont dans `rules/api-contracts.md`.

- **Le transport entre services est HTTP/JSON sous mTLS — décision ADR-0050 — sauf le flux vidéo gRPC d'ADR-0070.** `proto/` décrit les contrats ; les contrats ordinaires HTTP/JSON restent vérifiés par `test/integration/contract_test.go`. Le Video Recorder a du code Protobuf/gRPC généré pour l'ingestion bidirectionnelle et le replay ; toute nouvelle exception gRPC demande un ADR.
- TLS 1.3 mutuel entre services, `INTERNAL_TLS=required` par défaut. Le listener public du Gateway reste en HTTP (le TLS se termine à l'arête).
- Un client HTTP interne n'est construit que pour des pairs déclarés (`mtls.Peer{URL, Service}`) : l'identité du pair est épinglée.
- Les contrats évoluent **de façon additive** uniquement (`docs/api/grpc/README.md` §1) ; une rupture exige un package `v2`. Un numéro de champ Protobuf supprimé est `reserved`, jamais réutilisé.
