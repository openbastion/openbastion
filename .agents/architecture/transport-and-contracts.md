# Transport, contrats, identité

Comment les services se parlent, et ce qui ne doit pas être « réparé » sans demande. Les règles d'écriture des routes sont dans `rules/api-contracts.md`.

- Le transport interne documenté est gRPC (`docs/api/grpc/README.md`). **Dans ce dépôt, c'est du HTTP/JSON** avec exactement les noms de champs des messages Protobuf, uniquement dans `internal/interfaces/`. Raison : réseau restreint du sandbox de build (`NOTES_SANDBOX.md`). Ne « répare » pas cet écart de ton propre chef.
- TLS 1.3 mutuel entre services, `INTERNAL_TLS=required` par défaut. Le listener public du Gateway reste en HTTP (le TLS se termine à l'arête).
- Un client HTTP interne n'est construit que pour des pairs déclarés (`mtls.Peer{URL, Service}`) : l'identité du pair est épinglée.
- Les contrats évoluent **de façon additive** uniquement (`docs/api/grpc/README.md` §1) ; une rupture exige un package `v2`. Un numéro de champ Protobuf supprimé est `reserved`, jamais réutilisé.
