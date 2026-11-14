# CycloneDX JSON Schema 1.7

This directory vendors the official CycloneDX 1.7 JSON Schema for offline,
reproducible validation of generated SBOMs.

- Upstream: https://github.com/CycloneDX/specification
- Source path: `schema/bom-1.7.schema.json`
- Upstream revision: `6470e34ef83f915868ece48934cff52e10c9eb49`
- Upstream license: Apache License 2.0 (see [LICENSE](LICENSE))
- SHA-256: `73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce`

The three schemas it refers to, from the same upstream revision (`schema/` directory), so that
every `$ref` resolves offline. Validation never fetches a schema: a reference to anything else
fails the check.

| File | SHA-256 |
| --- | --- |
| `spdx.schema.json` | `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359` |
| `cryptography-defs.schema.json` | `013919cfb1c6209f919cd7253a4e3f740cb44023697bb4657a5f0584d6f47137` |
| `jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

Do not edit these schemas locally. Update it only from an explicitly reviewed
upstream revision, and update this provenance record and the checksums (here and in
`scripts/check-cyclonedx-sbom.sh`) together.
