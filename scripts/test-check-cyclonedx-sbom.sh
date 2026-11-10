#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
checker="$script_dir/check-cyclonedx-sbom.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/valid.json" <<'JSON'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
  "version": 1,
  "metadata": {},
  "components": []
}
JSON

"$checker" "$tmp/valid.json"

jq '.specVersion = "1.6"' "$tmp/valid.json" > "$tmp/wrong-version.json"
if "$checker" "$tmp/wrong-version.json"; then
  echo 'test-check-cyclonedx-sbom: accepted unsupported specVersion' >&2
  exit 1
fi

jq 'del(.serialNumber)' "$tmp/valid.json" > "$tmp/missing-serial.json"
if "$checker" "$tmp/missing-serial.json"; then
  echo 'test-check-cyclonedx-sbom: accepted missing serialNumber' >&2
  exit 1
fi

printf '{not-json\n' > "$tmp/malformed.json"
if "$checker" "$tmp/malformed.json"; then
  echo 'test-check-cyclonedx-sbom: accepted malformed JSON' >&2
  exit 1
fi

printf 'test-check-cyclonedx-sbom: positive and negative fixtures passed\n'
