#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
checker="$script_dir/check-cyclonedx-sbom.sh"
schema="$repo_root/third_party/cyclonedx/1.7/bom-1.7.schema.json"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

command -v jq >/dev/null 2>&1 || { echo 'jq is required' >&2; exit 2; }
python_bin=${PYTHON:-python3}
"$python_bin" -c 'import jsonschema, rfc3339_validator; assert not jsonschema.FormatChecker().conforms("not-a-date", "date-time")' >/dev/null 2>&1 || { echo 'python3 packages jsonschema[format] are required' >&2; exit 2; }

expected_schema_sha='73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce'
actual_schema_sha=$(sha256sum "$schema" | awk '{print $1}')
[ "$actual_schema_sha" = "$expected_schema_sha" ] || {
  echo "test-check-cyclonedx-sbom: vendored schema checksum mismatch" >&2
  exit 1
}

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
jq '.specVersion = "1.6"' "$tmp/valid.json" > "$tmp/unsupported-schema.json"
if "$checker" "$tmp/unsupported-schema.json" 1.6; then
  echo 'test-check-cyclonedx-sbom: accepted a specVersion without a vendored schema' >&2
  exit 1
fi

jq 'del(.serialNumber)' "$tmp/valid.json" > "$tmp/missing-serial.json"
if "$checker" "$tmp/missing-serial.json"; then
  echo 'test-check-cyclonedx-sbom: accepted missing serialNumber' >&2
  exit 1
fi

jq '.components = [{"type":"library"}]' "$tmp/valid.json" > "$tmp/invalid-component.json"
if "$checker" "$tmp/invalid-component.json"; then
  echo 'test-check-cyclonedx-sbom: accepted component missing required name' >&2
  exit 1
fi

jq '.unexpected = true' "$tmp/valid.json" > "$tmp/unknown-property.json"
if "$checker" "$tmp/unknown-property.json"; then
  echo 'test-check-cyclonedx-sbom: accepted unknown top-level property' >&2
  exit 1
fi

jq '.metadata.timestamp = "not-a-date"' "$tmp/valid.json" > "$tmp/invalid-date-time.json"
if "$checker" "$tmp/invalid-date-time.json"; then
  echo 'test-check-cyclonedx-sbom: accepted invalid date-time format' >&2
  exit 1
fi

printf '{not-json\n' > "$tmp/malformed.json"
if "$checker" "$tmp/malformed.json"; then
  echo 'test-check-cyclonedx-sbom: accepted malformed JSON' >&2
  exit 1
fi

printf 'test-check-cyclonedx-sbom: official schema, contract and negative fixtures passed\n'
