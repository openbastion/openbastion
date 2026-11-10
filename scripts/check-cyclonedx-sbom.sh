#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'cyclonedx-check: %s\n' "$1" >&2; exit 1; }

file=${1:?usage: check-cyclonedx-sbom.sh <sbom.json>}
expected_spec=${2:-1.7}
command -v jq >/dev/null 2>&1 || fail 'jq is required'
[ -s "$file" ] || fail "SBOM is missing or empty: $file"

jq -e --arg spec "$expected_spec" '
  .bomFormat == "CycloneDX" and
  .specVersion == $spec and
  (.version | type == "number" and . >= 1) and
  (.serialNumber | type == "string" and test("^urn:uuid:[0-9a-fA-F-]{36}$")) and
  (.metadata | type == "object") and
  (.components | type == "array")
' "$file" >/dev/null 2>&1 || fail "invalid CycloneDX document or unsupported specVersion (expected $expected_spec)"

printf 'cyclonedx-check: %s is a CycloneDX %s document\n' "$file" "$expected_spec"
