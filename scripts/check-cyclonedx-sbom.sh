#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'cyclonedx-check: %s\n' "$1" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
file=${1:?usage: check-cyclonedx-sbom.sh <sbom.json>}
expected_spec=${2:-1.7}
[ "$expected_spec" = "1.7" ] || fail "no vendored CycloneDX JSON Schema for specVersion $expected_spec"
schema="$repo_root/third_party/cyclonedx/1.7/bom-1.7.schema.json"
expected_schema_sha="73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce"
python_bin=${PYTHON:-python3}

command -v jq >/dev/null 2>&1 || fail 'jq is required'
command -v "$python_bin" >/dev/null 2>&1 || fail 'python3 is required'
[ -s "$file" ] || fail "SBOM is missing or empty: $file"
[ -s "$schema" ] || fail "vendored CycloneDX schema is missing: $schema"
actual_schema_sha=$(sha256sum "$schema" | awk '{print $1}')
[ "$actual_schema_sha" = "$expected_schema_sha" ] || fail "vendored CycloneDX schema checksum mismatch"

jq -e --arg spec "$expected_spec" '
  .bomFormat == "CycloneDX" and
  .specVersion == $spec and
  (.version | type == "number" and floor == . and . >= 1) and
  (.serialNumber | type == "string" and test("^urn:uuid:[0-9a-fA-F-]{36}$")) and
  (.metadata | type == "object") and
  (.components | type == "array")
' "$file" >/dev/null 2>&1 || fail "invalid CycloneDX document or unsupported specVersion (expected $expected_spec)"

"$python_bin" - "$schema" "$file" <<'PY'
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError as exc:
    print("cyclonedx-check: Python package 'jsonschema' is required", file=sys.stderr)
    raise SystemExit(2) from exc

schema_path, document_path = map(Path, sys.argv[1:3])

try:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    document = json.loads(document_path.read_text(encoding="utf-8"))
    validator_type = jsonschema.validators.validator_for(schema)
    validator_type.check_schema(schema)
    validator = validator_type(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )
except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
    print(f"cyclonedx-check: unable to load or validate schema/document: {exc}", file=sys.stderr)
    raise SystemExit(2) from exc

if errors:
    for error in errors[:20]:
        location = "$"
        for part in error.absolute_path:
            location += f"[{part}]" if isinstance(part, int) else f".{part}"
        print(f"cyclonedx-check: JSON Schema violation at {location}: {error.message}", file=sys.stderr)
    if len(errors) > 20:
        print(f"cyclonedx-check: {len(errors) - 20} additional violation(s) omitted", file=sys.stderr)
    raise SystemExit(1)
PY

printf 'cyclonedx-check: %s is valid against the official CycloneDX %s JSON Schema and OpenBastion contract\n' "$file" "$expected_spec"
