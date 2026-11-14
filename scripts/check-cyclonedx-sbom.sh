#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'cyclonedx-check: %s\n' "$1" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
file=${1:?usage: check-cyclonedx-sbom.sh <sbom.json>}
expected_spec=${2:-1.7}
[ "$expected_spec" = "1.7" ] || fail "no vendored CycloneDX JSON Schema for specVersion $expected_spec"
schema_dir="$repo_root/third_party/cyclonedx/1.7"
schema="$schema_dir/bom-1.7.schema.json"
# The schema and the three it refers to, from the same upstream revision (README.md): every
# reference resolves from these files, never from the network.
expected_schema_shas="73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce bom-1.7.schema.json
4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359 spdx.schema.json
013919cfb1c6209f919cd7253a4e3f740cb44023697bb4657a5f0584d6f47137 cryptography-defs.schema.json
8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae jsf-0.82.schema.json"
python_bin=${PYTHON:-python3}

command -v jq >/dev/null 2>&1 || fail 'jq is required'
command -v "$python_bin" >/dev/null 2>&1 || fail 'python3 is required'
[ -s "$file" ] || fail "SBOM is missing or empty: $file"
while read -r expected_sha name; do
  [ -s "$schema_dir/$name" ] || fail "vendored CycloneDX schema is missing: $schema_dir/$name"
  actual_sha=$(sha256sum "$schema_dir/$name" | awk '{print $1}')
  [ "$actual_sha" = "$expected_sha" ] || fail "vendored CycloneDX schema checksum mismatch: $name"
done <<< "$expected_schema_shas"

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
    from referencing import Registry, Resource
    from referencing.exceptions import Unresolvable
except ImportError as exc:
    print("cyclonedx-check: Python package 'jsonschema' is required", file=sys.stderr)
    raise SystemExit(2) from exc

schema_path, document_path = map(Path, sys.argv[1:3])

try:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    document = json.loads(document_path.read_text(encoding="utf-8"))
    # Every schema of the directory under its own $id. The registry has no retrieve function: a
    # reference to anything else is unresolvable and fails the check, instead of being fetched.
    resources = []
    for path in sorted(schema_path.parent.glob("*.schema.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resources.append((contents["$id"], Resource.from_contents(contents)))
    registry = Registry().with_resources(resources)
    validator_type = jsonschema.validators.validator_for(schema)
    validator_type.check_schema(schema)
    validator = validator_type(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )
except (OSError, KeyError, json.JSONDecodeError, jsonschema.SchemaError, Unresolvable) as exc:
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
