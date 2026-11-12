#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'license-check: %s\n' "$1" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || fail 'jq is required'
command -v node >/dev/null 2>&1 || fail 'node is required for Agent Skills provenance verification'

jq -e '.license == "AGPL-3.0-only"' web/admin-ui/package.json >/dev/null || fail 'Admin UI package.json must declare AGPL-3.0-only'
jq -e '.license == "AGPL-3.0-only"' web/packages/icons/package.json >/dev/null || fail 'icons package.json must declare AGPL-3.0-only'
jq -e '.packages[""].license == "AGPL-3.0-only" and .packages["../packages/icons"].license == "AGPL-3.0-only"' web/admin-ui/package-lock.json >/dev/null || fail 'Admin UI lockfile licence metadata is inconsistent'
jq -e '.packages[""].license == "AGPL-3.0-only"' web/packages/icons/package-lock.json >/dev/null || fail 'icons lockfile licence metadata is inconsistent'
grep -Eq 'identifier:[[:space:]]*AGPL-3.0-only' docs/api/rest/openapi.yaml || fail 'OpenAPI SPDX identifier is inconsistent'
grep -Eq 'license:[[:space:]]*AGPL-3.0-only' .agents/settings/project.yaml || fail 'project SPDX identifier is inconsistent'
cmp -s LICENSE web/packages/icons/LICENSE || fail 'icons package LICENSE must match the canonical root LICENSE'
node scripts/check-skills-provenance.mjs
printf 'license-check: project SPDX metadata and third-party notices are consistent\n'
