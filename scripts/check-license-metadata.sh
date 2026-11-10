#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'license-check: %s\n' "$1" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || fail 'jq is required'

jq -e '.license == "AGPL-3.0-only"' web/admin-ui/package.json >/dev/null || fail 'Admin UI package.json must declare AGPL-3.0-only'
jq -e '.license == "AGPL-3.0-only"' web/openbastion-icons/package.json >/dev/null || fail 'icons package.json must declare AGPL-3.0-only'
jq -e '.packages[""].license == "AGPL-3.0-only" and .packages["../openbastion-icons"].license == "AGPL-3.0-only"' web/admin-ui/package-lock.json >/dev/null || fail 'Admin UI lockfile licence metadata is inconsistent'
jq -e '.packages[""].license == "AGPL-3.0-only"' web/openbastion-icons/package-lock.json >/dev/null || fail 'icons lockfile licence metadata is inconsistent'
grep -Eq 'identifier:[[:space:]]*AGPL-3.0-only' docs/api/rest/openapi.yaml || fail 'OpenAPI SPDX identifier is inconsistent'
grep -Eq 'license:[[:space:]]*AGPL-3.0-only' .agents/settings/project.yaml || fail 'project SPDX identifier is inconsistent'
cmp -s LICENSE web/openbastion-icons/LICENSE || fail 'icons package LICENSE must match the canonical root LICENSE'
grep -Fq 'Copyright (c) 2026 Samuel Berthe' THIRD_PARTY_NOTICES.md || fail 'MIT copyright notice is missing'
test -s docs/licensing/skills-provenance.md || fail 'Agent Skills provenance inventory is missing'
printf 'license-check: project SPDX metadata and third-party notices are consistent\n'
