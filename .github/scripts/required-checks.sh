#!/usr/bin/env bash
# Fail-closed gate for the reusable CI workflows (ADR-0077).
set -euo pipefail

failed=0

require_success() {
  local name="$1"
  local result="$2"

  if [[ "$result" == "success" ]]; then
    printf 'PASS: %s (%s)\n' "$name" "$result"
  else
    printf '::error title=Required workflow did not succeed::%s returned %s\n' "$name" "$result"
    failed=1
  fi
}

require_success "Go" "${GO_RESULT-}"
require_success "Integration" "${INTEGRATION_RESULT-}"
require_success "PostgreSQL" "${POSTGRES_RESULT-}"
require_success "Frontend" "${FRONTEND_RESULT-}"
require_success "Security" "${SECURITY_RESULT-}"
require_success "Containers" "${CONTAINERS_RESULT-}"

exit "$failed"
