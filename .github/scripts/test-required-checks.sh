#!/usr/bin/env bash
# Exercise every gate input against success and non-success workflow conclusions.
set -euo pipefail

script="$(dirname "$0")/required-checks.sh"
variables=(GO_RESULT INTEGRATION_RESULT POSTGRES_RESULT FRONTEND_RESULT SECURITY_RESULT CONTAINERS_RESULT)
success=(success success success success success success)

run_gate() {
  env \
    "GO_RESULT=$1" \
    "INTEGRATION_RESULT=$2" \
    "POSTGRES_RESULT=$3" \
    "FRONTEND_RESULT=$4" \
    "SECURITY_RESULT=$5" \
    "CONTAINERS_RESULT=$6" \
    bash "$script"
}

run_gate "${success[@]}" >/dev/null

for state in failure cancelled skipped neutral timed_out action_required stale ''; do
  for index in "${!variables[@]}"; do
    results=("${success[@]}")
    results[$index]="$state"
    if run_gate "${results[@]}" >/dev/null 2>&1; then
      printf 'FAIL: %s=%q unexpectedly passed\n' "${variables[$index]}" "$state" >&2
      exit 1
    fi
  done
done

for variable in "${variables[@]}"; do
  assignments=()
  for candidate in "${variables[@]}"; do
    [[ "$candidate" == "$variable" ]] || assignments+=("$candidate=success")
  done
  if env -u "$variable" "${assignments[@]}" bash "$script" >/dev/null 2>&1; then
    printf 'FAIL: missing %s unexpectedly passed\n' "$variable" >&2
    exit 1
  fi
done

printf 'PASS: required-checks gate rejects every non-success and missing result\n'
