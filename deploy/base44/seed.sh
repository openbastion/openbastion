#!/bin/sh
# Previews only, in the Base44 sandbox (docker-compose.base44.yml): a new installation has no
# user and no demo password (deploy/docker-compose/README.md), so the preview could not even be
# logged into. This one-shot service does the documented first-run journey — the operator
# account through the CLI, everything else through the public API — and nothing else.
# It is idempotent: once the operator can log in, it exits without writing anything.
set -eu

GATEWAY=${GATEWAY_URL:-http://api-gateway:8080}
AUTHN=${AUTHENTICATION_URL:-https://authentication:8086}
USER_NAME=${OPERATOR_USERNAME:-operator}
PASSWORD=${OPERATOR_PASSWORD:-openbastion-demo}

log() { echo "seed: $*"; }

login() {
  curl -fsS -X POST "$GATEWAY/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER_NAME\",\"password\":\"$PASSWORD\"}" 2>/dev/null |
    sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p'
}

log "waiting for the gateway"
i=0
until curl -fsS "$GATEWAY/healthz" >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -gt 90 ] && { log "the gateway never answered — giving up"; exit 1; }
  sleep 2
done

if [ -n "$(login)" ]; then
  log "$USER_NAME already exists — nothing to do"
  exit 0
fi

# The first user: the internal route under the admin-cli identity (deploy/docker-compose/README.md).
log "creating the operator $USER_NAME"
printf '%s\n' "$PASSWORD" | go run github.com/openbastion/openbastion/cli/openbastion-cli user create \
  -authn "$AUTHN" -username "$USER_NAME" -display "Opérateur" \
  -roles platform-admin,vault-admin 2>&1 | sed 's/^/seed: /' || true

TOKEN=$(login)
[ -n "$TOKEN" ] || { log "the operator cannot log in — stopping"; exit 1; }

# The policy that lets the Vault-administering role list and manage the Vault's accounts.
log "creating the vault-admin policy"
curl -sS -o /dev/null -w 'seed: policy -> HTTP %{http_code}\n' -X POST "$GATEWAY/policies" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"vault-admin-accounts","role":"vault-admin","resourcePattern":"vault:account-admin:*","effect":"allow"}'

# One privileged account, so the admin UI has something real to show. Its target is fictitious:
# the pinned host key (ADR-0039) is one whose private half was discarded — no machine has it.
log "onboarding the demonstration account"
curl -sS -o /dev/null -w 'seed: account -> HTTP %{http_code}\n' -X POST "$GATEWAY/vault/accounts" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"id\":\"acc_demo\",\"name\":\"prod-db-01-root\",\"username\":\"root\",
       \"targetHost\":\"10.0.4.12:22\",\"protocol\":\"ssh\",\"rotationPolicy\":\"manual\",
       \"initialSecret\":\"$(printf '%s' 'demo-only-do-not-use-in-prod' | base64 | tr -d '\n')\",
       \"hostKey\":\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC+pXuNMSq8lVqUNZ0A+gFlXPmbP+09vCp5Y/mHuzYpS\"}"

log "done — log in as $USER_NAME"
