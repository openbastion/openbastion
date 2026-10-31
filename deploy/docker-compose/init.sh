#!/bin/sh
# Draws the secrets of a docker-compose installation into an env file (ADR-0033):
#   deploy/docker-compose/init.sh [path]        (default: deploy/docker-compose/.env)
# It refuses to overwrite an existing file: the keys in it are what makes the audit chain, the
# vault and the recordings readable — draw new ones and yesterday's data is lost for good.
# Keep a copy of this file outside the host (docs/deployment/backup-restore.md), never in git.
set -eu
out="${1:-$(dirname "$0")/.env}"
if [ -e "$out" ]; then
  echo "init.sh: $out already exists — refusing to overwrite it (its keys protect existing data)" >&2
  exit 1
fi
hex32() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
umask 077
{
  echo "# OpenBastion docker-compose secrets — generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by init.sh."
  echo "# Never commit this file. Losing it loses the audit chain, the vault and the recordings."
  echo "PG_SUPERUSER_PASSWORD=$(hex32)"
  for svc in AUTHENTICATION AUTHORIZATION SESSION_BROKER PASSWORD_VAULT AUDIT_SERVICE COMMAND_RECORDER; do
    echo "PG_PASSWORD_$svc=$(hex32)"
  done
  echo "VAULT_KMS_KEY_HEX=$(hex32)"
  echo "RECORDER_KMS_KEY_HEX=$(hex32)"
  echo "TOKEN_SIGNING_KEY_HEX=$(hex32)"
  echo "AUDIT_CHAIN_KEY_HEX=$(hex32)"
  echo "# The demonstration target's password (profile demo) — what the Vault holds and no one sees."
  echo "DEMO_TARGET_PASSWORD=$(hex32)"
} > "$out"
chmod 600 "$out"
echo "init.sh: secrets written to $out (mode 0600)"
