#!/bin/sh
# Previews only, in the Base44 sandbox (docker-compose.base44.yml): a new installation has no
# user and no demo password (deploy/docker-compose/README.md), so the preview could not even be
# logged into. This one-shot service does the documented first-run journey — the operator
# account through the CLI, everything else through the public API — and nothing else.
# It is idempotent: what exists is not written again.
set -eu

GATEWAY=${GATEWAY_URL:-http://api-gateway:8080}
AUTHN=${AUTHENTICATION_URL:-https://authentication:8086}
USER_NAME=${OPERATOR_USERNAME:-operator}
PASSWORD=${OPERATOR_PASSWORD:-openbastion-demo}
AUDITOR_NAME=${AUDITOR_USERNAME:-auditor}
AUDITOR_PASSWORD=${AUDITOR_PASSWORD:-openbastion-demo}

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

# The screen target of the preview, on an installation of any age (ADR-0071): an account whose
# certificate is pinned, read from the target's own volume, and the right to open a session on it.
#
# Done means the account pins this target's certificate, not merely that the account exists: an
# interrupted run or a recreated target is repaired here. A refused step stops the seed, so that the
# service does not report as seeded a preview that cannot open a screen. 409: already there.
seed_vnc() {
  token=$1
  pin=$(openssl x509 -in /trust/cert.pem -outform der | sha256sum | cut -d' ' -f1)
  if curl -sS "$GATEWAY/vault/accounts/acc_demo_vnc" -H "Authorization: Bearer $token" |
    grep -q "\"tlsCertificateSha256\":\"$pin\""; then
    log "acc_demo_vnc already pins the target"
    return 0
  fi
  log "onboarding the VNC demonstration account"
  step 'VNC policy' POST /policies \
    '{"name":"vault-admin-demo-screen","role":"vault-admin","resourcePattern":"vault:account:acc_demo_vnc","effect":"allow"}'
  step 'VNC account' POST /vault/accounts \
    "{\"id\":\"acc_demo_vnc\",\"name\":\"demo-desktop\",\"username\":\"operator\",
      \"targetHost\":\"vnc-target:5901\",\"protocol\":\"vnc\",\"rotationPolicy\":\"manual\",
      \"initialSecret\":\"$(printf '%s' "$VNC_TARGET_PASSWORD" | base64 | tr -d '\n')\"}"
  step 'VNC pin' PUT /vault/accounts/acc_demo_vnc/tls-pin \
    "{\"tlsCertificateSha256\":\"$pin\",\"targetDomain\":\"vnc-target\"}"
}

# The SSH target of the preview (demo-ssh-target), by the same rule: done means the account pins
# this target's host key (ADR-0039). That key derives from SSH_TARGET_PASSWORD: its private half is
# as public as this development password, which is all a target that executes nothing needs.
# An account from before this target points at a machine that does not exist, and the API cannot
# move it: it gets no right to a session, and the log says what to do.
SSH_HOST_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDcmLFmmVd4+WLuTaTGBq+u7taFcTBqDl2G7rRblW3oe'
seed_ssh() {
  token=$1
  account=$(curl -sS "$GATEWAY/vault/accounts/acc_demo" -H "Authorization: Bearer $token")
  case "$account" in
    *'"targetHost":"10.0.4.12:22"'*)
      log "acc_demo predates the demonstration target: no SSH session on it until the preview's volumes are recreated"
      return 0 ;;
    *"\"hostKey\":\"$SSH_HOST_KEY"*)
      log "acc_demo already pins the target"
      return 0 ;;
  esac
  log "onboarding the SSH demonstration account"
  step 'SSH policy' POST /policies \
    '{"name":"vault-admin-demo-ssh","role":"vault-admin","resourcePattern":"vault:account:acc_demo","effect":"allow"}'
  step 'SSH account' POST /vault/accounts \
    "{\"id\":\"acc_demo\",\"name\":\"demo-shell\",\"username\":\"root\",
      \"targetHost\":\"demo-ssh-target:2022\",\"protocol\":\"ssh\",\"rotationPolicy\":\"manual\",
      \"initialSecret\":\"$(printf '%s' "$SSH_TARGET_PASSWORD" | base64 | tr -d '\n')\",
      \"hostKey\":\"$SSH_HOST_KEY\"}"
  step 'SSH host key' PUT /vault/accounts/acc_demo/host-key "{\"hostKey\":\"$SSH_HOST_KEY\"}"
}

# Who may replay a recording (ADR-0070): an auditor, not the operator who held the session. A
# separate account, with the session-auditor role and the policy that reads any recording of the
# preview. The account through the CLI, like the operator; the policy through the public API.
seed_auditor() {
  token=$1
  printf '%s\n' "$AUDITOR_PASSWORD" | go run github.com/openbastion/openbastion/cli/openbastion-cli user create \
    -authn "$AUTHN" -username "$AUDITOR_NAME" -display "Auditeur" \
    -roles session-auditor 2>&1 | sed 's/^/seed: /' || true
  step 'recording read policy' POST /policies \
    '{"name":"session-auditor-recordings","role":"session-auditor","resourcePattern":"recording:session:*","effect":"allow"}'
}

step() {
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X "$2" "$GATEWAY$3" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$4")
  log "$1 -> HTTP $code"
  case "$code" in
    2??|409) ;;
    *) log "$1 was refused — stopping"; exit 1 ;;
  esac
}

TOKEN=$(login)
if [ -n "$TOKEN" ]; then
  log "$USER_NAME already exists"
  seed_ssh "$TOKEN"
  seed_vnc "$TOKEN"
  seed_auditor "$TOKEN"
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

seed_ssh "$TOKEN"
seed_vnc "$TOKEN"
seed_auditor "$TOKEN"

log "done — log in as $USER_NAME, and as $AUDITOR_NAME to replay a recording"
