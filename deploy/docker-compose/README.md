# OpenBastion with docker-compose (ADR-0033)

One host, eight services under mutual TLS, one PostgreSQL database per service, two ports
published on `127.0.0.1`: the public API of the Gateway and the SSH port of the proxy.
For development and small on-premise installations; not a high-availability setup
(`docs/deployment/high-availability.md`).

## Start

```sh
deploy/docker-compose/init.sh          # once: draws the secrets into deploy/docker-compose/.env (0600)
docker compose -f deploy/docker-compose/docker-compose.yml up -d --build --wait
```

`init.sh` refuses to overwrite an existing `.env`: its keys are what makes the audit chain,
the vault and the recordings readable. **Keep a copy of it outside the host, never in git.**

## The first users

No user exists, and there is no demo password. The CLI creates them, under the `admin-cli`
identity, with the password on standard input:

```sh
C="docker compose -f deploy/docker-compose/docker-compose.yml"
read -rs PW; echo "$PW" | $C run --rm -T cli user create \
  -authn https://authentication:8086 -username alice -roles platform-admin,vault-admin
$C run --rm -T cli audit verify-chain -audit https://audit-service:8082
```

The Authorization Service gives the role `platform-admin` (`BOOTSTRAP_ADMIN_ROLE`) the right
to create policies on its first start. Everything else — policies, accounts, sessions,
recordings — goes through the public API at `http://127.0.0.1:8080` (`docs/api/`).

## Demonstration target

`--profile demo` adds `demo-ssh-target:2022`, a pretend SSH shell (nothing typed is
executed) whose password is `DEMO_TARGET_PASSWORD` in `.env`: onboard it in the Vault, open a
session, connect to `127.0.0.1:2222` with the ticket as password.

Onboarding needs the target's host key (ADR-0039): the proxy sends the password only to the
server that presents it. The demonstration target prints its key when it starts, and keeps
it across restarts:

```sh
$C logs demo-ssh-target | grep 'host key'
# demo-ssh-target host key: ssh-ed25519 AAAA…   -> "hostKey" when onboarding the account
```

For a real target, read the key on the target itself (`/etc/ssh/ssh_host_ed25519_key.pub`),
not over the network the pin protects.

## What lives where

| Volume | Holds | Mounted in |
|---|---|---|
| `postgres` | the six databases | `postgres` |
| `pki-ca` | the internal authority **and its key** | the `pki` job only |
| `pki` | each service's certificate and key, one directory each | each service: **its own directory only**, read-only |
| `anchors` | the anchors of the audit chain (ADR-0028) | `audit-service` |
| `archives` | the audit archives (ADR-0032), when retention is on | `audit-service` |

The `pki` job runs at every `up`: it keeps the authority and renews the services'
certificates (`OB_CERT_TTL`, 720 h by default) — run `up` again before they expire.

## Settings

| Variable | Default | |
|---|---|---|
| `OB_BIND` | `127.0.0.1` | address the two ports are published on |
| `OB_GATEWAY_PORT` | `8080` | public API |
| `OB_SSH_PORT` | `2222` | SSH proxy |
| `OB_CERT_TTL` | `720h` | lifetime of the services' certificates |
| `AUDIT_ARCHIVE_DIR`, `AUDIT_RETENTION_MONTHS` | off | audit retention (ADR-0032): `/var/lib/openbastion/archives` and a number of months |

## Limits

- PostgreSQL is reached in clear on the Compose network (`sslmode=disable`): fine on one host,
  not for a database elsewhere.
- Base images are named by tag, not pinned by digest.
- One instance of each service.

## Test

`COMPOSE_TEST=1 go test -run TestCompose ./test/integration/` builds and starts this stack and
goes through the whole journey on the published ports (`test/integration/compose_test.go`).
