# OpenBastion with docker-compose (ADR-0033)

One host, eight core services under mutual TLS, one PostgreSQL database per service, two ports
published on `127.0.0.1`: the public API of the Gateway and the SSH port of the proxy. The
Video Recorder and SeaweedFS are added by the optional `recording` profile.
For development and small on-premise installations; not a high-availability setup
(`docs/deployment/high-availability.md`).

## Start

```sh
deploy/docker-compose/init.sh          # once: draws the secrets into deploy/docker-compose/.env (0600)
docker compose -f deploy/docker-compose/docker-compose.yml up -d --build --wait
```

Compose builds the shared Go runtime image once (on `authentication`), the tools image once (on `pki`) and a hardened PostgreSQL 16 image. The PostgreSQL image starts from a pinned upstream multi-architecture digest and applies available Debian security updates during the build; the `postgres` and optional `video-recorder-db-init` services reuse it.

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

## Graphical VNC sessions (ADR-0071)

The Go-native proxy is optional and currently serves **VNC only**; RDP is deliberately refused until its engine and protocol-security tests exist. It uses a separate, explicit PEM bundle for target TLS trust. Do not point it at the internal service CA unless that CA is intentionally the trust anchor for the VNC targets.

1. Set `SCREEN_TARGET_CA_FILE` to a host path containing the PEM CA certificates that should trust the VNC targets.
2. Configure the Video Recorder profile as described above, then enable both profiles:

   ```sh
   docker compose --env-file deploy/docker-compose/.env \
     --env-file deploy/docker-compose/.env.recording \
     -f deploy/docker-compose/docker-compose.yml \
     --profile recording --profile rdp-vnc up -d --build --wait
   ```

The Session Broker routes a session based on its stored protocol. The Gateway returns an HttpOnly, SameSite=Strict one-use attach cookie for VNC and relays the binary screen WebSocket; the proxy ticket is never returned to browser JavaScript. The Admin UI's live screen viewer is still pending.

## What lives where

| Volume | Holds | Mounted in |
|---|---|---|
| `postgres` | the seven service databases | `postgres` |
| `pki-ca` | the internal authority **and its key** | the `pki` job only |
| `pki` | each service's certificate and key, one directory each | each service: **its own directory only**, read-only |
| `anchors` | the anchors of the audit chain (ADR-0028) | `audit-service` |
| `archives` | the audit archives (ADR-0032), when retention is on | `audit-service` |
| `seaweedfs-data` | encrypted Video Recorder objects (with `--profile recording`) | `seaweedfs` |
| `seaweedfs-config` | generated S3 identities (with `--profile recording`) | `seaweedfs-config`, `seaweedfs` |

The `pki` job runs at every `up`: it keeps the authority and renews the services'
certificates (`OB_CERT_TTL`, 720 h by default) — run `up` again before they expire.

## Video recordings

The default stack does not enable video storage. The separate profile requires an external
Transit endpoint and an operator-provided token/CA; it uses SeaweedFS 4.51 over HTTPS with
client-certificate verification and stores object data in the persistent `seaweedfs-data`
volume. Video segments are encrypted by the Recorder before they reach S3.

1. Put these values in `deploy/docker-compose/.env`: `VIDEO_RECORDER_TRANSIT_ADDR` (HTTPS),
   `VIDEO_RECORDER_TRANSIT_KEY`, `VIDEO_RECORDER_TRANSIT_TOKEN_FILE` (host path) and
   `VIDEO_RECORDER_TRANSIT_CA_FILE` (host path). The token file must be owned by UID 65532 and
   mode `0400`; the CA file must be readable by the service.
2. On installations created before video recording was added, generate a separate, mode-0600
   credentials file without changing the existing `.env`:

   ```sh
   deploy/docker-compose/init-recording.sh
   ```

   Fresh installations already have these credentials in `.env` from `init.sh`; do not create a
   second credentials file for them. For an older installation, pass both files to Compose. The
   profile's database-init job creates the Video Recorder role and database on an existing
   PostgreSQL volume without changing other service databases. That one-shot job receives
   `PG_SUPERUSER_PASSWORD` to perform the bootstrap, has no published port, and exits before the
   Recorder starts.
3. Ensure the Transit policy allows encrypt/decrypt with that key, then start. For an older
   installation, include both env files:

   ```sh
   docker compose --env-file deploy/docker-compose/.env \
     --env-file deploy/docker-compose/.env.recording \
     -f deploy/docker-compose/docker-compose.yml --profile recording up -d --build --wait
   ```

   For a fresh installation, use the standard command with no `--env-file` options.

`init.sh` creates dedicated S3 credentials in `.env`; they are mounted only into the Recorder and
the SeaweedFS configuration job. The identity currently has `Admin` because the Recorder creates
the bucket on startup; keep this SeaweedFS instance and its generated credentials dedicated to
recordings. A compromised Recorder could delete or reconfigure buckets on this instance. The
Recorder refuses to start if PostgreSQL, Authorization,
Audit, Transit, the S3 bucket or its TLS identity is unavailable. The production Compose profile
does not fall back to a local KEK. Back up `seaweedfs-data` together with the Video Recorder
PostgreSQL metadata and retain the Transit key independently.

## Settings

| Variable | Default | |
|---|---|---|
| `OB_BIND` | `127.0.0.1` | address the two ports are published on |
| `OB_GATEWAY_PORT` | `8080` | public API |
| `OB_SSH_PORT` | `2222` | SSH proxy |
| `OB_CERT_TTL` | `720h` | lifetime of the services' certificates |
| `AUDIT_ARCHIVE_DIR`, `AUDIT_RETENTION_MONTHS` | off | audit retention (ADR-0032): `/var/lib/openbastion/archives` and a number of months |
| `VIDEO_RECORDER_TRANSIT_ADDR`, `VIDEO_RECORDER_TRANSIT_KEY`, `VIDEO_RECORDER_TRANSIT_TOKEN_FILE`, `VIDEO_RECORDER_TRANSIT_CA_FILE` | required with `--profile recording` | Transit wrapping key and credentials for the Video Recorder (ADR-0070) |

## Limits

- PostgreSQL is reached in clear on the Compose network (`sslmode=disable`): fine on one host,
  not for a database elsewhere.
- Base images are pinned by digest (ADR-0051), which means they are not updated by themselves: to
  update one, read its new index digest (`docker buildx imagetools inspect <name>:<tag>`), replace it
  in the `Dockerfile` or here, build, and run `make test-compose`. `test/integration/images_test.go`
  refuses an image pulled without a digest. The build images use Go 1.27.3, the version of the CI (ADR-0052).
- One instance of each service.

## Test

`COMPOSE_TEST=1 go test -run TestCompose ./test/integration/` builds and starts this stack and
goes through the whole journey on the published ports (`test/integration/compose_test.go`).
