#!/usr/bin/env bash
# A second reference client against the Windows target (ADR-0071): gopher-rdp, an RDP client in Go
# on crypto/tls with CredSSP v6, SPNEGO and the SHA-256 key binding, the profile of this client.
# If it opens a session where this client is closed after its Connect-Initial, Go's TLS stack is
# not the cause. Test only: never shipped, never imported, its code is not ours (MIT).
#
#   gopher-rdp.sh WORKDIR DUMP    (the RDP_WINDOWS_* variables of test.env set)
#
# It is fetched at one pinned commit, read before being pinned, and built in pure Go (no GUI, no
# cgo) from its own go.sum. It does not check the target's certificate (InsecureSkipVerify, its
# choice): it is given only the random password of this run's test machine, on the loopback.
# Its full log stays in WORKDIR; DUMP gets it without the lines that name credentials or keys.
set -euo pipefail
work=${1:?usage: gopher-rdp.sh WORKDIR DUMP}
dump=${2:?usage: gopher-rdp.sh WORKDIR DUMP}
commit=bfc357b3a95b9bf770c38b10fd8041e0251a0955 # 2026-06-15

mkdir -p "$work/src"
cd "$work/src"
git init -q
git fetch -q --depth 1 https://github.com/bouncyball-git/gopher-rdp.git "$commit"
git checkout -q FETCH_HEAD
test "$(git rev-parse HEAD)" = "$commit"
CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -o "$work/gopher-rdp" ./client

host=${RDP_WINDOWS_ADDRESS%:*}
port=${RDP_WINDOWS_ADDRESS##*:}
status=0
timeout 40 "$work/gopher-rdp" -host "$host" -port "$port" -user "$RDP_WINDOWS_USER" -pass "$RDP_WINDOWS_PASSWORD" \
  -no-clipboard -auto-reconnect=false -heartbeat 0 -log -log-level=debug -log-file="$work/gopher-rdp.log" \
  > "$work/gopher-rdp.out" 2>&1 || status=$?
{
  grep -a -v -i -E 'pass|credential|key|hash|nonce|secret|cookie|verifier' "$work/gopher-rdp.log" "$work/gopher-rdp.out" || true
  echo "gopher-rdp exit status: $status (124: still connected after 40 s)"
} > "$dump/gopher-rdp.log"
grep -a -E -i 'error|fail|MCS|connect|activ|demand|licens|exit status' "$dump/gopher-rdp.log" | head -60 || true
