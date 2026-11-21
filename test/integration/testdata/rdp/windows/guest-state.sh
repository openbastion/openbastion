#!/usr/bin/env bash
# guest-state.sh OUTDIR NAME: the Windows virtual machine's state at this instant, for a test that
# has just lost it (ADR-0071, CI instability "B": the target lost during TestRDPWindows_Measure,
# cause not established). Called by the engine's Windows tests on failure (RDP_WINDOWS_GUEST_STATE);
# every part is bounded and best effort, a part that fails says so and the rest goes on.
#
#   OUTDIR/NAME.png       the screen, from QEMU's own VNC console (vnc_snapshot.py), whatever RDP says
#   OUTDIR/NAME.txt       the guest's pulse (COM1, oem/rdp-setup.ps1) and the age of its last copy to the
#                         share, QEMU's monitor (info status, info cpus), the container's and the host's load,
#                         memory and the end of the kernel log (an OOM kill, a KVM error)
#
# Diagnostic of the test machine only: it reads, it changes nothing in the guest.
set -u
out=${1:?OUTDIR}
name=${2:?NAME}
here=$(cd "$(dirname "$0")" && pwd)
container=openbastion-rdp-windows
mkdir -p "$out"
txt="$out/$name.txt"
{
  echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) $name"
  ip=$(timeout 10 docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container" 2>&1)
  echo "== screen (QEMU VNC console, $ip:5900)"
  timeout 30 python3 "$here/vnc_snapshot.py" "$ip" 5900 "$out/$name.png" 2>&1 || echo "screen: failed ($?)"
  echo "== QEMU monitor (/run/shm/monitor.sock)"
  # HMP on a Unix socket: whichever client the image has.
  timeout 20 docker exec "$container" sh -c '
    q() { printf "%s\n" "$1" | {
      if command -v socat >/dev/null 2>&1; then socat -t 3 - UNIX-CONNECT:/run/shm/monitor.sock;
      elif command -v nc >/dev/null 2>&1; then nc -q 3 -U /run/shm/monitor.sock 2>/dev/null || nc -U /run/shm/monitor.sock;
      elif command -v python3 >/dev/null 2>&1; then python3 -c "import socket,sys,time;s=socket.socket(socket.AF_UNIX);s.connect(\"/run/shm/monitor.sock\");s.sendall(sys.stdin.read().encode());time.sleep(2);s.settimeout(1);print(s.recv(65536).decode(errors=\"replace\"))";
      else echo "no client for the monitor (socat, nc, python3)"; fi; }; }
    q "info status"; q "info cpus"' 2>&1 || echo "monitor: failed ($?)"
  # The guest's own word (oem/rdp-setup.ps1, guest-pulse.ps1): one line every 5 s on COM1, which
  # QEMU writes to the container's output, whatever the share and RDP do. The last lines show what
  # used the processors up to the loss, and when the guest stopped saying anything.
  echo "== guest pulse (COM1, every 5 s; cpu in % of one core)"
  pulse=$(timeout 20 docker logs --since 30m "$container" 2>&1 | tr -d '\r' | grep -a 'OBPULSE' | tail -n 36)
  [ -n "$pulse" ] || pulse=$(timeout 20 docker exec "$container" sh -c 'tr -d "\r" < /run/shm/qemu.pty 2>/dev/null | grep -a OBPULSE | tail -n 36' 2>&1)
  printf '%s\n' "${pulse:-pulse: no line (COM1 not written, or the guest never ran guest-pulse.ps1)}"
  # The export loop's last copy to the share: in the losses of 19 and 20 November it stopped
  # 30 s to 2 min before RDP fell silent.
  shared=${RDP_WINDOWS_SHARED:-${RUNNER_TEMP:-/nonexistent}/windows/shared}
  echo "== the guest's copies to the share ($shared)"
  if [ -f "$shared/export-status.txt" ]; then
    echo "export-status.txt written $(( $(date +%s) - $(stat -c %Y "$shared/export-status.txt") )) s ago: $(tr -d '\r\357\273\277' < "$shared/export-status.txt" | head -c 300)"
  else
    echo "no export-status.txt"
  fi
  echo "== container"
  timeout 20 docker stats --no-stream "$container" 2>&1 || true
  timeout 10 docker exec "$container" sh -c 'ps -o pid,stat,pcpu,pmem,etime,comm -C qemu-system-x86_64 2>/dev/null || ps aux | grep -i qemu | head -3' 2>&1 || true
  echo "== host"
  uptime 2>&1; free -m 2>&1
  echo "== kernel (last lines)"
  timeout 10 sudo -n dmesg 2>/dev/null | tail -n 25 || echo "dmesg: unavailable"
} > "$txt" 2>&1
echo "$txt"
