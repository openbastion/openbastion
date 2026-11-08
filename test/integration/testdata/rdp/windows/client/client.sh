#!/bin/sh
# Connects xfreerdp3 to RDP_HOST for 40 s and says how it ended. The test authority is trusted by
# installing it (mounted at /usr/local/share/ca-certificates/rdp-test.crt), and /cert:deny refuses
# any certificate it does not vouch for: nothing is accepted on first use.
# 124 (timeout) means the session was still up after 40 s; anything else, FreeRDP stopped it.
set -u
update-ca-certificates >/dev/null 2>&1
Xvfb :1 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
DISPLAY=:1 timeout 40 xfreerdp3 "/v:${RDP_HOST:?}" "/u:${RDP_USER:?}" "/p:${RDP_PASSWORD:?}" \
  /sec:nla /cert:deny /size:1280x800 /log-level:DEBUG
status=$?
echo "xfreerdp3 exit status: $status"
exit 0
