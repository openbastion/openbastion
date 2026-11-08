#!/bin/sh
# The certificate comes first: the client checks its chain, its name and its pin before CredSSP.
set -eu
config="$HOME/.config/freerdp/shadow"
mkdir -p "$config"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout "$config/shadow.key" -out "$config/shadow.crt" \
  -subj /CN=rdp-target -addext subjectAltName=DNS:rdp-target 2>/dev/null
winpr-hash3 -u "$RDP_USER" -p "$RDP_PASSWORD" -f sam >"$HOME/sam"
# Xvfb keeps its size. RDP_DISPLAY=resizable takes Xvnc, whose size xrandr changes during a session
# (`xrandr -s 1024x768`): the server then reactivates its clients at the new size (ADR-0071).
if [ "${RDP_DISPLAY:-}" = resizable ]; then
  Xvnc :1 -geometry 1280x800 -depth 24 -SecurityTypes None -localhost -rfbport 5999 -nolisten tcp &
else
  Xvfb :1 -screen 0 1280x800x24 -nolisten tcp &
fi
until [ -S /tmp/.X11-unix/X1 ]; do sleep 0.2; done
DISPLAY=:1 xterm -geometry 80x24+0+0 -e cat &
DISPLAY=:1 exec freerdp-shadow-cli3 /port:3389 /sec:nla "/sam-file:$HOME/sam"
