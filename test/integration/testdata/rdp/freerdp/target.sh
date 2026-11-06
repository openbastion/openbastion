#!/bin/sh
# The certificate comes first: the client checks its chain, its name and its pin before CredSSP.
set -eu
config="$HOME/.config/freerdp/shadow"
mkdir -p "$config"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout "$config/shadow.key" -out "$config/shadow.crt" \
  -subj /CN=rdp-target -addext subjectAltName=DNS:rdp-target 2>/dev/null
winpr-hash3 -u "$RDP_USER" -p "$RDP_PASSWORD" -f sam >"$HOME/sam"
Xvfb :1 -screen 0 1024x768x24 -nolisten tcp &
until [ -S /tmp/.X11-unix/X1 ]; do sleep 0.2; done
DISPLAY=:1 xterm -geometry 80x24+0+0 -e cat &
DISPLAY=:1 exec freerdp-shadow-cli3 /port:3389 /sec:nla "/sam-file:$HOME/sam"
