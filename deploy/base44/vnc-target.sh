#!/bin/sh
# The preview's screen target (deploy/base44/docker-compose.yml): a real TigerVNC, VeNCrypt/X.509
# only (ADR-0071 §5), showing `cat` in a terminal, so that what an operator types is visible on the
# recording and nothing typed is executed. Development values: a real target has its own.
set -eu

if [ ! -s /key/key.pem ] || [ ! -s /trust/cert.pem ]; then
  # The private key stays in this container's volume; the proxy and the seed read only the certificate.
  umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -keyout /key/key.pem -out /key/cert.pem -subj /CN=vnc-target \
    -addext subjectAltName=DNS:vnc-target 2>/dev/null
  umask 022
  cp /key/cert.pem /trust/cert.pem
fi

printf '%s' "$VNC_PASSWORD" | vncpasswd -f >/key/passwd
chmod 0600 /key/passwd

Xvnc :1 -rfbport 5901 -geometry 800x600 -depth 24 -SecurityTypes X509Vnc \
  -X509Cert /key/cert.pem -X509Key /key/key.pem -PasswordFile /key/passwd &
server=$!
until [ -S /tmp/.X11-unix/X1 ]; do
  kill -0 "$server" 2>/dev/null || { echo "vnc-target: Xvnc stopped" >&2; exit 1; }
  sleep 0.2
done
DISPLAY=:1 HOME=/tmp xterm -geometry 80x24+0+0 -e cat &
wait "$server"
