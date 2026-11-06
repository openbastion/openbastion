#!/bin/bash
# A real TigerVNC target for pkg/vnc and the screen flow (ADR-0071), without Docker and without
# installing anything: the Debian/Ubuntu packages are unpacked in a working directory, and an
# unprivileged user namespace lays what the server expects over /usr/bin and /etc/pam.d.
#
#   target.sh <workdir> [X509Plain|X509Vnc]   starts the server, in the foreground
#   target.sh <workdir> --env                 prints the OPENBASTION_VNC_* variables of the tests
#
# X509Plain checks the password through PAM (pam_exec), X509Vnc against a password file.
# Test values, on the loopback: a real installation has its own certificate and secrets.
set -euo pipefail
work=$(mkdir -p "$1" && cd "$1" && pwd)
mode=${2:-X509Plain}
display=${VNC_DISPLAY:-77}
port=${VNC_PORT:-15977}
user=operator
plain_password=long-vault-password-42
vnc_password=secret78

if [ "$mode" = --env ]; then
  password=$plain_password
  [ "$(cat "$work/mode" 2>/dev/null)" = X509Vnc ] && password=$vnc_password
  cat <<ENV
export OPENBASTION_VNC_TARGET=127.0.0.1:$port
export OPENBASTION_VNC_CA_FILE=$work/cert.pem
export OPENBASTION_VNC_PIN=$(openssl x509 -in "$work/cert.pem" -outform der | sha256sum | cut -d' ' -f1)
export OPENBASTION_VNC_SERVER_NAME=vnc-target.test
export OPENBASTION_VNC_USER=$user
export OPENBASTION_VNC_PASSWORD=$password
ENV
  exit 0
fi
case "$mode" in X509Plain | X509Vnc) ;; *) echo "unknown mode: $mode" >&2; exit 2 ;; esac
echo "$mode" >"$work/mode"

root=$work/root
if [ ! -x "$root/usr/bin/Xtigervnc" ]; then
  mkdir -p "$work/debs" "$root"
  (cd "$work/debs" && apt-get download tigervnc-standalone-server tigervnc-common tigervnc-tools \
    libtasn1-6 libxfont2 libfontenc1 xkb-data x11-xkb-utils libxkbfile1)
  for deb in "$work"/debs/*.deb; do dpkg-deb -x "$deb" "$root"; done
fi
export LD_LIBRARY_PATH=$root/usr/lib/x86_64-linux-gnu

if [ ! -s "$work/cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
    -keyout "$work/key.pem" -out "$work/cert.pem" -subj /CN=vnc-target.test \
    -addext subjectAltName=DNS:vnc-target.test,DNS:localhost 2>/dev/null
fi
printf '%s' "$vnc_password" | "$root/usr/bin/tigervncpasswd" -f >"$work/passwd"

mkdir -p "$work/pam.d"
cat >"$work/checkpw.sh" <<CHECK
#!/bin/sh
# pam_exec gives the password on stdin.
IFS= read -r given || true
[ "\$PAM_USER" = "$user" ] && [ "\$given" = "$plain_password" ]
CHECK
chmod +x "$work/checkpw.sh"
cat >"$work/pam.d/openbastion-vnc" <<PAM
auth required pam_exec.so expose_authtok quiet $work/checkpw.sh
account required pam_permit.so
PAM

exec unshare -Urm --kill-child bash -c "
  mount -t overlay overlay -o lowerdir=$root/usr/bin:/usr/bin /usr/bin
  mount -t overlay overlay -o lowerdir=$work/pam.d:/etc/pam.d /etc/pam.d
  exec /usr/bin/Xtigervnc :$display -rfbport $port -geometry 800x600 -depth 24 -localhost=1 \
    -xkbdir $root/usr/share/X11/xkb -SecurityTypes $mode \
    -X509Cert $work/cert.pem -X509Key $work/key.pem -PasswordFile $work/passwd \
    -PlainUsers=$user -pam_service=openbastion-vnc
"
