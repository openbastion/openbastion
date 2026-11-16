#!/bin/bash
# Start a real TigerVNC target and an independent X11 input oracle.
# The CI runner installs TigerVNC/X11 packages before invoking this script.
# Only the dedicated PAM service file is installed with elevated privileges;
# Xtigervnc and xev themselves run as the invoking (unprivileged) user.
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
plain_password=${VNC_PLAIN_PASSWORD:-long-vault-password-42}
vnc_password=secret78
pam_service=openbastion-vnc
server_pid=
xev_pid=
pam_installed=0

install_privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

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
export OPENBASTION_VNC_INPUT_LOG=$work/input.log
ENV
  exit 0
fi
case "$mode" in X509Plain | X509Vnc) ;; *) echo "unknown mode: $mode" >&2; exit 2 ;; esac

for command in Xtigervnc tigervncpasswd xev openssl; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command '$command' is missing; install the TigerVNC and x11-utils runner packages" >&2
    exit 1
  }
done
if [[ "$work" =~ [[:space:]] ]]; then
  echo "work directory must not contain whitespace for the PAM exec path: $work" >&2
  exit 2
fi

echo "$mode" >"$work/mode"

if [ ! -s "$work/cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
    -keyout "$work/key.pem" -out "$work/cert.pem" -subj /CN=vnc-target.test \
    -addext subjectAltName=DNS:vnc-target.test,DNS:localhost 2>/dev/null
fi
printf '%s' "$vnc_password" | tigervncpasswd -f >"$work/passwd"

cat >"$work/checkpw.sh" <<CHECK
#!/bin/sh
# pam_exec gives the password on stdin.
IFS= read -r given || true
[ "\$PAM_USER" = "$user" ] && [ "\$given" = "$plain_password" ]
CHECK
chmod 0700 "$work/checkpw.sh"
cat >"$work/pam-service" <<PAM
auth required pam_exec.so expose_authtok quiet $work/checkpw.sh
account required pam_permit.so
PAM
install_privileged install -o root -g root -m 0644 "$work/pam-service" "/etc/pam.d/$pam_service"
pam_installed=1

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ -n "$xev_pid" ]; then
    kill "$xev_pid" 2>/dev/null || true
    wait "$xev_pid" 2>/dev/null || true
  fi
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ "$pam_installed" -eq 1 ]; then
    install_privileged rm -f "/etc/pam.d/$pam_service" || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p /tmp/.X11-unix
Xtigervnc ":$display" -rfbport "$port" -geometry 800x600 -depth 24 -localhost=1 \
  -xkbdir /usr/share/X11/xkb -SecurityTypes "$mode" \
  -X509Cert "$work/cert.pem" -X509Key "$work/key.pem" -PasswordFile "$work/passwd" \
  -PlainUsers="$user" -pam_service="$pam_service" &
server_pid=$!

for attempt in $(seq 1 100); do
  if [ -S "/tmp/.X11-unix/X$display" ]; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo 'TigerVNC exited before creating its X11 socket' >&2
    exit 1
  fi
  sleep 0.05
done
if [ ! -S "/tmp/.X11-unix/X$display" ]; then
  echo "TigerVNC did not create /tmp/.X11-unix/X$display" >&2
  exit 1
fi

DISPLAY=":$display" stdbuf -oL xev -root -event keyboard >"$work/input.log" 2>&1 &
xev_pid=$!
sleep 0.25
kill -0 "$xev_pid" 2>/dev/null || {
  echo 'xev did not attach to the TigerVNC root window' >&2
  cat "$work/input.log" >&2
  exit 1
}
wait "$server_pid"
