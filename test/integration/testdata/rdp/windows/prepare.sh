#!/usr/bin/env bash
# Makes, in DIR, what docker-compose.yml and the Windows interop test need (ADR-0071):
#   - a test authority and the RDP certificate of "rdp-windows.test", signed by it;
#   - oem/: install.bat, rdp-setup.ps1, the certificate as a PFX and its password, for Windows;
#   - compose.env (for docker compose) and test.env (for make test-rdp-windows).
# The pin and the roots are known before Windows starts: nothing is learnt from the target.
# Everything here is for one run and is never committed.
set -euo pipefail
dir=${1:?usage: prepare.sh DIR}
here=$(cd "$(dirname "$0")" && pwd)
name=rdp-windows.test
mkdir -p "$dir/oem" "$dir/storage" "$dir/dump"
umask 077
cd "$dir"

openssl req -x509 -newkey rsa:3072 -nodes -days 2 -subj "/CN=OpenBastion Windows RDP test authority" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$name" -keyout rdp.key -out rdp.csr 2>/dev/null
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n' "$name" > rdp.ext
openssl x509 -req -in rdp.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile rdp.ext -out rdp.pem 2>/dev/null

pfx_password=$(openssl rand -hex 24)
# SHA1/3DES: what every Windows Server imports, for a key that lives two days.
openssl pkcs12 -export -in rdp.pem -inkey rdp.key -out oem/rdp.pfx -passout "pass:$pfx_password" \
  -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
printf '%s' "$pfx_password" > oem/rdp.pfx.pass
# cmd.exe reads a batch file line by line on CRLF: the copy is converted, the source stays LF.
sed 's/$/\r/' "$here/oem/install.bat" > oem/install.bat
cp "$here/oem/rdp-setup.ps1" oem/

pin=$(openssl x509 -in rdp.pem -outform DER | openssl dgst -sha256 | awk '{print $NF}')
# Windows rejects a password without three of: lower, upper, digit, symbol.
password="Ob-$(openssl rand -hex 12)-W1"
chmod 755 oem storage
chmod 644 oem/*

cat > compose.env <<ENV
WINDOWS_PASSWORD=$password
WINDOWS_STORAGE_DIR=$dir/storage
WINDOWS_OEM_DIR=$dir/oem
ENV
cat > test.env <<ENV
RDP_WINDOWS=1
RDP_WINDOWS_ADDRESS=127.0.0.1:3389
RDP_WINDOWS_USER=operator
RDP_WINDOWS_PASSWORD=$password
RDP_WINDOWS_CA_FILE=$dir/ca.pem
RDP_WINDOWS_PIN=$pin
RDP_WINDOWS_SERVER_NAME=$name
RDP_WINDOWS_DUMP=$dir/dump
ENV
echo "prepared $dir: the RDP certificate of $name, pin $pin"
