#!/bin/sh
# A fresh EXAMPLE.TEST domain whose LDAPS uses the test's certificate — the NT ACLs in a tdb
# (xattr_tdb), so that the container needs no CAP_SYS_ADMIN for security.* attributes; then /seed/setup.sh adds the
# people and groups; then samba in the foreground.
set -eu
admin=$(cat /seed/admin-password)
rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba/* /var/cache/samba/*
mkdir -p /var/lib/samba/private/tls
cp /seed/cert.pem /seed/key.pem /seed/ca.pem /var/lib/samba/private/tls/
chmod 600 /var/lib/samba/private/tls/key.pem
samba-tool domain provision --realm=EXAMPLE.TEST --domain=EXAMPLE --server-role=dc --dns-backend=NONE \
  --adminpass="$admin" \
  --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
  --option="xattr_tdb:file = /var/lib/samba/xattr.tdb" \
  --option="dns update command = /bin/true" \
  --option="tls enabled = yes" \
  --option="tls keyfile = /var/lib/samba/private/tls/key.pem" \
  --option="tls certfile = /var/lib/samba/private/tls/cert.pem" \
  --option="tls cafile = /var/lib/samba/private/tls/ca.pem" >/tmp/provision.log 2>&1 || { cat /tmp/provision.log; exit 1; }
sh /seed/setup.sh
echo "samba: ready to start"
exec samba -i -M single --debug-stdout -d 1
