#!/bin/sh
# The realm, its database and its principals, from the environment of the test run (KDC_REALM,
# KDC_USER, KDC_USER_PASSWORD, KDC_SERVICE, KDC_SERVICE_PASSWORD), then the KDC in the foreground.
set -eu
cat > /etc/krb5.conf <<CONF
[libdefaults]
  default_realm = ${KDC_REALM}
  dns_lookup_kdc = false
[realms]
  ${KDC_REALM} = {
    kdc = localhost:88
  }
CONF
mkdir -p /etc/krb5kdc
cat > /etc/krb5kdc/kdc.conf <<CONF
[kdcdefaults]
  kdc_ports = 88
  kdc_tcp_ports = 88
[realms]
  ${KDC_REALM} = {
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    master_key_type = aes256-cts-hmac-sha1-96
  }
CONF
master=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
kdb5_util create -s -r "${KDC_REALM}" -P "$master" >/dev/null
kadmin.local -q "addprinc +requires_preauth -pw ${KDC_USER_PASSWORD} ${KDC_USER}" >/dev/null
kadmin.local -q "addprinc -pw ${KDC_SERVICE_PASSWORD} ${KDC_SERVICE}" >/dev/null
echo "kdc ready"
exec krb5kdc -n
