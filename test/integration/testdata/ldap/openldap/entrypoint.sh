#!/bin/sh
# A fresh dc=example,dc=test directory, TLS (StartTLS) with the test's certificate, its people and
# groups from /seed/data.ldif; then slapd in the foreground.
set -eu
pw=$(cat /seed/admin-password)
hash=$(slappasswd -s "$pw")
mkdir -p /etc/ldap/slapd.d /var/lib/ldap /etc/ldap/certs /run/slapd
rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*
cp /seed/cert.pem /seed/key.pem /seed/ca.pem /etc/ldap/certs/
cat > /tmp/config.ldif <<LDIF
dn: cn=config
objectClass: olcGlobal
cn: config
olcTLSCACertificateFile: /etc/ldap/certs/ca.pem
olcTLSCertificateFile: /etc/ldap/certs/cert.pem
olcTLSCertificateKeyFile: /etc/ldap/certs/key.pem
olcTLSProtocolMin: 3.3

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/ldap/schema/core.ldif
include: file:///etc/ldap/schema/cosine.ldif
include: file:///etc/ldap/schema/inetorgperson.ldif

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: back_mdb

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * none

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=test
olcDbDirectory: /var/lib/ldap
olcRootDN: cn=admin,dc=example,dc=test
olcRootPW: $hash
olcDbIndex: objectClass eq
olcDbIndex: uid eq
olcDbIndex: member eq
olcDbIndex: uniqueMember eq
olcSecurity: tls=1
olcAccess: {0}to attrs=userPassword by self =xw by anonymous auth by * none
olcAccess: {1}to * by dn.exact="cn=svc-bastion,ou=service,dc=example,dc=test" read by self read by * none
LDIF
slapadd -n 0 -F /etc/ldap/slapd.d -l /tmp/config.ldif
slapadd -n 1 -F /etc/ldap/slapd.d -l /seed/data.ldif
chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap /etc/ldap/certs /run/slapd
exec slapd -d 256 -u openldap -g openldap -F /etc/ldap/slapd.d -h "ldap:///"
