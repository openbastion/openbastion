#!/bin/sh
# The certificate job (ADR-0033): the authority and its key stay in /ca (volume pki-ca), mounted
# here only. Each service gets, in /pki/<service>, its own certificate, its own key and the
# authority's certificate — never the authority's key, never another service's key. Run at every
# `docker compose up`: the authority is kept, the services' certificates are renewed.
set -eu
openbastion-pki all --dir /ca --ttl "${OB_CERT_TTL:-720h}"
for svc in api-gateway authentication authorization session-broker workflow-service ssh-proxy rdp-vnc-proxy password-vault audit-service command-recorder video-recorder seaweedfs admin-cli; do
  mkdir -p "/pki/$svc"
  cp "/ca/$svc/cert.pem" "/ca/$svc/key.pem" "/ca/ca.pem" "/pki/$svc/"
done
# ADR-0116: the HMAC key of the session metadata, the Session Broker's own. Drawn once, at the first
# start, and never again: a new key would make every signed row unverifiable. Never in PostgreSQL.
if [ ! -s /pki/session-broker/session-metadata.key ]; then
  (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /pki/session-broker/session-metadata.key)
  echo "session metadata key drawn in /pki/session-broker/session-metadata.key (ADR-0116)"
fi
chown -R 65532:65532 /pki
chown -R 1000:1000 /pki/seaweedfs
chmod 700 /pki/*
chmod 600 /pki/*/key.pem /pki/session-broker/session-metadata.key
chmod 700 /pki/seaweedfs
echo "certificates issued to /pki/<service>; the authority's key stays in the pki-ca volume"
