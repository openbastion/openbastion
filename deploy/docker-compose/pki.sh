#!/bin/sh
# The certificate job (ADR-0033): the authority and its key stay in /ca (volume pki-ca), mounted
# here only. Each service gets, in /pki/<service>, its own certificate, its own key and the
# authority's certificate — never the authority's key, never another service's key. Run at every
# `docker compose up`: the authority is kept, the services' certificates are renewed.
set -eu
openbastion-pki all --dir /ca --ttl "${OB_CERT_TTL:-720h}"
for svc in api-gateway authentication authorization session-broker ssh-proxy rdp-vnc-proxy password-vault audit-service command-recorder video-recorder seaweedfs admin-cli; do
  mkdir -p "/pki/$svc"
  cp "/ca/$svc/cert.pem" "/ca/$svc/key.pem" "/ca/ca.pem" "/pki/$svc/"
done
chown -R 65532:65532 /pki
chown -R 1000:1000 /pki/seaweedfs
chmod 700 /pki/*
chmod 600 /pki/*/key.pem
chmod 700 /pki/seaweedfs
echo "certificates issued to /pki/<service>; the authority's key stays in the pki-ca volume"
