# ADR-0061: the Active Directory of the directory login tests — a Samba domain controller from
# Debian's packages, on the pinned official image (ADR-0051), never a third-party image. Built by
# test/integration/ldap_flow_test.go; the certificate, its authority and the passwords are the
# test's, mounted at /seed.
FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba samba-ad-dc samba-ad-provision python3-samba ldb-tools \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
EXPOSE 636
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
