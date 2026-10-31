# ADR-0061: the Active Directory of the directory login tests — a Samba domain controller from
# Debian's packages, on the pinned official image (ADR-0051), never a third-party image. Built by
# test/integration/ldap_flow_test.go; the certificate, its authority and the passwords are the
# test's, mounted at /seed.
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba samba-ad-dc samba-ad-provision python3-samba ldb-tools \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
EXPOSE 636
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
