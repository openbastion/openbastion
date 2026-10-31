# ADR-0061: the OpenLDAP of the directory login tests — Debian's slapd, from the pinned official
# image (ADR-0051), never a third-party image. Built by test/integration/ldap_flow_test.go; the
# certificate, its authority and the password are the test's, mounted at /seed.
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN echo 'slapd slapd/no_configuration boolean true' | debconf-set-selections \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
EXPOSE 389
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
