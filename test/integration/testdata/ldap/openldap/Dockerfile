# ADR-0061: the OpenLDAP of the directory login tests — Debian's slapd, from the pinned official
# image (ADR-0051), never a third-party image. Built by test/integration/ldap_flow_test.go; the
# certificate, its authority and the password are the test's, mounted at /seed.
FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN echo 'slapd slapd/no_configuration boolean true' | debconf-set-selections \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
EXPOSE 389
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
