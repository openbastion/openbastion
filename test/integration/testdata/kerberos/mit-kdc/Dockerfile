# A real Kerberos KDC for the test of pkg/rdp's Kerberos (ADR-0100, increment 1): MIT krb5, one realm,
# a user and a TERMSRV service principal, AES only. Test only: never shipped. It is not Active
# Directory: the Windows side of ADR-0100 (a domain controller, a joined target, NTLM refused) is a
# later increment, in CI.
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update \
 && apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server \
 && rm -rf /var/lib/apt/lists/*
COPY kdc.sh /kdc.sh
ENTRYPOINT ["sh", "/kdc.sh"]
