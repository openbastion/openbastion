# A reference RDP client against the Windows target (ADR-0071): FreeRDP 3's xfreerdp3, on a virtual
# display. It answers one question our client cannot: does a known client get past the MCS
# Connect-Initial on this machine? Test only: never shipped, and not the client under test.
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update \
 && apt-get install -y --no-install-recommends freerdp3-x11 xvfb ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -m 1777 /tmp/.X11-unix
COPY client.sh /client.sh
ENTRYPOINT ["sh", "/client.sh"]
