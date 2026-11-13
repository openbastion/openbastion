# A reference RDP client against the Windows target (ADR-0071): FreeRDP 3's xfreerdp3, on a virtual
# display. It answers one question our client cannot: does a known client get past the MCS
# Connect-Initial on this machine? Test only: never shipped, and not the client under test.
FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
 && apt-get install -y --no-install-recommends freerdp3-x11 xvfb ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -m 1777 /tmp/.X11-unix
COPY client.sh /client.sh
ENTRYPOINT ["sh", "/client.sh"]
