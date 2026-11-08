# A real RDP server for the interoperability test of pkg/rdp (ADR-0071): FreeRDP's shadow server,
# which speaks HYBRID (TLS + CredSSP/NTLMv2), showing a terminal on a virtual display. Test only:
# never shipped. It is not Windows: the Windows criterion of ADR-0071 stays open. Xvnc and xrandr:
# a display whose size changes during a session (RDP_DISPLAY=resizable, target.sh).
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update \
 && apt-get install -y --no-install-recommends freerdp3-shadow-x11 winpr3-utils xvfb tigervnc-standalone-server x11-xserver-utils xterm xfonts-base openssl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -m 1777 /tmp/.X11-unix \
 && useradd -m -u 1000 rdp
COPY target.sh /target.sh
USER 1000:1000
ENTRYPOINT ["sh", "/target.sh"]
