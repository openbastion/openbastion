#!/usr/bin/env python3
"""vnc_snapshot.py HOST PORT OUT: one whole frame of QEMU's own VNC console, as a PNG.

The screen of the Windows virtual machine as QEMU shows it (ADR-0071, CI instability), whatever RDP
says: QEMU serves its console in RFB with no authentication, inside the dockur container only. This
is a diagnostic of the test machine, standard library only; it is not pkg/vnc, which refuses any VNC
without VeNCrypt by design.
"""
import socket
import struct
import sys
import zlib


def recv(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("the console closed the connection")
        data += chunk
    return data


def png(width, height, rgb):
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    rows = b"".join(b"\x00" + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b""))


def main(host, port, out):
    sock = socket.create_connection((host, int(port)), timeout=15)
    version = recv(sock, 12)
    sock.sendall(b"RFB 003.008\n")
    count = recv(sock, 1)[0]
    if count == 0:
        raise SystemExit("the console refused: " + recv(sock, struct.unpack(">I", recv(sock, 4))[0]).decode(errors="replace"))
    types = recv(sock, count)
    if 1 not in types:
        raise SystemExit(f"no 'None' security type: {list(types)}")
    sock.sendall(b"\x01")
    if struct.unpack(">I", recv(sock, 4))[0] != 0:
        raise SystemExit("security handshake failed")
    sock.sendall(b"\x01")  # ClientInit: shared
    width, height = struct.unpack(">HH", recv(sock, 4))
    recv(sock, 16)  # the server's pixel format, replaced below
    recv(sock, struct.unpack(">I", recv(sock, 4))[0])  # its name
    # 32 bits per pixel, true colour, little-endian, red at bit 16, green at 8, blue at 0.
    sock.sendall(struct.pack(">BxxxBBBBHHHBBBxxx", 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
    sock.sendall(struct.pack(">BxH", 2, 1) + struct.pack(">i", 0))  # SetEncodings: Raw only
    sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))  # a whole, non-incremental frame
    rgb = bytearray(width * height * 3)
    covered = 0
    while covered < width * height:
        kind = recv(sock, 1)[0]
        if kind == 1:  # SetColourMapEntries
            recv(sock, 3)
            recv(sock, 6 * struct.unpack(">H", recv(sock, 2))[0])
            continue
        if kind == 2:  # Bell
            continue
        if kind == 3:  # ServerCutText
            recv(sock, 3)
            recv(sock, struct.unpack(">I", recv(sock, 4))[0])
            continue
        if kind != 0:
            raise SystemExit(f"unexpected message {kind}")
        recv(sock, 1)
        for _ in range(struct.unpack(">H", recv(sock, 2))[0]):
            x, y, w, h, enc = struct.unpack(">HHHHi", recv(sock, 12))
            if enc == -223:  # DesktopSize pseudo-encoding
                continue
            if enc != 0:
                raise SystemExit(f"encoding {enc} not asked for")
            data = recv(sock, w * h * 4)
            for row in range(h):
                for col in range(w):
                    b, g, r = data[(row * w + col) * 4:(row * w + col) * 4 + 3]
                    at = ((y + row) * width + x + col) * 3
                    rgb[at:at + 3] = bytes((r, g, b))
            covered += w * h
    open(out, "wb").write(png(width, height, bytes(rgb)))
    print(f"{out}: {width}x{height}, {version.decode().strip()}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
