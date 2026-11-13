#!/usr/bin/env python3
"""ppm2png.py IN OUT: a binary PPM (P6, 8 bits), as QEMU's screendump writes it, to a PNG.

The screen of the Windows virtual machine, whatever RDP says (ADR-0071, CI instability): standard
library only, as the runner has no image tool to rely on.
"""
import struct
import sys
import zlib


def tokens(data):
    pos = 0
    while True:
        while data[pos:pos + 1].isspace():
            pos += 1
        if data[pos:pos + 1] == b"#":
            pos = data.index(b"\n", pos) + 1
            continue
        end = pos
        while not data[end:end + 1].isspace():
            end += 1
        yield data[pos:end], end
        pos = end


def main(src, dst):
    data = open(src, "rb").read()
    it = tokens(data)
    magic, _ = next(it)
    width, _ = next(it)
    height, _ = next(it)
    maxval, end = next(it)
    if magic != b"P6" or maxval != b"255":
        sys.exit("not an 8-bit binary PPM")
    width, height = int(width), int(height)
    pixels = data[end + 1:end + 1 + width * height * 3]
    rows = b"".join(b"\x00" + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b"")
    open(dst, "wb").write(png)
    print(f"{dst}: {width}x{height}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
