from __future__ import annotations

import struct
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "xiaomi_submission" / "workspace_template" / "assets" / "vulnmind_icon.png"


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def write_png(path: Path, width: int = 256, height: int = 256) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            if x < width // 2:
                base = (17, 70, 56)
            else:
                base = (10, 24, 35)

            pulse = (x * 3 + y * 5) % 40
            r = min(base[0] + pulse, 255)
            g = min(base[1] + pulse, 255)
            b = min(base[2] + pulse, 255)

            if abs(x - y) < 6 or abs((width - 1 - x) - y) < 6:
                r, g, b = 241, 196, 15

            row.extend((r, g, b, 255))
        rows.append(bytes(row))

    raw = b"".join(rows)
    png = b"\x89PNG\r\n\x1a\n"
    png += _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += _chunk(b"IDAT", zlib.compress(raw, level=9))
    png += _chunk(b"IEND", b"")
    path.write_bytes(png)


def main() -> int:
    write_png(OUTPUT)
    print(f"[VulnMind AI] Icon generated: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
