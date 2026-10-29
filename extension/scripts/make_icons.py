"""Generate PhishGuard PNG icons (16/48/128) using only the stdlib (zlib + struct)."""
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "icons")
BG = (15, 23, 42)        # slate-900 rounded square
SHIELD = (16, 185, 129)  # emerald-500
MARK = (255, 255, 255)   # check mark


def chunk(tag, data):
    c = tag + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)


def write_png(path, size, pixels):
    raw = b"".join(b"\x00" + bytes(v for px in row for v in px) for row in pixels)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def in_rounded_square(x, y, r):
    # x, y in [0, 1]
    cx = min(max(x, r), 1 - r)
    cy = min(max(y, r), 1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_shield(x, y):
    top, mid, bot = 0.18, 0.52, 0.86
    if y < top or y > bot:
        return False
    if y <= mid:
        half = 0.32
    else:
        t = (y - mid) / (bot - mid)
        half = 0.32 * (1 - t ** 1.6)
    return abs(x - 0.5) <= half


def on_check(x, y, w):
    def seg(ax, ay, bx, by):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        px, py = ax + t * dx, ay + t * dy
        return (x - px) ** 2 + (y - py) ** 2 <= w * w
    return seg(0.36, 0.50, 0.46, 0.61) or seg(0.46, 0.61, 0.65, 0.38)


def render(size):
    ss = 4  # supersampling for anti-aliasing
    rows = []
    for j in range(size):
        row = []
        for i in range(size):
            acc = [0, 0, 0, 0]
            for sj in range(ss):
                for si in range(ss):
                    x = (i + (si + 0.5) / ss) / size
                    y = (j + (sj + 0.5) / ss) / size
                    if not in_rounded_square(x, y, 0.22):
                        continue
                    col = BG
                    if in_shield(x, y):
                        col = SHIELD
                        if size >= 32 and on_check(x, y, 0.045):
                            col = MARK
                    acc[0] += col[0]; acc[1] += col[1]; acc[2] += col[2]; acc[3] += 255
            n = ss * ss
            a = acc[3] // n
            if a == 0:
                row.append((0, 0, 0, 0))
            else:
                k = acc[3] / 255
                row.append((int(acc[0] / k), int(acc[1] / k), int(acc[2] / k), a))
        rows.append(row)
    return rows


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for s in (16, 48, 128):
        write_png(os.path.join(OUT, f"icon{s}.png"), s, render(s))
        print(f"wrote icons/icon{s}.png")
