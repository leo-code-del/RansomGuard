#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate RansomGuard's icon: icon.ico (for the exe) and icon.png (for the README).

  python make_icon.py

Requires: pip install pillow
"""

from PIL import Image, ImageChops, ImageDraw

S = 1024  # draw large, then scale down, for smooth edges
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
SMALL = 24  # at or below this size use the simplified version (no keyhole or inner rim, thicker lines)


def bezier(p0, p1, p2, p3, n=64):
    pts = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        pts.append((u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]))
    return pts


def shield(scale=1.0, cy=0.47):
    """Shield outline (scaled around (0.5, cy))."""
    L, T, R, B = (0.11, 0.19), (0.5, 0.05), (0.89, 0.19), (0.5, 0.97)
    pts = (bezier(L, (0.28, 0.18), (0.40, 0.11), T) + bezier(T, (0.60, 0.11), (0.72, 0.18), R)
           + bezier(R, (0.90, 0.57), (0.72, 0.85), B) + bezier(B, (0.28, 0.85), (0.10, 0.57), L))
    return [((0.5 + (x - 0.5) * scale) * S, (cy + (y - cy) * scale) * S) for x, y in pts]


def gradient(top, bottom):
    g = Image.new("RGBA", (1, 256))
    for y in range(256):
        t = y / 255
        g.putpixel((0, y), tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    return g.resize((S, S))


def mask(points):
    m = Image.new("L", (S, S), 0)
    ImageDraw.Draw(m).polygon(points, fill=255)
    return m


def hexrgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def render(small=False):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    outer = mask(shield())
    img.paste(gradient(hexrgb("#7cb4ff"), hexrgb("#2f6fe4")), (0, 0), outer)  # light rim
    inner = mask(shield(0.86))
    img.paste(gradient(hexrgb("#3b82f6"), hexrgb("#1e3a8a")), (0, 0), inner)
    if not small:  # darker right half for depth
        right = Image.new("L", (S, S), 0)
        ImageDraw.Draw(right).rectangle((S // 2, 0, S, S), fill=46)
        img.paste((10, 20, 60, 255), (0, 0), ImageChops.multiply(right, inner))

    d = ImageDraw.Draw(img)
    white = (255, 255, 255, 255)
    k = 1.35 if small else 1.1  # slightly larger padlock on small icons
    cx, cy = 0.5 * S, 0.53 * S

    def box(x0, y0, x1, y1):
        return (cx + x0 * k * S, cy + y0 * k * S, cx + x1 * k * S, cy + y1 * k * S)

    w = round((0.075 if small else 0.052) * S)  # shackle thickness
    sh = box(-0.10, -0.24, 0.10, -0.04)  # shackle arc
    d.arc(sh, 180, 360, fill=white, width=w)
    mid = (sh[1] + sh[3]) / 2
    d.rectangle((sh[0], mid - 1, sh[0] + w, cy), fill=white)
    d.rectangle((sh[2] - w, mid - 1, sh[2], cy), fill=white)
    d.rounded_rectangle(box(-0.155, -0.065, 0.155, 0.185), radius=0.04 * k * S, fill=white)
    if not small:  # keyhole
        hole = hexrgb("#1e3a8a") + (255,)
        r = 0.034 * k * S
        hy = cy + 0.04 * k * S
        d.ellipse((cx - r, hy - r, cx + r, hy + r), fill=hole)
        d.polygon([(cx - 0.014 * k * S, hy), (cx + 0.014 * k * S, hy),
                   (cx + 0.022 * k * S, hy + 0.09 * k * S), (cx - 0.022 * k * S, hy + 0.09 * k * S)],
                  fill=hole)
    return img


def main():
    big, small = render(), render(small=True)
    imgs = [(small if n <= SMALL else big).resize((n, n), Image.LANCZOS) for n in SIZES]
    imgs[-1].save("icon.ico", sizes=[(n, n) for n in SIZES], append_images=imgs[:-1])
    imgs[-1].save("icon.png")
    print("Created icon.ico and icon.png")


if __name__ == "__main__":
    main()
