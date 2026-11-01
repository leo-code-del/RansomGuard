#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""產生 RansomGuard 的圖標：icon.ico（打包 exe 用）與 icon.png（README 用）。

  python make_icon.py

需要套件：pip install pillow
"""

import sys

from PIL import Image, ImageChops, ImageDraw

S = 1024  # 先畫大圖再縮小，邊緣才平滑
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
SMALL = 24  # 這個尺寸以下用簡化版（沒有鑰匙孔與內框，線條加粗）


def bezier(p0, p1, p2, p3, n=64):
    pts = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        pts.append((u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]))
    return pts


def shield(scale=1.0, cy=0.47):
    """盾牌外形（以 (0.5, cy) 為中心縮放）。"""
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
    img.paste(gradient(hexrgb("#7cb4ff"), hexrgb("#2f6fe4")), (0, 0), outer)  # 亮色外框
    inner = mask(shield(0.86))
    img.paste(gradient(hexrgb("#3b82f6"), hexrgb("#1e3a8a")), (0, 0), inner)
    if not small:  # 右半邊稍暗，做出立體感
        right = Image.new("L", (S, S), 0)
        ImageDraw.Draw(right).rectangle((S // 2, 0, S, S), fill=46)
        img.paste((10, 20, 60, 255), (0, 0), ImageChops.multiply(right, inner))

    d = ImageDraw.Draw(img)
    white = (255, 255, 255, 255)
    k = 1.35 if small else 1.1  # 小圖示的鎖頭放大一點
    cx, cy = 0.5 * S, 0.53 * S

    def box(x0, y0, x1, y1):
        return (cx + x0 * k * S, cy + y0 * k * S, cx + x1 * k * S, cy + y1 * k * S)

    w = round((0.075 if small else 0.052) * S)  # 鎖環粗細
    sh = box(-0.10, -0.24, 0.10, -0.04)  # 鎖環的圓弧
    d.arc(sh, 180, 360, fill=white, width=w)
    mid = (sh[1] + sh[3]) / 2
    d.rectangle((sh[0], mid - 1, sh[0] + w, cy), fill=white)
    d.rectangle((sh[2] - w, mid - 1, sh[2], cy), fill=white)
    d.rounded_rectangle(box(-0.155, -0.065, 0.155, 0.185), radius=0.04 * k * S, fill=white)
    if not small:  # 鑰匙孔
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
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # 主控台不是 UTF-8 時中文才不會出錯
    print("已產生 icon.ico、icon.png")


if __name__ == "__main__":
    main()
