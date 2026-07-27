# SPDX-License-Identifier: AGPL-3.0-or-later
"""Draw the NullChat mark and write every icon the project needs.

The mark is Ø — the empty set. It is drawn as geometry rather than scaled from
the original image, because the same shape has to hold up at 16 px in a system
tray and at 1024 px on a desktop. Everything is rendered at 8x and downsampled,
which is what keeps the diagonal clean at small sizes.

Run:  python tools/make_icons.py
"""

from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
BLACK = (0, 0, 0, 255)
WHITE = (255, 255, 255, 255)

# Supersampling factor. 8 is generous, but these are generated once and a
# ragged diagonal is the first thing that makes an icon look amateur.
SS = 8


def draw_mark(size: int, rounded: bool, transparent_bg: bool = False) -> Image.Image:
    """The Ø mark at `size` pixels square.

    `rounded` gives the launcher icon its rounded square; a tray icon is drawn
    on transparency instead, because the system draws its own background and a
    black tile would sit in the taskbar like a hole.
    """
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    if not transparent_bg:
        if rounded:
            # Radius follows the source: soft, not a squircle.
            d.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.219), fill=BLACK)
        else:
            d.rectangle([0, 0, s - 1, s - 1], fill=BLACK)

    stroke = max(1, int(s * 0.066))
    radius = s * 0.293
    cx = cy = s / 2
    fg = WHITE if not transparent_bg else WHITE

    d.ellipse(
        [cx - radius, cy - radius, cx + radius, cy + radius],
        outline=fg,
        width=stroke,
    )
    # The slash overshoots the circle on both sides — that overshoot is what
    # makes it read as Ø rather than as a circle with a line through it, and it
    # has to be generous: at 0.226 the ends barely cleared the stroke and the
    # mark looked like a "no entry" sign.
    over = s * 0.30
    d.line(
        [cx - over, cy + over, cx + over, cy - over],
        fill=fg,
        width=stroke,
    )

    return img.resize((size, size), Image.LANCZOS)


def write_png(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "PNG", optimize=True)
    print(f"  {path.relative_to(ROOT)}  ({img.width}x{img.height})")


def write_ico(path: Path) -> None:
    """A Windows .ico holding every size Explorer might ask for."""
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [draw_mark(n, rounded=True) for n in sizes]
    path.parent.mkdir(parents=True, exist_ok=True)
    images[-1].save(path, format="ICO", sizes=[(n, n) for n in sizes])
    print(f"  {path.relative_to(ROOT)}  ({', '.join(str(n) for n in sizes)})")


def main() -> None:
    print("desktop / launcher:")
    for n in (16, 32, 48, 64, 128, 256, 512, 1024):
        write_png(draw_mark(n, rounded=True), ROOT / "assets" / "icon" / f"icon-{n}.png")

    print("windows:")
    write_ico(ROOT / "app" / "windows" / "runner" / "resources" / "app_icon.ico")

    # Tray icons keep the black tile on purpose. A white mark on transparency
    # looks tidier on a dark taskbar and is *invisible* on a light one — and
    # Windows lets the user choose. A tile is always legible on both.
    print("tray:")
    for n in (16, 24, 32, 48):
        write_png(
            draw_mark(n, rounded=True),
            ROOT / "app" / "assets" / "tray" / f"tray-{n}.png",
        )
    # window_manager/tray_manager wants one file; 32 is the usual ask on Windows.
    write_png(draw_mark(32, rounded=True), ROOT / "app" / "assets" / "tray" / "tray.png")
    # Windows tray accepts .ico and looks crisper with one.
    tray_sizes = [16, 24, 32, 48]
    tray_imgs = [draw_mark(n, rounded=True) for n in tray_sizes]
    tray_ico = ROOT / "app" / "assets" / "tray" / "tray.ico"
    tray_imgs[-1].save(tray_ico, format="ICO", sizes=[(n, n) for n in tray_sizes])
    print(f"  {tray_ico.relative_to(ROOT)}")

    print("android:")
    android = {
        "mipmap-mdpi": 48,
        "mipmap-hdpi": 72,
        "mipmap-xhdpi": 96,
        "mipmap-xxhdpi": 144,
        "mipmap-xxxhdpi": 192,
    }
    base = ROOT / "app" / "android" / "app" / "src" / "main" / "res"
    for folder, n in android.items():
        write_png(draw_mark(n, rounded=True), base / folder / "ic_launcher.png")

    print("linux:")
    for n in (16, 32, 48, 64, 128, 256, 512):
        write_png(
            draw_mark(n, rounded=True),
            ROOT / "packaging" / "linux" / "icons" / f"{n}x{n}" / "nullchat.png",
        )

    print("in-app (the mark shown on the connecting screen etc.):")
    write_png(draw_mark(512, rounded=True), ROOT / "app" / "assets" / "logo.png")

    print("\ndone")


if __name__ == "__main__":
    main()
