# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build every icon the project needs from the artwork in assets/mark.png.

The mark is the user's own image, not a redrawing of it. Three things are done
to it and nothing else:

* **Squared.** The source is 553x468; icons are square. The mark is centred on
  a black canvas rather than stretched, so its proportions are untouched.
* **Cleaned.** It arrived as a JPEG, so the edges carry compression noise —
  grey pixels that turn into visible mush when the image is scaled down to
  16 px. The artwork is pure black and white, so a threshold restores exactly
  the intended shape and costs nothing.
* **Rounded**, as asked, for the launcher icons.

Run:  python tools/make_icons.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "assets" / "mark.png"

# Everything is built from one high-resolution master, so each size is a clean
# downsample rather than a separate approximation.
MASTER = 1024


def load_master() -> Image.Image:
    """The artwork, squared, de-JPEGed, at MASTER x MASTER."""
    src = Image.open(SOURCE).convert("L")

    # Centre on a square black canvas — never stretch, that would distort the
    # circle into an ellipse.
    side = max(src.size)
    square = Image.new("L", (side, side), 0)
    square.paste(src, ((side - src.width) // 2, (side - src.height) // 2))

    # Order matters here, and the obvious order is wrong.
    #
    # Thresholding first — while the circle is only ~300 px across — bakes the
    # JPEG's ringing into the outline: every place the compressor smeared an
    # edge becomes a permanent bump, and enlarging magnifies it.
    #
    # So: enlarge first, letting LANCZOS interpolate the smeared edge into a
    # smooth ramp; then threshold at high resolution, where one pixel of error
    # is a quarter of a pixel in the finished icon; then come back down with
    # anti-aliasing.
    big = square.resize((MASTER * 4, MASTER * 4), Image.LANCZOS)
    big = big.filter(ImageFilter.GaussianBlur(radius=MASTER * 4 / 400))
    big = big.point(lambda p: 255 if p > 128 else 0, mode="L")
    master = big.resize((MASTER, MASTER), Image.LANCZOS)

    # `master` is the coverage of white over black, greys included, so using it
    # as the paste mask keeps those soft edges instead of discarding them.
    rgba = Image.new("RGBA", master.size, (0, 0, 0, 255))
    white = Image.new("RGBA", master.size, (255, 255, 255, 255))
    rgba.paste(white, mask=master)
    return rgba


MASTER_IMG: Image.Image | None = None


def mark(size: int, rounded: bool) -> Image.Image:
    global MASTER_IMG
    if MASTER_IMG is None:
        MASTER_IMG = load_master()

    img = MASTER_IMG.resize((size, size), Image.LANCZOS)
    if not rounded:
        return img

    # Rounded corners, done at 4x so the curve is not jagged at small sizes.
    scale = 4
    mask = Image.new("L", (size * scale, size * scale), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, size * scale - 1, size * scale - 1],
        radius=int(size * scale * 0.219),
        fill=255,
    )
    mask = mask.resize((size, size), Image.LANCZOS)
    out = img.copy()
    out.putalpha(mask)
    return out


def write_png(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "PNG", optimize=True)
    print(f"  {path.relative_to(ROOT)}  ({img.width}x{img.height})")


def main() -> None:
    print("desktop / launcher:")
    for n in (16, 32, 48, 64, 128, 256, 512, 1024):
        write_png(mark(n, rounded=True), ROOT / "assets" / "icon" / f"icon-{n}.png")

    print("windows:")
    sizes = [16, 24, 32, 48, 64, 128, 256]
    ico = ROOT / "app" / "windows" / "runner" / "resources" / "app_icon.ico"
    ico.parent.mkdir(parents=True, exist_ok=True)
    mark(256, rounded=True).save(ico, format="ICO", sizes=[(n, n) for n in sizes])
    print(f"  {ico.relative_to(ROOT)}  ({', '.join(map(str, sizes))})")

    # The tray keeps the black tile: a white mark on transparency looks tidy on
    # a dark taskbar and is invisible on a light one, and Windows lets the user
    # pick either.
    print("tray:")
    for n in (16, 24, 32, 48):
        write_png(mark(n, rounded=True), ROOT / "app" / "assets" / "tray" / f"tray-{n}.png")
    write_png(mark(32, rounded=True), ROOT / "app" / "assets" / "tray" / "tray.png")
    tray_sizes = [16, 24, 32, 48]
    tray_ico = ROOT / "app" / "assets" / "tray" / "tray.ico"
    mark(48, rounded=True).save(tray_ico, format="ICO", sizes=[(n, n) for n in tray_sizes])
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
        write_png(mark(n, rounded=True), base / folder / "ic_launcher.png")

    print("linux:")
    for n in (16, 32, 48, 64, 128, 256, 512):
        write_png(
            mark(n, rounded=True),
            ROOT / "packaging" / "linux" / "icons" / f"{n}x{n}" / "nullchat.png",
        )

    print("in-app:")
    write_png(mark(512, rounded=True), ROOT / "app" / "assets" / "logo.png")

    print("\ndone")


if __name__ == "__main__":
    main()
