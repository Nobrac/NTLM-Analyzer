#!/usr/bin/env python3
"""Derive every icon the project needs from the four brand files.

This used to draw a shield with PIL. It no longer draws anything: the logo is
now artwork that lives in assets/, and this script only derives the formats
Windows, browsers and WiX insist on.

Which source is used where follows from what each one is legible against:

    logo-badge-dark.png     dark tile, white N   - reads on light surfaces,
                                                   and its white N still carries
                                                   on a dark taskbar
    logo-badge-light.png    white tile, dark N   - for dark surfaces only
    logo-wordmark-dark.png  dark lettering       - for light surfaces
    logo-wordmark-light.png white lettering      - for dark surfaces

Usage:  python3 make-icon.py --out assets
"""
import argparse
import os
from PIL import Image

ICO_SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
PAPER = (250, 251, 253)      # the MSI dialog background
PANEL = (236, 240, 246)
RULE = (203, 212, 226)


def load(path):
    im = Image.open(path).convert("RGBA")
    # The exports are 491x490 and 1668x491 - square them up so a resize never
    # distorts the mark.
    w, h = im.size
    if w != h and abs(w - h) < max(w, h) * 0.05:
        side = max(w, h)
        sq = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        sq.paste(im, ((side - w) // 2, (side - h) // 2), im)
        return sq
    return im


def fit(im, box_w, box_h):
    """Scale to fit inside a box without distorting or enlarging."""
    r = min(box_w / im.width, box_h / im.height, 1.0)
    return im.resize((max(1, int(im.width * r)), max(1, int(im.height * r))),
                     Image.LANCZOS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="assets")
    ap.add_argument("--src", default="assets",
                    help="where the logo-*.png brand files live")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    badge_dark = load(os.path.join(a.src, "logo-badge-dark.png"))
    badge_light = load(os.path.join(a.src, "logo-badge-light.png"))

    # --- Windows application icon -------------------------------------------
    # The dark tile: Explorer, the Apps list and the installer all show icons
    # on light backgrounds, and on a dark taskbar the white N still reads.
    frames = [badge_dark.resize((n, n), Image.LANCZOS) for n in ICO_SIZES]
    ico = os.path.join(a.out, "ntlm-agent.ico")
    frames[-1].save(ico, format="ICO",
                    sizes=[(n, n) for n in ICO_SIZES], append_images=frames[:-1])
    print("wrote %s (%d sizes)" % (ico, len(ICO_SIZES)))

    # --- README header ------------------------------------------------------
    badge_dark.resize((256, 256), Image.LANCZOS).save(
        os.path.join(a.out, "icon-256.png"), optimize=True)
    print("wrote %s" % os.path.join(a.out, "icon-256.png"))

    # --- favicons for the dashboard and the project page --------------------
    # The dashboard is dark, so the light badge is the one that shows up in a
    # tab. Two sizes: 16 for normal tabs, 32 for pinned tabs and bookmarks.
    for n in (16, 32):
        badge_light.resize((n, n), Image.LANCZOS).save(
            os.path.join(a.out, "favicon-%d.png" % n), optimize=True)
        print("wrote %s" % os.path.join(a.out, "favicon-%d.png" % n))

    # --- MSI artwork --------------------------------------------------------
    # Light, because WixUI draws every page title in black. Sizes are fixed by
    # WixUI: 493x58 for the strip on top of each page, 493x312 for the welcome
    # and finish pages. BMP because PNG is ignored.
    banner = Image.new("RGB", (493, 58), PAPER)
    banner.paste(PAPER, (0, 0, 493, 58))
    from PIL import ImageDraw
    d = ImageDraw.Draw(banner)
    d.rectangle([0, 56, 493, 58], fill=RULE)
    # Mark on the right: WixUI writes its title over the left of this strip,
    # and 493 px here map to only 370 dialog units, so the mark has to stay
    # small or the title runs into it.
    m = fit(badge_dark, 40, 40)
    banner.paste(m, (493 - m.width - 12, (56 - m.height) // 2), m)
    banner.save(os.path.join(a.out, "msi-banner.bmp"))
    print("wrote %s" % os.path.join(a.out, "msi-banner.bmp"))

    dlg = Image.new("RGB", (493, 312), PAPER)
    d = ImageDraw.Draw(dlg)
    d.rectangle([0, 0, 164, 312], fill=PANEL)
    d.rectangle([164, 0, 165, 312], fill=RULE)
    # The badge only. The wordmark contains the same mark, so showing both put
    # it on the panel twice, and the product name is already in the dialog's
    # own heading.
    big = fit(badge_dark, 112, 112)
    dlg.paste(big, ((164 - big.width) // 2, (312 - big.height) // 2), big)
    dlg.save(os.path.join(a.out, "msi-dialog.bmp"))
    print("wrote %s" % os.path.join(a.out, "msi-dialog.bmp"))


if __name__ == "__main__":
    main()
