#!/usr/bin/env python3
"""Draw the NTLM-Analyzer icon and export it as .ico and .png.

The mark is the product's own statement rather than a generic padlock: a shield
whose fill is the handover bar from the dashboard - a thin red remnant on the
left, amber in the middle, the green target state taking most of the width. Read
left to right it is "NTLMv1 -> NTLMv2 -> Kerberos", which is the whole project.

Design constraints that drove it:

  * it has to survive 16x16 in a taskbar and a services list, so there is no
    keyhole, no text, no thin line work - only a silhouette and three colour
    fields, which is the most a 16 px tile can carry
  * the colours are the dashboard's own (--v1 / --v2 / --krb), so the icon and
    the UI read as one product
  * everything is drawn at 8x and downsampled, because Pillow's polygon fill has
    no antialiasing of its own and a jagged shield edge looks broken

Usage:
    python3 make-icon.py --out assets
"""
import argparse
import os

from PIL import Image, ImageDraw

# Straight from the dashboard's :root block.
RED = (255, 107, 107, 255)
AMBER = (245, 184, 65, 255)
GREEN = (61, 220, 151, 255)
EDGE = (14, 19, 31, 255)          # --void, as the outline
SS = 8                            # supersampling factor

# Share of the shield width per band. Deliberately not equal thirds: the point
# is that the insecure remnant is small and the target state dominates.
BANDS = ((RED, 0.00, 0.16), (AMBER, 0.16, 0.38), (GREEN, 0.38, 1.00))


def bez(p0, p1, p2, p3, steps=40):
    """Cubic bezier, sampled - Pillow has no curve primitive."""
    out = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        x = (u ** 3) * p0[0] + 3 * (u ** 2) * t * p1[0] + 3 * u * (t ** 2) * p2[0] + (t ** 3) * p3[0]
        y = (u ** 3) * p0[1] + 3 * (u ** 2) * t * p1[1] + 3 * u * (t ** 2) * p2[1] + (t ** 3) * p3[1]
        out.append((x, y))
    return out


def shield(w, h, inset):
    """Classic shield: flat top with eased corners, straight flanks, a point.

    Built from beziers rather than a power curve - the earlier version pinched
    the flanks and the tip came out looking clipped.
    """
    x0, y0 = inset, inset
    x1, y1 = w - inset, h - inset
    cx = (x0 + x1) / 2
    r = (x1 - x0) * 0.13                 # top corner radius
    flank = y0 + (y1 - y0) * 0.42        # where the taper starts

    pts = [(x0 + r, y0)]
    pts += [(x1 - r, y0)]
    # top-right corner
    pts += bez((x1 - r, y0), (x1 - r * 0.45, y0), (x1, y0 + r * 0.45), (x1, y0 + r), 10)
    pts += [(x1, flank)]
    # right flank into the tip
    # Control points chosen by rendering the alternatives side by side: a low
    # second handle keeps the flanks convex and gives the tip a real point
    # instead of the flat-bottomed bucket the first attempt produced.
    pts += bez((x1, flank), (x1, flank + (y1 - flank) * 0.70),
               (cx + (x1 - cx) * 0.14, y1), (cx, y1), 34)
    # tip back up the left flank
    pts += bez((cx, y1), (cx - (cx - x0) * 0.14, y1),
               (x0, flank + (y1 - flank) * 0.70), (x0, flank), 34)
    pts += [(x0, y0 + r)]
    # top-left corner
    pts += bez((x0, y0 + r), (x0, y0 + r * 0.45), (x0 + r * 0.45, y0), (x0 + r, y0), 10)
    return pts


def render(size):
    """One tile at the requested pixel size, drawn big and downsampled.

    The outline is the difference between the silhouette and an inset copy of
    it. Drawing it as a line left artefacts at the corners where the segments
    met, and no join style fixed them.
    """
    s = size * SS
    pad = s * 0.05
    outline_w = max(2, int(s * 0.05))

    def mask_of(inset):
        m = Image.new("L", (s, s), 0)
        ImageDraw.Draw(m).polygon(shield(s, s, inset), fill=255)
        return m

    outer = mask_of(pad)
    inner = mask_of(pad + outline_w)

    # The three colour fields, clipped to the inner silhouette.
    bands = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    bd = ImageDraw.Draw(bands)
    left, width = pad, s - 2 * pad
    for colour, a, b in BANDS:
        bd.rectangle([left + width * a, 0, left + width * b, s], fill=colour)

    # A dark seam between bands so they stay separable at small sizes.
    seam = max(2, int(s * 0.022))
    for _, _, b in BANDS[:-1]:
        x = left + width * b
        bd.rectangle([x - seam / 2, 0, x + seam / 2, s], fill=EDGE)

    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(Image.new("RGBA", (s, s), EDGE), (0, 0), outer)   # outline
    img.paste(bands, (0, 0), inner)                             # fill
    return img.resize((size, size), Image.LANCZOS)


def msi_art(out, tile):
    """The two bitmaps WiX's stock UI expects.

    Light, not dark. The dashboard's palette was the obvious choice and the
    wrong one: WixUI draws every page title and description in **black**, and
    that is baked into the stock dialogs - so a dark banner meant black text on
    dark blue. The brand shows through the mark and the three colours instead,
    on a background the standard text can actually be read against.

    Sizes are fixed by WixUI: 493x58 for the strip across the top of every page,
    493x312 for the welcome and finish pages. BMP because PNG is ignored.
    """
    PAPER = (250, 251, 253)       # near-white, matches the dialog background
    PANEL = (236, 240, 246)       # left column of the welcome page
    RULE = (203, 212, 226)
    MUTED = (90, 104, 128)

    # --- top banner: text space on the left, mark on the right ---
    # WixUI writes the page title over the left of this strip, so nothing of
    # ours may sit there.
    banner = Image.new("RGB", (493, 58), PAPER)
    d = ImageDraw.Draw(banner)
    d.rectangle([0, 56, 493, 58], fill=RULE)
    ico = tile.resize((40, 40), Image.LANCZOS)
    banner.paste(ico, (493 - 40 - 16, 8), ico)
    banner.save(os.path.join(out, "msi-banner.bmp"))
    print("wrote %s" % os.path.join(out, "msi-banner.bmp"))

    # --- welcome/finish panel: mark on the left, text space on the right ---
    dlg = Image.new("RGB", (493, 312), PAPER)
    d = ImageDraw.Draw(dlg)
    d.rectangle([0, 0, 164, 312], fill=PANEL)
    d.rectangle([164, 0, 165, 312], fill=RULE)
    big = tile.resize((108, 108), Image.LANCZOS)
    dlg.paste(big, (28, 72), big)
    y = 206
    for colour, a, b in BANDS:
        d.rectangle([28 + 108 * a, y, 28 + 108 * b, y + 6], fill=colour[:3])
    d.text((28, 222), "NTLMv1", fill=(196, 60, 60))
    d.text((28, 236), "NTLMv2", fill=(160, 112, 20))
    d.text((28, 250), "Kerberos", fill=(20, 130, 92))
    d.text((28, 272), "retire one,", fill=MUTED)
    d.text((28, 285), "keep the other", fill=MUTED)
    dlg.save(os.path.join(out, "msi-dialog.bmp"))
    print("wrote %s" % os.path.join(out, "msi-dialog.bmp"))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="assets")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # Windows picks the nearest size, so ship the ones it actually asks for:
    # 16 in menus and lists, 32 on the desktop, 48 in Explorer, 256 for the
    # large-tile views and the installer.
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    tiles = {n: render(n) for n in sizes}

    ico = os.path.join(args.out, "ntlm-agent.ico")
    tiles[256].save(ico, format="ICO", sizes=[(n, n) for n in sizes])
    print("wrote %s (%d sizes)" % (ico, len(sizes)))

    png = os.path.join(args.out, "icon-256.png")
    tiles[256].save(png)
    print("wrote %s" % png)

    # Side-by-side sheet to judge the small sizes without squinting.
    sheet = Image.new("RGBA", (sum(sizes) + 20 * len(sizes), 300), (14, 19, 31, 255))
    x = 10
    for n in sizes:
        sheet.paste(tiles[n], (x, 150 - n // 2), tiles[n])
        x += n + 20
    sheet.save(os.path.join(args.out, "icon-preview.png"))
    print("wrote %s" % os.path.join(args.out, "icon-preview.png"))

    msi_art(args.out, tiles[256])


if __name__ == "__main__":
    main()
