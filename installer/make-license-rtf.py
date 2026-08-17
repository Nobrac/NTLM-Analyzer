#!/usr/bin/env python3
"""Convert a plain-text licence into the RTF the installer's licence page needs.

This exists as a script rather than a few lines inside the workflow because the
conversion is mostly backslash handling, and doing that inline meant escaping
through YAML into PowerShell into a .NET string - which produced a wrong result
three times in a row. Here it is plain Python, and it can be tested.

Usage:
    python installer/make-license-rtf.py LICENSE license.rtf
"""
import sys


def to_rtf(text):
    # RTF's own escapes first, and in this order: doing the braces before the
    # backslash would escape the backslashes we just inserted.
    out = text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
    # Normalise line endings before turning them into paragraphs, otherwise a
    # CRLF file yields an empty paragraph per line.
    out = out.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\par\n")
    # Anything above ASCII has to be a \uN escape - the licence is ASCII today,
    # but a copyright sign added later would otherwise corrupt the page.
    buf = []
    for ch in out:
        buf.append(ch if ord(ch) < 128 else "\\u%d?" % ord(ch))
    body = "".join(buf)
    return ("{\\rtf1\\ansi\\ansicpg1252\\deff0"
            "{\\fonttbl{\\f0\\fswiss Segoe UI;}}"
            "\\fs17 " + body + "}")


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: make-license-rtf.py <input.txt> <output.rtf>")
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        text = f.read()
    rtf = to_rtf(text)
    # ASCII only, so the file is valid RTF regardless of the reader's codepage.
    with open(dst, "w", encoding="ascii", newline="") as f:
        f.write(rtf)
    print("wrote %s (%d bytes from %d)" % (dst, len(rtf), len(text)))


if __name__ == "__main__":
    main()
