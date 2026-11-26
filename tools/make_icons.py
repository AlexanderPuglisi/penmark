"""Render the PenMark icon and banner from the SVG sources.

Needs the `resvg` command (cargo install resvg --locked). Uses only the
Python standard library. Run from the repository root:

    python tools/make_icons.py

Outputs:
    assets/brand/png/penmark-<size>.png   one PNG per icon size
    assets/brand/penmark.ico              every size in one Windows icon
    assets/brand/penmark-banner.png       README banner (fonts from assets/fonts)
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "assets" / "brand"
FONTS = ROOT / "assets" / "fonts"
PNG_DIR = BRAND / "png"

# Each size uses the drawing tuned for it: thicker stroke when small.
SOURCES = {
    16: "penmark-icon-16.svg",
    20: "penmark-icon-16.svg",
    24: "penmark-icon-32.svg",
    32: "penmark-icon-32.svg",
    40: "penmark-icon-32.svg",
    48: "penmark-icon-48.svg",
    64: "penmark-icon-48.svg",
    96: "penmark-icon-96.svg",
    128: "penmark-icon-96.svg",
    256: "penmark-icon.svg",
}


def resvg() -> str:
    exe = shutil.which("resvg") or str(Path.home() / ".cargo" / "bin" / "resvg.exe")
    if not Path(exe).exists():
        sys.exit("resvg not found: cargo install resvg --locked")
    return exe


def render(src: Path, out: Path, width: int, height: int | None = None) -> None:
    cmd = [resvg(), "--skip-system-fonts", "-w", str(width)]
    if height is not None:
        cmd += ["-h", str(height)]
    for font in sorted(FONTS.glob("*.ttf")):
        cmd += ["--use-font-file", str(font)]
    cmd += [str(src), str(out)]
    subprocess.run(cmd, check=True)


def write_ico(pngs: list[tuple[int, bytes]], out: Path) -> None:
    """ICO container with PNG entries (supported since Windows Vista)."""
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries = b""
    for size, data in pngs:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    out.write_bytes(header + entries + b"".join(d for _, d in pngs))


def main() -> None:
    PNG_DIR.mkdir(parents=True, exist_ok=True)
    pngs = []
    for size, name in SOURCES.items():
        out = PNG_DIR / f"penmark-{size}.png"
        render(BRAND / name, out, size, size)
        pngs.append((size, out.read_bytes()))
    write_ico(pngs, BRAND / "penmark.ico")
    render(BRAND / "penmark-banner.svg", BRAND / "penmark-banner.png", 1280, 640)
    print(f"{len(pngs)} sizes -> {BRAND / 'penmark.ico'}")


if __name__ == "__main__":
    main()
