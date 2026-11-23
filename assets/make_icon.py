"""Render valet.svg (and valet-small.svg for the tiny sizes) to valet.ico with Edge, then pack it.

Run from anywhere: py -3 assets/make_icon.py   (needs Microsoft Edge and Pillow)
"""
import pathlib
import subprocess
import tempfile

from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def render(svg: pathlib.Path, size: int, out: pathlib.Path) -> Image.Image:
    page = out.with_suffix(".html")
    page.write_text(
        f'<html><body style="margin:0;background:transparent">'
        f'<img src="{svg.as_uri()}" width="{size}" height="{size}" style="display:block"></body></html>',
        encoding="utf-8",
    )
    subprocess.run(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
         "--default-background-color=00000000", f"--window-size={size},{size}",
         f"--screenshot={out}", page.as_uri()],
        check=True, capture_output=True,
    )
    return Image.open(out).convert("RGBA").crop((0, 0, size, size))


with tempfile.TemporaryDirectory() as tmp:
    images = [
        render(HERE / ("valet-small.svg" if s <= 24 else "valet.svg"), s, pathlib.Path(tmp) / f"{s}.png")
        for s in SIZES
    ]
    images[-1].save(HERE / "valet.ico", sizes=[i.size for i in images], append_images=images[:-1])
print("wrote", HERE / "valet.ico")
