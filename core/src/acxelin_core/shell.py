"""The page shell every product console shares: Acxelin's colours, typeface and logo inlined into one self-contained page, so the
page's content-security policy can forbid every external source. A product's page marks where they go with /*SHELL*/ and <!--LOGO-->."""
import base64
import functools
from pathlib import Path

ASSETS = Path(__file__).parent / "assets"


@functools.cache
def _parts():
    font = base64.b64encode((ASSETS / "host-grotesk.woff2").read_bytes()).decode()
    css = (ASSETS / "shell.css").read_text(encoding="utf-8")
    face = '@font-face{font-family:"Host Grotesk";src:url(data:font/woff2;base64,' + font + ') format("woff2");font-weight:300 700;font-display:swap}'
    return face + css, (ASSETS / "acxelin-quantum.svg").read_text(encoding="utf-8")


def render(html):
    css, logo = _parts()
    return html.replace("/*SHELL*/", css).replace("<!--LOGO-->", logo).encode()
