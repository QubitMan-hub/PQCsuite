"""The page shell every product console shares: Acxelin's colours, typefaces and logo inlined into one self-contained page, so the
page's content-security policy can forbid every external source. A product's page marks where they go with /*SHELL*/ and <!--LOGO-->;
the shared script goes at the start of its one inline script."""
import base64
import functools
from pathlib import Path

ASSETS = Path(__file__).parent / "assets"


@functools.cache
def _parts():
    face = "".join('@font-face{font-family:"%s";src:url(data:font/woff2;base64,%s) format("woff2");font-weight:%s;font-display:swap}'
                   % (family, base64.b64encode((ASSETS / f).read_bytes()).decode(), weight)
                   for family, f, weight in (("Host Grotesk", "host-grotesk.woff2", "300 700"), ("Roboto Mono", "roboto-mono.woff2", "400 500")))
    return (face + (ASSETS / "shell.css").read_text(encoding="utf-8"), (ASSETS / "acxelin-quantum.svg").read_text(encoding="utf-8"),
            (ASSETS / "shell.js").read_text(encoding="utf-8"))


def render(html):
    css, logo, js = _parts()
    return html.replace("/*SHELL*/", css).replace("<!--LOGO-->", logo).replace("<script>", "<script>\n" + js, 1).encode()
