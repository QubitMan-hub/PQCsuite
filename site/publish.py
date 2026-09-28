"""Copies the site into a folder ready to publish, with the absolute addresses that search engines and link previews need.

    python site/publish.py https://www.example.com/pqc-suite/ dist
"""
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urljoin

SITE = Path(__file__).resolve().parent
PAGES = ["index.html", "wolf-pack.html"]


def publish(base, out):
    if not re.fullmatch(r"https://[^/\s]+/(\S*/)?", base):
        raise SystemExit("the address must start with https:// and end with /")
    out = Path(out)
    shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(SITE, out, ignore=shutil.ignore_patterns("publish.py", "og.html", "__pycache__"))
    for page in PAGES:
        url = urljoin(base, "" if page == "index.html" else page)
        p = out / page
        s = p.read_text(encoding="utf-8")
        s = s.replace("<head>\n", f'<head>\n<link rel="canonical" href="{url}">\n<meta property="og:url" content="{url}">\n', 1)
        s = re.sub(r'(<meta (?:property|name)="(?:og|twitter):image" content=")([^"]+)"', lambda m: f'{m.group(1)}{urljoin(base, m.group(2))}"', s)
        p.write_text(s, encoding="utf-8")
    p = out / "404.html"
    p.write_text(p.read_text(encoding="utf-8").replace("<head>\n", f'<head>\n<base href="{base}">\n', 1), encoding="utf-8")
    urls = "".join(f"  <url><loc>{urljoin(base, '' if p == 'index.html' else p)}</loc></url>\n" for p in PAGES)
    (out / "sitemap.xml").write_text(f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{urls}</urlset>\n', encoding="utf-8")
    (out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {urljoin(base, 'sitemap.xml')}\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    publish(sys.argv[1], sys.argv[2])
    print(f"published to {sys.argv[2]}")
