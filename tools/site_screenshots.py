"""Regenerate the website's product screenshots from real product output: python tools/build_site.py && python tools/site_screenshots.py

Readiness: its sample report. TLS: a console seeded with an authority and a few certificates, one renewed and one revoked.
"""
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "site"


def tls_console(browser):
    from acxelin_core import console as core
    from acxelin_tls import console as tc
    with tempfile.TemporaryDirectory() as d:
        app = tc.build(Path(d))
        call = lambda path, body=None: app.routes[("POST", path)](body or {})[1]
        call("/api/ca/create", {"name": "Example Root CA"})
        web = call("/api/certificates/issue", {"kind": "server", "common_name": "web.example.com", "names": ["www.example.com"]})
        call("/api/certificates/issue", {"kind": "server", "common_name": "api.example.com"})
        laptop = call("/api/certificates/issue", {"kind": "client", "common_name": "laptop-7.example.com"})
        call("/api/certificates/renew", {"serial": web["serial"]})
        call("/api/certificates/revoke", {"serial": laptop["serial"], "reason": "keyCompromise"})
        server = core.start(app, Path(d), port=0)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 860}, color_scheme="light")
            page.goto(f"http://127.0.0.1:{server.server_address[1]}/#{app.sessions.ticket()}")
            page.get_by_role("cell", name="laptop-7.example.com", exact=True).wait_for()
            page.screenshot(path=str(ROOT / "website/assets/tls-console.png"))
        finally:
            server.shutdown()


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900}, color_scheme="light")
        page.goto((BUILD / "readiness/sample-report.html").as_uri())
        page.screenshot(path=str(ROOT / "website/assets/readiness-report.png"))
        tls_console(browser)
        browser.close()


if __name__ == "__main__":
    main()
