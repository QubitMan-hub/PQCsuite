"""Regenerate the website's product screenshots from real product output: python tools/build_site.py && python tools/site_screenshots.py

Readiness: its sample report. TLS: a console seeded with an authority and a few certificates, one renewed and one revoked.
VPN: the console's People tab after a real invitation and a revocation, and the app window opening a real invitation.
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
            page = browser.new_page(viewport={"width": 1280, "height": 890}, color_scheme="light")
            page.goto(f"http://127.0.0.1:{server.server_address[1]}/#{app.sessions.ticket()}")
            page.get_by_role("cell", name="laptop-7.example.com", exact=True).wait_for()
            page.screenshot(path=str(ROOT / "website/assets/tls-console.png"))
        finally:
            server.shutdown()


def vpn_console(browser):
    from acxelin_core import console as core
    from acxelin_core.pki import CA
    from acxelin_vpn import console as vc
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        ca = CA.init(home / "ca", "Acme VPN Root")
        for who in ("alice", "bob", "carol"):
            ca.issue(who, "client", out=home / who)
        app = vc.build(home)
        call = lambda path, body=None: app.routes[("POST", path)](body or {})
        call("/api/people/settings", {"enroll": "https://ca.acme.example:9443", "gateway": "vpn.acme.example:7443"})
        call("/api/people/invite", {"name": "dave", "hours": 24})
        call("/api/people/revoke", {"name": "carol"})
        server = core.start(app, home, port=0)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 890}, color_scheme="light")
            page.goto(f"http://127.0.0.1:{server.server_address[1]}/#{app.sessions.ticket()}")
            page.get_by_role("tab", name="People").click()
            page.get_by_role("cell", name="carol", exact=True).wait_for()
            page.screenshot(path=str(ROOT / "website/assets/vpn-console.png"))
        finally:
            server.shutdown()


def vpn_app(browser):
    import threading
    from acxelin_core.pki import CA
    from acxelin_vpn import app, join
    with tempfile.TemporaryDirectory() as d:
        folder = Path(d)
        ca = CA.init(folder / "ca", "Acme VPN Root")
        (folder / "alice.acxinvite").write_bytes(join.make(ca, "alice", "https://ca.acme.example:9443", "vpn.acme.example:7443")[0])
        window = app.App(folder=folder, apply=False)
        server = app.serve(window)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            page = browser.new_page(viewport={"width": 480, "height": 760}, color_scheme="light")
            page.goto(f"http://127.0.0.1:{server.server_address[1]}/#{window.ticket()}")
            page.get_by_text("alice").first.wait_for()
            page.wait_for_timeout(500)
            page.screenshot(path=str(ROOT / "website/assets/vpn-app.png"))
        finally:
            server.shutdown()


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900}, color_scheme="light")
        page.goto((BUILD / "readiness/sample-report.html").as_uri())
        page.screenshot(path=str(ROOT / "website/assets/readiness-report.png"))
        tls_console(browser)
        vpn_console(browser)
        vpn_app(browser)
        browser.close()


if __name__ == "__main__":
    main()
