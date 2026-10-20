"""The Acxelin VPN administrator console in a real browser: what an administrator does, with axe on every tab in light, dark
and phone width."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from acxelin_core import console as core
from acxelin_core.pki import CA

from acxelin_vpn import console as vc
from acxelin_vpn import join

sync = pytest.importorskip("playwright.sync_api")
AXE = Path(__file__).resolve().parents[4] / "tools/browser/node_modules/axe-core/axe.min.js"
PASS = "vpn-ca-pass-81d0"


@pytest.fixture(scope="module")
def browser():
    with sync.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"no Playwright browser: {e}")
        yield b
        b.close()


@pytest.fixture
def console(tmp_path):
    home = tmp_path / "home"
    ca = CA.init(home / "ca", "VPN Root", passphrase=PASS.encode())
    _, rec = ca.issue("branch.acme", "site", ["10.0.0.2"], out=tmp_path / "branch")
    ca.issue("alice", "client", out=tmp_path / "alice")
    status = {"branch.acme": {"initiate": True, "profile": "standard", "keys_age_s": 42, "certificate": rec.serial,
                              "tunnel": {"peer": "branch.acme", "state": "ESTABLISHED", "key_exchange": "CURVE_25519 + ML_KEM_768", "ppk": True,
                                         "encryption": "AES_GCM_16_256", "established_s": 300,
                                         "children": [{"name": "net", "state": "INSTALLED", "encryption": "AES_GCM_16_256", "bytes_in": 10, "bytes_out": 20}]}}}

    class Site(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(status).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    site = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    app = vc.build(home)
    server = core.start(app, home, port=0)
    yield app, f"http://127.0.0.1:{server.server_address[1]}", home, f"http://127.0.0.1:{site.server_address[1]}"
    server.shutdown()
    site.shutdown()


def opened(browser, console, **ctx):
    app, base, _, _ = console
    c = browser.new_context(accept_downloads=True, **({"viewport": {"width": 1280, "height": 900}} | ctx))
    page = c.new_page()
    page.goto(f"{base}/#{app.sessions.ticket()}")
    page.get_by_role("heading", name="Unlock the certificate authority").wait_for()
    page.get_by_label("Passphrase").fill("wrong")
    page.get_by_role("button", name="Unlock").click()
    page.get_by_text("does not open the CA key").wait_for()
    page.get_by_label("Passphrase").fill(PASS)
    page.get_by_role("button", name="Unlock").click()
    page.get_by_role("heading", name="Sites").wait_for()
    return c, page


def test_an_administrator_adds_a_site_and_reads_its_tunnel(browser, console):
    c, page = opened(browser, console)
    page.get_by_label("Name", exact=True).fill("Headquarters")
    page.get_by_label("Status address").fill(console[3])
    page.get_by_role("button", name="Add a site").click()
    page.get_by_role("heading", name="Headquarters").wait_for()
    for text in ("branch.acme", "Protected", "CURVE_25519 + ML_KEM_768", "AES_GCM_16_256", "42 s ago", "branch.acme · valid"):
        assert page.get_by_text(text).first.is_visible(), text
    page.get_by_role("button", name="Remove Headquarters").click()
    page.get_by_text("No sites added yet").wait_for()
    c.close()


def test_an_administrator_invites_someone_downloads_the_file_and_revokes_alice_in_two_steps(browser, console, tmp_path):
    c, page = opened(browser, console)
    page.get_by_role("tab", name="People").click()
    page.get_by_label("Enrollment service").fill("https://ca.example:9443")
    page.get_by_label("Gateway key agreement address").fill("vpn.example:7443")
    page.get_by_role("button", name="Save", exact=True).click()
    page.get_by_text("Saved.").wait_for()
    page.get_by_label("Their name").fill("bob")
    with page.expect_download() as d:
        page.get_by_role("button", name="Download invitation").click()
    saved = tmp_path / d.value.suggested_filename
    d.value.save_as(saved)
    assert saved.name == "bob.acxinvite" and join.read(saved)["name"] == "bob"
    page.get_by_text("Downloaded bob.acxinvite").wait_for()
    page.get_by_role("cell", name="alice", exact=True).wait_for()
    page.get_by_role("button", name="Revoke alice").click()
    page.get_by_role("button", name="Confirm revoke alice").click()
    page.get_by_role("cell", name="Revoked", exact=True).wait_for()
    assert page.get_by_text("Revoked alice").is_visible() and page.get_by_text("Invited bob").is_visible()
    assert PASS not in page.content() and join.parse(saved.read_text())["token"] not in page.content()
    c.close()


def test_health_lists_checks_with_what_to_do(browser, console):
    c, page = opened(browser, console)
    page.get_by_role("tab", name="Health").click()
    page.locator("th", has_text="What to do").wait_for()
    assert page.get_by_text("VPN Root").first.is_visible()
    c.close()


def test_a_used_link_says_how_to_open_a_new_one(browser, console):
    app, base, _, _ = console
    ticket = app.sessions.ticket()
    c = browser.new_context()
    first, second = c.new_page(), c.new_page()
    first.goto(f"{base}/#{ticket}")
    first.get_by_role("heading", name="Unlock the certificate authority").wait_for()
    assert "#" not in first.url and c.cookies() == []
    second.goto(f"{base}/#{ticket}")
    second.get_by_role("heading", name="This link has expired").wait_for()
    assert "acxelin-vpn console" in second.content()
    c.close()


def test_a_new_administrator_creates_the_certificate_authority_in_the_console(browser, tmp_path):
    home = tmp_path / "fresh"
    app = vc.build(home)
    server = core.start(app, home, port=0)
    c = browser.new_context()
    page = c.new_page()
    try:
        page.goto(f"http://127.0.0.1:{server.server_address[1]}/#{app.sessions.ticket()}")
        page.get_by_role("heading", name="Create the VPN's certificate authority").wait_for()
        page.get_by_label("Name").fill("Example VPN Root")
        page.get_by_label("Passphrase (recommended)").fill(PASS)
        page.get_by_label("Repeat passphrase").fill(PASS + "x")
        page.get_by_role("button", name="Create certificate authority").click()
        page.get_by_text("The two passphrases are different").wait_for()
        assert not (home / "ca/ca.crt").exists()
        page.get_by_label("Repeat passphrase").fill(PASS)
        page.get_by_role("button", name="Create certificate authority").click()
        page.get_by_role("heading", name="Sites").wait_for()
        assert CA(home / "ca").cert.subject.rfc4514_string() == "CN=Example VPN Root"
        page.get_by_role("tab", name="People").click()
        first = page.get_by_role("heading", name="First, say where invitations point")
        first.wait_for()
        assert first.bounding_box()["y"] < page.get_by_role("heading", name="Invite someone").bounding_box()["y"]
        page.get_by_text("Use Invite someone to add the first person.").wait_for()
        assert "on the left" not in page.content()
    finally:
        c.close()
        server.shutdown()


@pytest.mark.parametrize("width,scheme", [(1280, "light"), (1280, "dark"), (390, "light")])
def test_every_tab_passes_axe_and_fits_the_screen(browser, console, width, scheme):
    c, page = opened(browser, console, viewport={"width": width, "height": 900}, color_scheme=scheme)
    axe = AXE.read_text()
    run = "axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))"
    found = {"sites": page.evaluate(axe + ";" + run)}
    for tab in ("People", "Health"):
        page.get_by_role("tab", name=tab).click()
        page.get_by_role("heading", name=tab, exact=True).wait_for()
        found[tab] = page.evaluate(run)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (tab, "scrolls sideways")
    assert not any(found.values()), found
    c.close()
