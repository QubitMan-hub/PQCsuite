"""Readiness console journeys in a real browser: what a customer does, not what the API returns.

Run with the Playwright browser installed (`python -m playwright install chromium`); skipped when it is not.
"""
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from acxelin_core import console as core

from acxelin_readiness import console as rc

sync = pytest.importorskip("playwright.sync_api")
AXE = Path(__file__).resolve().parents[4] / "tools/browser/node_modules/axe-core/axe.min.js"


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
def repos(tmp_path):
    root = tmp_path / "repos"
    (root / "shop").mkdir(parents=True)
    (root / "shop/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n\ndef issue_key():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (root / "api").mkdir()
    (root / "api/a.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    return root


@pytest.fixture
def console(tmp_path):
    app = rc.build(tmp_path / "home")
    server = core.start(app, tmp_path / "home", port=0)
    yield app, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def page(browser, console):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    yield pg
    ctx.close()


def open_console(page, console):
    app, base = console
    page.goto(f"{base}/#{app.sessions.ticket()}")


def fill_setup(page, repos):
    page.get_by_label("Folder path").fill(str(repos))
    page.get_by_role("button", name="Use this folder").click()
    page.get_by_role("tab", name="Projects").wait_for()


def scan_shop(page):
    page.get_by_label("Add a repository").select_option("shop")
    page.get_by_role("button", name="Add", exact=True).click()
    page.get_by_role("button", name="Scan repository").click()
    page.get_by_role("cell", name="RSA", exact=False).first.wait_for(timeout=30000)


def test_first_run_signs_in_without_leaving_a_ticket_or_cookie(page, console, repos):
    app, base = console
    ticket = app.sessions.ticket()
    page.goto(f"{base}/#{ticket}")
    page.get_by_role("heading", name="Where are your repositories?").wait_for()
    assert "#" not in page.url and ticket not in page.url
    assert page.context.cookies() == []
    assert page.evaluate("sessionStorage.getItem('acx-token')")
    fill_setup(page, repos)
    page.go_back() if False else None
    again = page.context.new_page()
    again.goto(f"{base}/#{ticket}")
    again.get_by_role("heading", name="This link has expired").wait_for()
    assert "acxelin-readiness console" in again.content()


def test_add_scan_see_priorities_and_assign_an_owner(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    assert page.get_by_text("critical").first.is_visible() or page.get_by_text("high").first.is_visible()
    page.get_by_text("Assign an owner").first.click()
    page.get_by_label("Owner").first.fill("payments team")
    page.get_by_role("button", name="Save").first.click()
    page.get_by_text("Owner: payments team").wait_for()
    assert "key_size=2048" not in page.content()


def test_stopping_a_scan_keeps_the_previous_result(page, console, repos):
    app, _ = console
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    first = page.get_by_text("Scanned", exact=False).first.inner_text()

    def slow(path, **kw):
        kw["cancel"].wait(20)
        raise rc.workspace.ScanStopped("Scan cancelled; the previous completed assessment is preserved")
    with patch("acxelin_readiness.console.workspace.scan", side_effect=slow):
        page.get_by_role("button", name="Scan repository").click()
        page.get_by_role("button", name="Stop scan").click()
        page.get_by_text("cancelled", exact=False).wait_for()
    assert page.get_by_text("Scanned", exact=False).first.inner_text() == first
    page.get_by_role("button", name="Scan repository").wait_for()


def test_choosing_another_repository_shows_its_own_state(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    page.get_by_label("Add a repository").select_option("api")
    page.get_by_role("button", name="Add", exact=True).click()
    page.get_by_role("button", name="api").click()
    page.get_by_text("Not scanned yet").wait_for()
    page.get_by_role("button", name="shop").click()
    page.get_by_role("cell", name="RSA", exact=False).first.wait_for()


def grade(target, g):
    return {"target": target, "grade": g, "protocol": "tls", "certificate": None, "negotiated": "TLS 1.3 X25519MLKEM768" if g == "A" else "TLS 1.3 X25519", "group": ""}


def test_endpoints_changes_since_the_last_check_and_cbom_download(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    page.get_by_role("tab", name="Endpoints").click()
    runs = iter([[grade("127.0.0.1:1", "F")], [grade("127.0.0.1:1", "A")]])
    with patch("acxelin_readiness.console.endpoints.scan", side_effect=lambda t: next(runs)):
        for _ in range(2):
            page.get_by_label("Hosts to check").fill("127.0.0.1:1")
            page.get_by_role("button", name="Check endpoints").click()
            page.get_by_role("button", name="Check endpoints").wait_for(state="visible")
            page.wait_for_function("!document.querySelector('#check').disabled")
        page.get_by_role("heading", name="Changed since the scan before").wait_for()
        assert "127.0.0.1:1: F → A" in page.content()
    with page.expect_download(timeout=60000) as d:
        page.get_by_role("button", name="Download CBOM").click()
    cbom = json.loads(Path(d.value.path()).read_text())
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    assert d.value.suggested_filename == "endpoints-cbom.json"


@pytest.mark.parametrize("width,scheme", [(1280, "light"), (1280, "dark"), (390, "light")])
def test_no_accessibility_violations_and_no_sideways_scroll(browser, console, repos, width, scheme):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = ctx.new_page()
    try:
        open_console(page, console)
        page.get_by_role("heading", name="Where are your repositories?").wait_for()
        views = []
        views.append(page.evaluate(AXE.read_text() + ";axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))"))
        fill_setup(page, repos)
        scan_shop(page)
        views.append(page.evaluate("axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))"))
        page.get_by_role("tab", name="Endpoints").click()
        views.append(page.evaluate("axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))"))
        assert views == [[], [], []], views
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    finally:
        ctx.close()


def test_keyboard_only_reaches_setup_and_submits(page, console, repos):
    open_console(page, console)
    page.get_by_label("Folder path").wait_for()
    assert page.evaluate("document.activeElement.id") == "dir"
    page.keyboard.type(str(repos))
    page.keyboard.press("Enter")
    page.get_by_role("tab", name="Projects").wait_for()
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement !== document.body")
    time.sleep(0)
