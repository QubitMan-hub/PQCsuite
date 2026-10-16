"""The Readiness section of the website, in a real browser: the customer's journey, not just the markup."""
import functools
import http.server
import re
import sys
import threading
from pathlib import Path

import pytest

sync = pytest.importorskip("playwright.sync_api")
ROOT = Path(__file__).resolve().parents[4]
AXE = ROOT / "tools/browser/node_modules/axe-core/axe.min.js"
PAGES = ["index.html", "readiness/index.html", "readiness/how-it-works.html", "readiness/set-up.html", "readiness/sample.html", "readiness/security.html"]
OTHER_PRODUCTS = re.compile(r"Acxelin (TLS|VPN|Q-Vault|Vault)|Wolf ?Pack|wolfpack|PQC ?Suite(?!/)", re.I)  # the repository path QubitMan-hub/PQCsuite/... is a real URL, not a product name


@pytest.fixture(scope="module")
def site():
    sys.path.insert(0, str(ROOT / "tools"))
    import build_site
    build_site.main()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(build_site.OUT))
    handler.log_message = lambda *a: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", build_site.OUT
    server.shutdown()


@pytest.fixture(scope="module")
def browser():
    with sync.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"no Playwright browser: {e}")
        yield b
        b.close()


def test_home_to_install_command_copied(browser, site):
    base, _ = site
    ctx = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
    page = ctx.new_page()
    page.goto(base + "/index.html")
    page.get_by_role("link", name="See Acxelin Readiness").click()
    page.get_by_role("heading", level=1).wait_for()
    assert page.url.endswith("/readiness/index.html")
    page.get_by_role("link", name="Set up in three commands").click()
    page.get_by_role("heading", name="Set up Acxelin Readiness").wait_for()
    page.get_by_role("button", name="Copy command").first.click()
    assert page.evaluate("navigator.clipboard.readText()") == 'pip install ./core "./products/readiness[crawler]"'
    page.get_by_role("button", name="Copied").wait_for()
    ctx.close()


def test_product_pages_show_only_their_own_product(browser, site):
    base, _ = site
    page = browser.new_page()
    for path in PAGES[1:]:
        page.goto(f"{base}/{path}")
        text = page.inner_text("body")
        assert not OTHER_PRODUCTS.search(text), (path, OTHER_PRODUCTS.search(text).group(0))
        nav = page.get_by_role("navigation", name="Acxelin Readiness")
        assert [a.inner_text() for a in nav.get_by_role("link").all()] == ["Acxelin Readiness", "Overview", "How it works", "Set up", "Sample", "Security"]
    page.goto(base + "/index.html")
    home = page.inner_text("body")
    assert "Acxelin Readiness" in home and not re.search(r"Acxelin (TLS|VPN|Q-Vault)|how it works|set up", home, re.I)
    page.close()


def test_sample_report_and_cbom_are_real_output(browser, site):
    base, out = site
    page = browser.new_page()
    page.goto(base + "/readiness/sample.html")
    frame = page.frame_locator("iframe.report")
    frame.get_by_text("payments-api").first.wait_for()
    assert page.locator("pre code").first.inner_text().lstrip().startswith("[")
    bom = (out / "readiness/sample-cbom.json").read_text()
    assert '"specVersion": "1.6"' in bom
    shown = page.locator("pre code").first.inner_text()
    assert '"cryptoProperties"' in shown and '"bom-ref"' in shown
    page.close()


def test_hero_image_loads_and_every_internal_link_resolves(browser, site):
    base, out = site
    page = browser.new_page()
    page.goto(base + "/readiness/index.html")
    assert page.evaluate("document.querySelector('.shot img').complete && document.querySelector('.shot img').naturalWidth > 0")
    broken = []
    for path in PAGES:
        page.goto(f"{base}/{path}")
        for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))"):
            if href.startswith(("http", "#", "mailto:")):
                continue
            target = (out / path).parent / href.split("#")[0]
            if not target.exists():
                broken.append((path, href))
    assert not broken, broken
    page.close()


@pytest.mark.parametrize("scheme,width", [("light", 1280), ("dark", 1280), ("light", 390)])
def test_every_page_passes_axe_and_does_not_scroll_sideways(browser, site, scheme, width):
    base, _ = site
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = ctx.new_page()
    axe = AXE.read_text()
    found = {}
    for path in PAGES:
        page.goto(f"{base}/{path}")
        page.wait_for_load_state("networkidle")
        violations = page.evaluate(axe + ";axe.run({exclude:[['iframe']]}).then(r=>r.violations.map(v=>v.id+': '+v.nodes.slice(0,2).map(n=>n.html.slice(0,60)).join(' | ')))")
        if violations:
            found[path] = violations
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (path, "scrolls sideways")
    assert not found, found
    ctx.close()


def test_skip_link_and_keyboard_reach_the_main_content(browser, site):
    base, _ = site
    page = browser.new_page()
    page.goto(base + "/readiness/index.html")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.className") == "skip"
    page.keyboard.press("Enter")
    assert page.evaluate("location.hash") == "#main"
    page.close()
