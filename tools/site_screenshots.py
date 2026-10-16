"""Regenerate the website's product screenshots from the built site: python tools/build_site.py && python tools/site_screenshots.py"""
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "site"


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900}, color_scheme="light")
        page.goto((BUILD / "readiness/sample-report.html").as_uri())
        page.screenshot(path=str(ROOT / "website/assets/readiness-report.png"))
        browser.close()


if __name__ == "__main__":
    main()
