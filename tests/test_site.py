import re
import runpy
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PAGES = ["index.html", "wolf-pack.html", "security.html", "404.html", "product-manual.html"]
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids, self.refs, self.stack, self.products = set(), [], [], []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag not in VOID:
            self.stack.append(a.get("id"))
        if a.get("id"):
            self.ids.add(a["id"])
        if tag == "meta" and re.fullmatch(r"(og|twitter):image", a.get("property") or a.get("name") or ""):
            self.refs.append(a["content"])
        for k in ("href", "src"):
            if a.get(k):
                self.refs.append(a[k])
                if "products" in self.stack:
                    self.products.append(a[k])

    def handle_endtag(self, tag):
        if tag not in VOID and self.stack:
            self.stack.pop()


class SiteTest(unittest.TestCase):
    def page(self, name):
        return Page((SITE / name).read_text(encoding="utf-8"))

    def test_every_link_and_file_resolves(self):
        pages = {n: self.page(n) for n in PAGES}
        for name, p in pages.items():
            for ref in p.refs:
                if re.match(r"(https?:|mailto:|data:)", ref):
                    continue
                path, _, frag = ref.partition("#")
                target = pages.get(path or name)
                if path and target is None:
                    self.assertTrue((SITE / path).exists(), f"{name}: {ref}")
                if frag and target is not None:
                    self.assertIn(frag, target.ids, f"{name}: {ref}")

    def test_fonts_are_served_from_the_site_and_the_finder_links_resolve(self):
        css = (SITE / "style.css").read_text(encoding="utf-8")
        fonts = re.findall(r'url\("(assets/fonts/[^"]+)"\)', css)
        self.assertEqual(len(fonts), 3)
        for f in fonts:
            self.assertTrue((SITE / f).exists(), f)
        for name in PAGES:
            self.assertNotIn("fonts.googleapis.com", (SITE / name).read_text(encoding="utf-8"))
        ids = self.page("index.html").ids
        js = (SITE / "site.js").read_text(encoding="utf-8")
        for href in re.findall(r'\["[^"]+", "([^"]+)", "', js):
            self.assertTrue(href[1:] in ids if href.startswith("#") else (SITE / href).exists(), href)

    def test_sample_report_is_published_and_linked(self):
        self.assertIn("wolf-pack-sample.html", self.page("wolf-pack.html").refs)
        self.assertIn("payments-api", (SITE / "wolf-pack-sample.html").read_text(encoding="utf-8"))

    def test_sample_dashboard_is_published_and_linked(self):
        for name in ("wolf-pack.html", "index.html"):
            self.assertIn("wolf-pack-inventory.html", self.page(name).refs)
        html = (SITE / "wolf-pack-inventory.html").read_text(encoding="utf-8")
        for system in ("payments-api", "customer-portal", "batch-jobs"):
            self.assertIn(system, html)

    def test_wolf_pack_is_reachable_but_not_a_product(self):
        p = self.page("index.html")
        self.assertIn("wolf-pack.html", p.refs)
        self.assertTrue(p.products)
        self.assertFalse([r for r in p.products if "wolf" in r.lower()])
        self.assertEqual(len(re.findall(r'<article class="product"', (SITE / "index.html").read_text(encoding="utf-8"))), 4)

    def test_install_commands_name_the_current_wheels(self):
        suite = re.search(r'__version__ = "(.+)"', (ROOT / "pqcsuite" / "__init__.py").read_text()).group(1)
        wolf = re.search(r'__version__ = "(.+)"', (ROOT / "wolf-pack" / "wolfpack" / "__init__.py").read_text()).group(1)
        for name in ("index.html", "wolf-pack.html", "product-manual.html"):
            wheels = set(re.findall(r"(pqcsuite|wolfpack_cbom)-([\d.]+)-py3-none-any\.whl", (SITE / name).read_text(encoding="utf-8")))
            self.assertTrue(wheels, name)
            self.assertLessEqual(wheels, {("pqcsuite", suite), ("wolfpack_cbom", wolf)}, name)

    def test_wolf_pack_band_sits_between_products_and_plan(self):
        html = (SITE / "index.html").read_text(encoding="utf-8")
        band = re.search(r'<section id="also".*?</section>', html, re.S).group(0)
        self.assertIn('href="wolf-pack.html"', band)
        self.assertLess(html.index('<section id="products"'), html.index('<section id="also"'))
        self.assertLess(html.index('<section id="also"'), html.index('<section id="plan"'))

    def test_console_keeps_wolf_pack_out_of_the_products_group(self):
        html = (ROOT / "pqcsuite" / "console" / "console.html").read_text(encoding="utf-8")
        products = re.search(r'\["Products", \{([^}]*)\}\]', html).group(1)
        self.assertNotIn("wolf", products.lower())
        self.assertIn('["Also from Acxelin", { wolfpack:', html)
        self.assertRegex(html, r"async wolfpack\(")


    def test_the_website_tour_is_the_same_as_the_console_and_vpn_window_tour(self):
        self.assertEqual((SITE / "tour.js").read_bytes(), (ROOT / "pqcsuite" / "tour.js").read_bytes(), "copy pqcsuite/tour.js to site/tour.js")
        from pqcsuite.console import page, policy
        served = page()
        self.assertEqual(served.count(b"<script>"), 1)
        self.assertIn(b"const Tour =", served.split(b"<script>")[1], "the tour runs inside the one inline script the policy hashes")
        self.assertIn("sha256-", policy(served))


class PublishTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.source = self.d / "source"
        self.source.mkdir()
        for name in PAGES:
            (self.source / name).write_text('<head>\n<meta property="og:image" content="image.png">\n</head>')
        self.publish = runpy.run_path(str(SITE / "publish.py"))["publish"]
        self.publish.__globals__["SITE"] = self.source

    def test_publish_is_repeatable_and_preserves_unrelated_output_files(self):
        out = self.d / "output"
        self.publish("https://example.test/pqc/", out)
        (out / "keep.txt").write_text("keep this")
        self.publish("https://example.test/new/", out)
        self.assertEqual((out / "keep.txt").read_text(), "keep this")
        self.assertIn('href="https://example.test/new/"', (out / "index.html").read_text())
        self.assertEqual((out / "index.html").read_text().count('rel="canonical"'), 1)
        self.assertIn("https://example.test/new/wolf-pack.html", (out / "sitemap.xml").read_text())

    def test_source_ancestors_descendants_and_unrelated_folders_are_preserved(self):
        unrelated = self.d / "unrelated"
        unrelated.mkdir()
        (unrelated / "keep.txt").write_text("keep this")
        for out in [self.d, self.source, self.source / "output", unrelated]:
            with self.subTest(out=out), self.assertRaises(SystemExit):
                self.publish("https://example.test/", out)
        self.assertTrue((self.source / "index.html").exists())
        self.assertEqual((unrelated / "keep.txt").read_text(), "keep this")

    def test_source_under_a_symlinked_parent_cannot_be_publish_destination(self):
        alias = self.d / "alias"
        try:
            alias.symlink_to(self.source, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlinks unavailable")
        self.publish.__globals__["SITE"] = alias
        with self.assertRaises(SystemExit):
            self.publish("https://example.test/", self.source / "output")
        self.assertFalse((self.source / "output").exists())

    def test_symlink_destinations_and_markup_in_the_base_are_refused(self):
        out = self.d / "output"
        for base in ['https://example.test/"bad"/', "https://example.test/?bad/", "https://example.test/#bad/"]:
            with self.subTest(base=base), self.assertRaises(SystemExit):
                self.publish(base, out)
        try:
            out.symlink_to(self.source, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        with self.assertRaises(SystemExit):
            self.publish("https://example.test/", out)
        self.assertTrue(out.is_symlink())

    def test_report_favicons_are_self_contained(self):
        for name in ("wolf-pack-sample.html", "wolf-pack-inventory.html"):
            content = (SITE / name).read_text()
            self.assertIn('<link rel="icon" href="data:image/svg+xml;base64,', content)


if __name__ == "__main__":
    unittest.main()
