import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PAGES = ["index.html", "wolf-pack.html"]
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

    def test_wolf_pack_is_reachable_but_not_a_product(self):
        p = self.page("index.html")
        self.assertIn("wolf-pack.html", p.refs)
        self.assertTrue(p.products)
        self.assertFalse([r for r in p.products if "wolf" in r.lower()])
        self.assertEqual(len(re.findall(r'<article class="product"', (SITE / "index.html").read_text(encoding="utf-8"))), 4)

    def test_console_keeps_wolf_pack_out_of_the_products_group(self):
        html = (ROOT / "pqcsuite" / "console" / "console.html").read_text(encoding="utf-8")
        products = re.search(r'\["Products", \{([^}]*)\}\]', html).group(1)
        self.assertNotIn("wolf", products.lower())
        self.assertIn('["Also from Acxelin", { wolfpack:', html)
        self.assertIn("wolfpack() {", html)


if __name__ == "__main__":
    unittest.main()
