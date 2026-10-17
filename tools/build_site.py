"""Build the website into build/site: python tools/build_site.py

Pages in website/ hold only their content; this wraps each with the shared head, header and footer. A section's pages show
only that product's navigation. The Readiness sample report and CBOM are produced by running the product on its example project.
"""
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC, OUT = ROOT / "website", ROOT / "build" / "site"
SECTIONS = {
    "tls": ("Acxelin TLS", [("index.html", "Overview"), ("how-it-works.html", "How it works"), ("set-up.html", "Set up"),
                            ("demo.html", "Demo"), ("security.html", "Security")]),
    "readiness": ("Acxelin Readiness", [("index.html", "Overview"), ("how-it-works.html", "How it works"), ("set-up.html", "Set up"),
                                         ("sample.html", "Sample"), ("security.html", "Security")]),
}
LAYOUT = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="icon" href="{root}assets/acxelin-quantum.svg" type="image/svg+xml">
<link rel="stylesheet" href="{root}assets/site.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="wrap bar">
<a href="{root}index.html" aria-label="Acxelin Quantum, all products">{logo}</a>
<nav aria-label="{nav_label}">{nav}</nav>
</div></header>
<main id="main"><div class="wrap">
{body}
</div></main>
<footer><div class="wrap"><span>{product} is made by <a href="https://acxelinquantum.com/">Acxelin Quantum</a>. © 2026 Acxelin Quantum. All rights reserved.</span><a href="{root}index.html">All products</a></div></footer>
<script>
document.querySelectorAll("main pre").forEach((pre) => {
  const wrap = document.createElement("div"), button = document.createElement("button");
  wrap.className = "code";
  button.type = "button"; button.className = "copy"; button.textContent = "Copy"; button.setAttribute("aria-label", "Copy command");
  button.addEventListener("click", async () => {
    const say = (text, label) => { button.textContent = text; button.setAttribute("aria-label", label); };
    try { await navigator.clipboard.writeText(pre.innerText.replace(/\n$/, "")); say("Copied", "Copied"); }
    catch (e) { say("Select and copy", "Select and copy by hand"); }
    setTimeout(() => say("Copy", "Copy command"), 1800);
  });
  pre.replaceWith(wrap); wrap.append(pre, button);
});
</script>
</body>
</html>
"""


def logo():
    svg = (ROOT / "website/assets/acxelin-quantum.svg").read_text(encoding="utf-8")
    return svg.replace('class="logo"', 'class="logo" aria-hidden="true" focusable="false"')


def nav(section, current, root):
    if not section:
        return '<a href="https://acxelinquantum.com/">Acxelin Quantum</a>'
    name, pages = SECTIONS[section]
    mark = lambda href: ' aria-current="page"' if href == current else ""
    links = "".join(f'<a href="{href}"{mark(href)}>{label}</a>' for href, label in pages)
    return f'<a class="product" href="index.html">{name}</a>{links}'


def sample(out):
    """Run the product on its example project; the site shows what it really produced."""
    from acxelin_readiness import cli
    project = ROOT / "products/readiness/examples/payments-api"
    with tempfile.TemporaryDirectory() as tmp:
        cli.main(["scan", str(project), "-o", tmp, "-q"])
        shutil.copy(Path(tmp) / "report.html", out / "readiness/sample-report.html")
        shutil.copy(Path(tmp) / "cbom.json", out / "readiness/sample-cbom.json")
        bom = json.loads((Path(tmp) / "cbom.json").read_text())
    parts = [c for c in bom["components"] if c.get("type") == "cryptographic-asset" and (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"][:2]
    return html.escape(json.dumps(parts, indent=2))


def tls_tour():
    """The real output of `acxelin-tls try`. The build fails when it cannot run (it needs OpenSSL 3.5+): the page never shows invented output."""
    run = subprocess.run([sys.executable, "-m", "acxelin_tls", "try"], capture_output=True, text=True, timeout=120)
    if run.returncode:
        sys.exit(f"acxelin-tls try failed (set ACXELIN_OPENSSL to an OpenSSL 3.5+ folder): {run.stderr or run.stdout}")
    return html.escape(run.stdout.strip("\n"))


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(SRC / "assets", OUT / "assets")
    for section in SECTIONS:
        (OUT / section).mkdir(parents=True)
    excerpt = sample(OUT)
    tour = tls_tour()
    mark = logo()
    for src in sorted(SRC.rglob("*.html")):
        rel = src.relative_to(SRC)
        text = src.read_text(encoding="utf-8")
        meta = re.match(r"<!-- title: (.*?) -->\n<!-- description: (.*?) -->\n", text)
        if not meta:
            sys.exit(f"{rel}: the first two lines must be the title and description comments")
        section = rel.parts[0] if len(rel.parts) > 1 else None
        root = "../" if section else ""
        name = SECTIONS[section][0] if section else "Acxelin Quantum"
        body = text[meta.end():].replace("{{CBOM_EXCERPT}}", excerpt).replace("{{TLS_TOUR}}", tour).replace("{root}", root).replace("<pre>", '<pre tabindex="0">').replace('<div class="scroll">', '<div class="scroll" tabindex="0" role="region" aria-label="Table, scrolls sideways">')
        values = {"title": meta.group(1), "description": meta.group(2), "root": root, "logo": mark, "product": name, "body": body,
                  "nav": nav(section, rel.name, root), "nav_label": name}
        page = LAYOUT
        for key, value in values.items():
            page = page.replace("{" + key + "}", value)
        (OUT / rel).parent.mkdir(parents=True, exist_ok=True)
        (OUT / rel).write_text(page, encoding="utf-8")
    print(f"built {OUT}")


if __name__ == "__main__":
    main()
