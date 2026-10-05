"""Render the customer manual from its Markdown source as one self-contained page in the website's style: a contents
sidebar, a card per task to start from, a banner per chapter, and the screenshots embedded so the copy attached to
each release works offline.

Build-only dependency: markdown-it-py==4.2.0. Run from an installed source checkout.
"""
import base64
import datetime as dt
import html
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pqcsuite import __version__  # noqa: E402
from pqcsuite.brand import _assets  # noqa: E402

START = [  # (what you want to do, what it gives you, the chapter or section that does it)
    ("Find the cryptography in our code", "Scan a repository, rank what to change first", "wolf-pack-find-cryptography-in-code"),
    ("Grade our servers", "See which endpoints are exposed, and why", "readiness-understand-exposure-and-next-actions"),
    ("Protect a service", "Post-quantum TLS in front of an app or database", "tls-and-mtls-protect-one-service-connection"),
    ("Connect a laptop", "Join the VPN with the Acxelin VPN app", "enroll-and-connect-a-laptop"),
    ("Protect backups", "Encrypt files and prove a restore works", "vault-protect-files-and-backups"),
    ("Install it", "The release wheels, step by step", "install-a-release"),
]

# sections a first-time reader can skip; they open with one click and print in full
FOLDED = {"install-the-current-checkout", "additional-product-prerequisites", "update-without-losing-work", "what-gets-saved",
          "split-tunnel-full-tunnel-and-recovery", "signatures-and-trusted-senders"}

STYLE = """
:root { --bg: #faf9f5; --paper: #ffffff; --ink: #2e3c4e; --body: #3f4c59; --muted: #636e78; --rule: #e6e0d2; --amber: #ffbf00;
  --amber-deep: #8a6100; --amber-wash: #fff6dc; --code: #26313c; --code-ink: #f4efe2;
  --display: "Host Grotesk", "Segoe UI", system-ui, sans-serif; --text: "Segoe UI", system-ui, -apple-system, Roboto, sans-serif;
  --mono: ui-monospace, "Cascadia Mono", "SF Mono", Consolas, monospace; color-scheme: light; }
* { box-sizing: border-box; }
html { scroll-padding-top: 84px; }
body { margin: 0; background: var(--bg); color: var(--body); font: 16px/1.65 var(--text); -webkit-font-smoothing: antialiased; }
a { color: var(--amber-deep); text-underline-offset: 3px; }
.top { position: sticky; top: 0; z-index: 5; background: rgba(250, 249, 245, .94); backdrop-filter: blur(8px); border-bottom: 1px solid var(--rule); }
.top .in { max-width: 1240px; margin: 0 auto; padding: 12px 24px; display: flex; align-items: center; gap: 20px; }
.top svg { width: 140px; height: auto; color: var(--ink); display: block; }
.top b { font: 500 15px/1 var(--display); color: var(--ink); padding-left: 18px; border-left: 1px solid var(--rule); }
.top nav { margin-left: auto; display: flex; gap: 22px; font-size: 15px; }
.top nav a { color: var(--ink); text-decoration: none; }
.top nav a:hover { color: #000; text-decoration: underline; }
.layout { max-width: 1240px; margin: 0 auto; padding: 0 24px; display: grid; grid-template-columns: 250px minmax(0, 1fr); gap: 56px; }
.toc { position: sticky; top: 72px; align-self: start; max-height: calc(100vh - 72px); overflow-y: auto; padding: 32px 0; }
.toc summary { display: none; }
.toc ol { list-style: none; margin: 0; padding: 0; counter-reset: ch; display: grid; gap: 2px; }
.toc li { counter-increment: ch; margin: 0; }
.toc a { display: grid; grid-template-columns: 28px 1fr; padding: 6px 10px; border-radius: 8px; color: var(--body); text-decoration: none; font-size: 14.5px; line-height: 1.35; }
.toc a::before { content: counter(ch, decimal-leading-zero); font: 500 12px/1.6 var(--mono); color: var(--muted); }
.toc a:hover { background: var(--paper); color: var(--ink); }
.toc a[aria-current] { background: var(--amber-wash); color: var(--ink); font-weight: 600; }
main { min-width: 0; padding: 40px 0 80px; max-width: 820px; }
.cover { padding-bottom: 40px; border-bottom: 1px solid var(--rule); }
.kicker { margin: 0; font: 500 13px/1.3 var(--text); letter-spacing: .1em; text-transform: uppercase; color: var(--amber-deep); }
h1, h2, h3 { font-family: var(--display); color: var(--ink); font-weight: 500; text-wrap: balance; }
h1 { font-size: clamp(36px, 4.4vw, 52px); line-height: 1.08; letter-spacing: -.015em; margin: 12px 0 16px; }
.lead { font-size: 19px; max-width: 60ch; margin: 0; }
.start { margin-top: 32px; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.start a { display: grid; gap: 4px; align-content: start; padding: 18px; background: var(--paper); border: 1px solid var(--rule); border-radius: 12px; text-decoration: none; transition: border-color .15s, box-shadow .15s; }
.start a:hover { border-color: var(--amber); box-shadow: 0 14px 28px -24px rgba(46, 60, 78, .5); }
.start b { font: 500 17px/1.3 var(--display); color: var(--ink); }
.start b::after { content: " \\2192"; color: var(--amber-deep); }
.start span { font-size: 14px; color: var(--muted); line-height: 1.45; }
.chapter { padding-top: 56px; }
.chapter > header { display: grid; grid-template-columns: auto 1fr; gap: 0 18px; align-items: center; padding-bottom: 18px; margin-bottom: 8px; border-bottom: 2px solid var(--ink); }
.chapter > header span { font: 500 15px/1 var(--mono); color: var(--amber-deep); background: var(--amber-wash); border-radius: 8px; padding: 9px 11px; }
h2 { font-size: clamp(26px, 3vw, 34px); line-height: 1.15; margin: 0; }
h3 { font-size: 21px; line-height: 1.25; margin: 40px 0 10px; }
p, li { max-width: 70ch; }
p { margin: 14px 0; }
ul, ol { padding-left: 22px; }
li { margin: 6px 0; }
li::marker { color: var(--amber-deep); }
strong { color: var(--ink); font-weight: 600; }
p.note { padding: 14px 18px; background: var(--paper); border: 1px solid var(--rule); border-left: 4px solid var(--amber); border-radius: 8px; }
code { font: .9em var(--mono); background: var(--amber-wash); color: var(--ink); padding: 1px 5px; border-radius: 4px; overflow-wrap: break-word; }
@media (min-width: 700px) { :not(pre) > code { white-space: nowrap; } }
.code { position: relative; margin: 16px 0; }
pre { margin: 16px 0; padding: 16px 84px 16px 18px; background: var(--code); color: var(--code-ink); border-radius: 10px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; font: 14px/1.6 var(--mono); }
.code pre { margin: 0; }
pre code { background: none; color: inherit; padding: 0; font: inherit; overflow-wrap: normal; }
.copy { position: absolute; top: 9px; right: 9px; font: 500 12px/1 var(--text); color: var(--code-ink); background: rgba(255, 255, 255, .08); border: 1px solid rgba(255, 255, 255, .2); border-radius: 6px; padding: 7px 10px; cursor: pointer; }
.copy:hover { border-color: var(--amber); }
.table { overflow-x: auto; margin: 20px 0; border: 1px solid var(--rule); border-radius: 10px; background: var(--paper); }
table { border-collapse: collapse; width: 100%; font-size: 15px; }
th { text-align: left; font: 500 12px/1.3 var(--text); letter-spacing: .08em; text-transform: uppercase; color: var(--muted); background: #f4f1e8; }
th, td { padding: 11px 16px; border-bottom: 1px solid var(--rule); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td:first-child { color: var(--ink); font-weight: 500; }
figure { margin: 24px 0; }
figure img { display: block; max-width: 100%; height: auto; border: 1px solid var(--rule); border-radius: 12px; box-shadow: 0 22px 44px -30px rgba(46, 60, 78, .5); background: var(--paper); }
figure.tall img { max-width: 360px; }
figcaption { margin-top: 10px; font-size: 14px; color: var(--muted); }
details.more { margin: 32px 0 0; border: 1px solid var(--rule); border-radius: 10px; background: var(--paper); }
details.more > summary { cursor: pointer; padding: 14px 18px; font: 500 18px/1.3 var(--display); color: var(--ink); list-style: none; display: flex; justify-content: space-between; gap: 12px; }
details.more > summary::-webkit-details-marker { display: none; }
details.more > summary::after { content: "+"; color: var(--amber-deep); font-size: 22px; line-height: 1; }
details.more[open] > summary::after { content: "\\2212"; }
details.more > .body { padding: 0 18px 8px; }
details.more .body > h3:first-child { display: none; }
.foot { margin-top: 72px; padding-top: 20px; border-top: 1px solid var(--rule); font-size: 13px; color: var(--muted); }
:focus-visible { outline: 2px solid #1a73e8; outline-offset: 2px; }
@media (max-width: 960px) {
  .layout { grid-template-columns: minmax(0, 1fr); gap: 0; }
  .toc { position: static; max-height: none; padding: 20px 0 0; }
  .toc summary { display: block; cursor: pointer; padding: 12px 16px; background: var(--paper); border: 1px solid var(--rule); border-radius: 10px; font: 500 16px/1.3 var(--display); color: var(--ink); }
  .toc[open] summary { margin-bottom: 8px; }
  .start { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .top nav { display: none; }
}
@media (max-width: 560px) { .start { grid-template-columns: minmax(0, 1fr); } .layout, .top .in { padding-inline: 16px; } main { padding-top: 24px; } .top b { display: none; } }
@media print {
  .top, .toc, .copy { display: none; } .layout { display: block; padding: 0; } main { max-width: none; padding: 0; }
  details.more > summary::after { content: ""; } .chapter { break-before: page; } pre, tr, figure { break-inside: avoid; } pre { white-space: pre-wrap; }
}
"""

SCRIPT = """
document.querySelectorAll("pre").forEach(pre => {
  const wrap = Object.assign(document.createElement("div"), { className: "code" });
  pre.replaceWith(wrap);
  const copy = Object.assign(document.createElement("button"), { type: "button", className: "copy", textContent: "Copy" });
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(pre.innerText.trim()); copy.textContent = "Copied"; }
    catch { getSelection().selectAllChildren(pre); copy.textContent = "Selected"; }
    setTimeout(() => (copy.textContent = "Copy"), 1600);
  });
  wrap.append(pre, copy);
});
const toc = document.querySelector(".toc");
if (matchMedia("(min-width: 961px)").matches) toc.open = true;
const links = new Map([...toc.querySelectorAll("a")].map(a => [a.hash.slice(1), a]));
const observer = new IntersectionObserver(entries => entries.forEach(e => {
  if (!e.isIntersecting) return;
  links.forEach(a => a.removeAttribute("aria-current"));
  links.get(e.target.id)?.setAttribute("aria-current", "true");
}), { rootMargin: "-20% 0px -70% 0px" });
document.querySelectorAll(".chapter").forEach(c => observer.observe(c));
const open = () => document.getElementById(location.hash.slice(1))?.closest("details.more")?.setAttribute("open", "");
addEventListener("hashchange", open);
addEventListener("beforeprint", () => document.querySelectorAll("details.more").forEach(d => (d.open = true)));
open();
"""


def slug(text):
    return re.sub(r'[^a-z0-9 -]', '', text.lower()).replace(' ', '-')


def image(src):
    path = (ROOT / 'docs' / src).resolve()
    kind = {'.webp': 'image/webp', '.png': 'image/png'}[path.suffix]
    return f'data:{kind};base64,{base64.b64encode(path.read_bytes()).decode()}'


def render():
    source = (ROOT / 'docs/PRODUCT-MANUAL.md').read_text(encoding='utf-8')
    md = MarkdownIt('commonmark', {'html': False}).enable('table')
    tokens = md.parse(source)
    for i, token in enumerate(tokens):
        if token.type == 'heading_open':
            token.attrSet('id', slug(tokens[i + 1].content))
        for child in token.children or ():
            if child.type == 'link_open':
                href = child.attrGet('href')
                if href and not href.startswith(('#', 'https://', 'http://', 'mailto:')):
                    child.attrSet('href', urljoin('https://github.com/QubitMan-hub/PQCsuite/blob/main/docs/', href))
            if child.type == 'image':
                child.attrSet('src', image(child.attrGet('src')))
    body = md.renderer.render(tokens, md.options, {})
    intro, _, rest = body.partition('<h2 id="contents">')
    rest = rest[rest.index('<h2 '):]
    intro = re.sub(r'<h1[^>]*>.*?</h1>\n|<p><strong>Acxelin Quantum[^<]*</strong></p>\n', '', intro)
    lead = re.sub(r'^<p>(.*)</p>$', r'\1', intro.strip(), flags=re.S)
    rest = rest.replace('<p><strong>', '<p class="note"><strong>')
    rest = rest.replace('<table>', '<div class="table" tabindex="0" role="region" aria-label="Table"><table>').replace('</table>', '</table></div>')
    rest = re.sub(r'<p><img src="([^"]+)" alt="([^"]*)"\s*/?></p>',
                  lambda m: f'<figure class="{"tall" if "VPN window" in m.group(2) else "wide"}"><img src="{m.group(1)}" alt="{m.group(2)}" loading="lazy">'
                            f'<figcaption>{m.group(2)}</figcaption></figure>', rest)
    chapters, toc = [], []
    for n, part in enumerate(re.split(r'(?=<h2 id=")', rest)[1:], 1):
        cid, title = re.match(r'<h2 id="([^"]+)">(.*?)</h2>', part).groups()
        sections = re.split(r'(?=<h3 id=")', part[part.index('</h2>') + 5:])
        out = sections[:1]
        for sec in sections[1:]:
            sid, stitle = re.match(r'<h3 id="([^"]+)">(.*?)</h3>', sec).groups()
            inner = sec.replace(f' id="{sid}"', '', 1)
            out.append(f'<details class="more" id="{sid}"><summary>{stitle}</summary><div class="body">{inner}</div></details>' if sid in FOLDED else sec)
        chapters.append(f'<section class="chapter" id="{cid}"><header><span>{n:02d}</span><h2>{title}</h2></header>{"".join(out)}</section>\n')
        toc.append(f'<li><a href="#{cid}">{title}</a></li>')
    font, logo = _assets()
    cards = ''.join(f'<a href="#{href}"><b>{html.escape(t)}</b><span>{html.escape(d)}</span></a>' for t, d, href in START)
    site = 'https://qubitman-hub.github.io/PQCsuite/'
    output = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Product manual · Acxelin PQC Suite</title>
<meta name="description" content="How to install and use Acxelin PQC Suite and Wolf Pack CBOM, step by step.">
<meta name="theme-color" content="#faf9f5">
<style>@font-face {{ font-family: "Host Grotesk"; font-weight: 400 600; font-display: swap; src: url("{font}") format("woff2"); }}{STYLE}</style>
</head>
<body>
<header class="top"><div class="in"><a href="{site}" aria-label="Acxelin PQC Suite website">{logo}</a><b>Product manual</b>
<nav aria-label="Website"><a href="{site}">Website</a><a href="{site}#app">Download</a><a href="{site}security.html">Security</a></nav></div></header>
<div class="layout">
<details class="toc"><summary>Contents</summary><nav aria-label="Contents"><ol>{"".join(toc)}</ol></nav></details>
<main id="main">
<section class="cover"><p class="kicker">Customer guide · PQC Suite {__version__}</p><h1>Product manual</h1><p class="lead">{lead}</p>
<div class="start" role="navigation" aria-label="Start here">{cards}</div></section>
{"".join(chapters)}<p class="foot">Acxelin Quantum · {dt.date.today():%d %B %Y} · made from <a href="https://github.com/QubitMan-hub/PQCsuite/blob/main/docs/PRODUCT-MANUAL.md">docs/PRODUCT-MANUAL.md</a>. To keep a copy, print this page and choose Save as PDF.</p>
</main>
</div>
<script>{SCRIPT}</script>
</body>
</html>
'''
    (ROOT / 'site/product-manual.html').write_text(output, encoding='utf-8')


if __name__ == '__main__':
    render()
