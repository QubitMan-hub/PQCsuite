"""Render the customer manual from its Markdown source using the shared Acxelin report style.

Build-only dependency: markdown-it-py==4.2.0. Run from an installed source checkout.
"""
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pqcsuite.brand import page  # noqa: E402


def render():
    source = (ROOT / 'docs/PRODUCT-MANUAL.md').read_text(encoding='utf-8')
    md = MarkdownIt('commonmark', {'html': False}).enable('table')
    tokens = md.parse(source)
    for i, token in enumerate(tokens):
        if token.type == 'heading_open':
            token.attrSet('id', re.sub(r'[^a-z0-9 -]', '', tokens[i + 1].content.lower()).replace(' ', '-'))
        if token.children:
            for child in token.children:
                if child.type == 'link_open':
                    href = child.attrGet('href')
                    if href and not href.startswith(('#', 'https://', 'http://')):
                        child.attrSet('href', urljoin('https://github.com/QubitMan-hub/PQCsuite/blob/main/docs/', href))
    body = md.renderer.render(tokens, md.options, {})
    body = re.sub(r'<h1[^>]*>.*?</h1>\n', '', body, count=1)
    body = body.replace('<table>', '<div class="manual-table" tabindex="0" role="region" aria-label="Reference table"><table>').replace('</table>', '</table></div>')
    style = '''<style>
main { max-width: 1040px; } h2 { font-size: 24px; margin: 40px 0 16px; } h3 { font-size: 18px; margin-top: 28px; }
p, li { max-width: 85ch; } a { color: var(--accent-text); text-decoration: underline; overflow-wrap: anywhere; }
pre { padding: 16px; background: var(--sunken); overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
code { overflow-wrap: anywhere; } .manual-table { overflow-x: auto; margin: 20px 0; } table { min-width: 550px; }
nav { display: flex; gap: 20px; flex-wrap: wrap; } :target { scroll-margin-top: 20px; }
@media print { :root { color-scheme: light; --bg: white; --ink: black; --ink-2: black; --mute: #444; --panel: white; --sunken: #eee; }
 main { max-width: none; padding: 0; } nav { display: none; } h2, h3 { break-after: avoid; } tr, pre { break-inside: avoid; }
 .manual-table { overflow: visible; } table { min-width: 0; } a { color: black; } }
</style>'''
    nav = '<nav aria-label="Manual navigation"><a href="https://qubitman-hub.github.io/PQCsuite/">PQC Suite website</a><a href="#contents">Contents</a><a href="https://github.com/QubitMan-hub/PQCsuite/blob/main/docs/PRODUCT-MANUAL.md">Markdown source</a></nav>'
    output = page('PQCSuite product manual', 'Customer guide',
                  'Five products, explained step by step. Read offline or use your browser’s Print → Save as PDF.', style + nav + body)
    output = output.replace('<html lang=en>', '<html lang="en">\n<head>\n', 1).replace('<main>', '</head><body>\n<main>', 1).replace('</main></html>', '</main></body></html>')
    (ROOT / 'site/product-manual.html').write_text(output, encoding='utf-8')


if __name__ == '__main__':
    render()
