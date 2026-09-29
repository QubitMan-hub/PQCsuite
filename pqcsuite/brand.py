"""The Acxelin look for the reports the suite writes: the console's colours, typeface and logo, in one self-contained page."""
import datetime as dt
import functools
import html
import re
from pathlib import Path

CSS = """
:root { --bg: #faf9f5; --panel: #ffffff; --sunken: #f4f1e8; --ink: #2e3c4e; --ink-2: #3f4c59; --mute: #636e78; --line: #e6e0d2;
  --accent: #ffbf00; --accent-text: #8a6100; --accent-wash: #fff6dc; --ok: #26734d; --warn: #8a6100; --bad: #b3431f;
  --mono: ui-monospace, "Cascadia Mono", "SF Mono", Consolas, monospace; --sans: "Segoe UI", system-ui, -apple-system, Roboto, sans-serif;
  --display: "Host Grotesk", "Segoe UI", system-ui, sans-serif; color-scheme: light; }
@media (prefers-color-scheme: dark) { :root { --bg: #141a22; --panel: #1b232d; --sunken: #212b37; --ink: #eef0f2; --ink-2: #c9ced5; --mute: #8e98a4;
  --line: #2d3947; --accent-text: #ffcf4d; --accent-wash: #2a2616; --ok: #5ccf8e; --warn: #f2c14e; --bad: #f2877b; color-scheme: dark; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.55 var(--sans); -webkit-font-smoothing: antialiased; }
main { max-width: 1180px; margin: 0 auto; padding: 28px 24px 48px; }
@media (max-width: 560px) { main { padding: 20px 16px 36px; } }
.brandbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding-bottom: 18px; margin-bottom: 26px; border-bottom: 1px solid var(--line); }
.brandbar svg { width: 150px; height: auto; color: var(--ink); display: block; }
.brandbar small { color: var(--mute); font-size: 12px; letter-spacing: .02em; }
.kicker { margin: 0 0 6px; font-size: 12px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; color: var(--accent-text); }
h1 { font: 500 28px/1.2 var(--display); margin: 0 0 6px; letter-spacing: -0.015em; text-wrap: balance; }
h2 { font: 500 15px/1.4 var(--display); margin: 0; }
.sub { color: var(--mute); margin: 0 0 24px; max-width: 80ch; font-size: 15px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 18px; }
.tile { display: grid; gap: 4px; align-content: start; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px 18px 18px; }
.tile span { color: var(--mute); font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .1em; }
.tile b { font: 500 32px/1.15 var(--display); letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; margin-bottom: 18px; overflow: hidden; }
.panel > h2 { padding: 13px 18px; border-bottom: 1px solid var(--line); }
.panel > p, .panel > ul { padding: 12px 18px; margin: 0; }
.panel ul { list-style: none; display: grid; gap: 6px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 720px; }
th, td { text-align: left; padding: 10px 18px 10px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
th:first-child, td:first-child { padding-left: 18px; }
th { font-size: 11px; color: var(--mute); font-weight: 600; letter-spacing: .08em; text-transform: uppercase; background: var(--sunken); }
tr:last-child td { border-bottom: 0; }
small, .mute { color: var(--mute); }
.mono { font-family: var(--mono); font-size: 12.5px; white-space: nowrap; }
.pill { white-space: nowrap; display: inline-block; padding: 2px 9px; border-radius: 6px; font-size: 12px; font-weight: 600; background: color-mix(in srgb, currentColor 13%, transparent); }
.ok { color: var(--ok); } .warn { color: var(--warn); } .bad { color: var(--bad); } .pill.mute { color: var(--ink-2); }
footer { margin-top: 28px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--mute); font-size: 12px; }
@media print { body { background: #fff; } .panel, .tile { break-inside: avoid; } }
"""


@functools.cache
def _assets():
    """The logo and typeface, taken from the console so there is one copy of each."""
    page = (Path(__file__).parent / "console" / "console.html").read_text(encoding="utf-8")
    font = re.search(r'src: url\("(data:font/woff2;base64,[^"]+)"\)', page).group(1)
    logo = re.search(r'<template id="logo">(.*?)</template>', page, re.S).group(1)
    return font, logo


def page(title, kicker, sub, body, product="PQC Suite"):
    """A complete report page: brand bar, heading, the body given, and a footer saying when it was made."""
    from . import __version__
    font, logo = _assets()
    e = html.escape
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>@font-face {{ font-family: "Host Grotesk"; font-weight: 400 600; src: url("{font}") format("woff2"); }}{CSS}</style>
<main><div class=brandbar>{logo}<small>{e(product)}</small></div>
<p class=kicker>{e(kicker)}</p><h1>{e(title)}</h1><p class=sub>{sub}</p>
{body}
<footer>Generated {now} by pqcsuite {__version__} · Acxelin Quantum</footer></main></html>"""
