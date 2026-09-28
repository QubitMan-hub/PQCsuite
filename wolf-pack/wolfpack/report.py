from collections import Counter
from html import escape as e

from . import __version__

MARK = {"critical": "■■■■", "high": "■■■□", "medium": "■■□□", "low": "■□□□", "ok": "□□□□"}

CSS = """
:root{--ink:#000;--paper:#fff;--mid:#6b6b6b;--rule:#d4d4d4}
@media (prefers-color-scheme:dark){:root{--ink:#f2f2f2;--paper:#0d0d0d;--mid:#9a9a9a;--rule:#333}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.55 ui-monospace,"Cascadia Mono","JetBrains Mono",Consolas,Menlo,monospace}
main{max-width:1120px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:28px;font-weight:700;letter-spacing:-.02em;margin:0 0 4px}
h2{font-size:15px;font-weight:700;margin:48px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
.sub{color:var(--mid);margin:0 0 32px}
.pack{display:grid;grid-template-columns:repeat(4,1fr);border:2px solid var(--ink)}
.pack div{padding:16px;border-right:1px solid var(--ink)}.pack div:last-child{border-right:0}
.pack b{display:block;font-size:30px;line-height:1.1;margin-top:4px}.pack span{color:var(--mid);font-size:12px}
.pack small{display:block;margin-top:8px;font-size:12px}
.ready{display:flex;gap:32px;flex-wrap:wrap;margin-top:20px}
.bar{height:10px;border:1px solid var(--ink);width:260px;margin-top:6px}.bar i{display:block;height:100%;background:var(--ink)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:760px}
th{text-align:left;font-weight:700;font-size:12px;border-bottom:1px solid var(--ink);padding:8px 10px 6px 0}
td{border-bottom:1px solid var(--rule);padding:9px 10px 9px 0;vertical-align:top}
tr.critical td:nth-child(3){font-weight:700}
.m{white-space:nowrap;letter-spacing:1px}.dim{color:var(--mid)}.w{max-width:380px}
.new{border:1px solid var(--ink);font-size:11px;padding:0 5px;margin-left:6px}
details{border-bottom:1px solid var(--rule);padding:8px 0}summary{cursor:pointer}
summary:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.occ{margin:8px 0 4px 18px;font-size:12px}.occ div{padding:2px 0;color:var(--mid)}.occ code{color:var(--ink)}
.alert{display:grid;grid-template-columns:90px 1fr;gap:12px;padding:8px 0;border-bottom:1px solid var(--rule)}
.tag{font-size:11px;border:1px solid var(--ink);padding:1px 6px;display:inline-block}
.tag.critical{background:var(--ink);color:var(--paper)}
.yes{font-weight:700}
footer{margin-top:56px;color:var(--mid);font-size:12px}
@media (max-width:720px){.pack{grid-template-columns:1fr 1fr}.pack div:nth-child(2){border-right:0}.pack div:nth-child(-n+2){border-bottom:1px solid var(--ink)}}
"""


def _ablation(st):
    off = st.get("roles_off")
    return f" Ablation run without: {', '.join(off)}." if off else ""


def _plural(n, word):
    return f"{n} {word}{'s' * (n != 1)}"


def endpoints_html(eps):
    if not eps:
        return ""
    rows = []
    for ep in eps:
        if ep.get("error"):
            rows.append(f"<tr><td>{e(ep['target'])}</td><td colspan=5 class=dim>unreachable: {e(ep['error'])}</td></tr>")
            continue
        pq = ", ".join(ep.get("pq_groups", []))
        others = [g for g in ep.get("groups", []) if g not in ep.get("pq_groups", [])]
        legacy = ", ".join(ep.get("legacy", []))
        extra = ep.get("cert") or ", ".join(ep.get("hostkeys", [])[:4])
        rows.append(f"<tr><td>{e(ep['target'])}</td><td>{e(ep.get('version') or '')}</td>"
                    f"<td>{'<span class=yes>yes, ' + e(pq) + '</span>' if pq else 'no'}</td><td>{e(ep.get('preferred_group') or 'unknown')}</td>"
                    f"<td class=w>{e(', '.join(others[:8]))}</td><td class=w>{e(extra)}{'<br>legacy accepted: ' + e(legacy) if legacy else ''}</td></tr>")
    return f"""<h2>Live endpoints</h2><div class="scroll"><table><thead><tr><th>Endpoint</th><th>Version</th><th>Hybrid PQ key exchange</th>
<th>Preferred group</th><th>Classical groups accepted</th><th>Certificate or host keys</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"""


def policy_html(c):
    if not c:
        return ""
    rows = []
    for v in c["violations"]:
        due = "<span class='tag critical'>overdue</span>" if v["overdue"] else f"<span class=tag>{v['deadline']}</span>"
        rows.append(f"<tr><td>{due}</td><td>{e(v['rule'])}</td><td><b>{e(v['asset']) or 'whole scan'}</b></td><td class=w>{e(v['message'])}</td>"
                    f"<td class='w dim'>{e(', '.join(v['files'][:3]))}</td></tr>")
    verdict = "passes" if c["passed"] else f"fails: {_plural(c['overdue'], 'rule')} already broken"
    return (f"<h2>Policy</h2><p>Checked against {e(', '.join(c['profiles']) or 'own rules')} as of {c['as_of']}: <span class=yes>{verdict}</span>, "
            f"{c['upcoming']} more due later.</p><div class=scroll><table><thead><tr><th>Due</th><th>Rule</th><th>Asset</th><th>Why</th><th>Where</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=5 class=dim>No rule broken.</td></tr>'}</tbody></table></div>")


def html(r):
    st, rd = r.stats, r.readiness
    rows = []
    for a in r.assets:
        locs = sorted({s.file for s in a.sightings})
        new = "<span class=new>new</span>" if a.new_files else ""
        rows.append(f"""<tr class="{a.tier}"><td class="m" title="{a.tier}">{MARK[a.tier]}</td><td>{e(a.tier)}</td><td><b>{e(a.variant)}</b>{new}</td>
<td class="w">{e(a.why)}</td><td class="w">{e(a.action) or '<span class="dim">none needed</span>'}</td><td>{e(a.exposure)}</td>
<td>{len(a.sightings)} in {_plural(len(locs), 'place')}</td><td>{a.confidence:.2f}</td></tr>""")
    detail = []
    for a in r.assets:
        occ = "".join(f"<div><code>{e(s.file)}{':' + str(s.line) if s.line else ''}</code> {e(s.evidence)}, {e(s.reason)}<br>{e(s.snippet)}</div>" for s in a.sightings[:60])
        detail.append(f"<details><summary><b>{e(a.variant)}</b> <span class='dim'>{e(a.nist)}</span></summary><div class='occ'>{occ}</div></details>")
    alerts = "".join(f"<div class='alert'><span><span class='tag {e(s)}'>{e(s)}</span></span><div>{e(t)}<br><span class='dim'>{e(w)}{'; ' + e(f) if f else ''}</span></div></div>"
                     for s, t, w, f in r.alerts) or "<p class='dim'>No hygiene alerts.</p>"
    libs = "".join(f"<tr><td>{e(l.name)}</td><td>{e(l.ecosystem)}</td><td>{e(l.version) or '<span class=dim>unpinned</span>'}</td>"
                   f"<td>{_plural(len(l.used_in), 'file')}</td><td>{'yes' if l.pq else ''}</td><td class='dim w'>{e(l.manifest)}{'<br>' + e(l.note) if l.note else ''}</td></tr>" for l in r.libraries)
    q = [s for s in r.sightings if s.verdict != "accepted"]
    why = Counter(s.reason for s in q)
    quar = "".join(f"<div><code>{e(s.file)}:{s.line}</code> {e(s.algo)}, {e(s.verdict)}: {e(s.reason)}<br>{e(s.snippet)}</div>" for s in q[:300])
    tiers, hz = rd["tiers"], st["horizon"]
    changed = [a for a in r.assets if a.new_files]
    base = ""
    if r.baseline:
        items = "".join(f"<div><b>{e(a.variant)}</b> <span class='dim'>{e(a.tier)}</span><br><span class='dim'>{e(', '.join(a.new_files[:8]))}</span></div>" for a in changed)
        base = f"<h2>New since baseline</h2><div class='occ' style='margin-left:0'>{items or '<p class=dim>Nothing new since the baseline.</p>'}</div>"
    scanned = st['files_code'] + st['files_config'] + st['files_artifacts'] + st['files_binary']
    pol = policy_html(r.compliance)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(r.project)}: Wolf Pack CBOM</title><style>{CSS}</style></head><body><main>
<h1>{e(r.project)}</h1>
<p class="sub">Cryptographic inventory and quantum migration plan. Wolf Pack {__version__}, scanned in {st['seconds']}s.{_ablation(st)}</p>
<div class="pack">
<div><span>Elders</span><b>{scanned + st['endpoints']}</b><small>{_plural(scanned, 'file')} and {_plural(st['endpoints'], 'endpoint')} checked against the rule base</small></div>
<div><span>Scouts</span><b>{st['raw_sightings']}</b><small>raw sightings, noisy by design</small></div>
<div><span>Den</span><b>{st['accepted']}</b><small>verified; {st['quarantined']} held, {st['rejected']} rejected, {st['suppressed']} suppressed</small></div>
<div><span>Alpha</span><b>{tiers['critical'] + tiers['high']}</b><small>assets to act on first; {st['promoted_on_second_look']} promoted on second look, {_plural(st['trails_followed'], 'key trail')} followed</small></div>
</div>
<div class="ready">
<div>Asymmetric assets that are quantum-safe: {rd['pq_safe']} of {rd['asymmetric']}<div class="bar"><i style="width:{rd['percent']}%"></i></div></div>
<div>Hybrid PQ key exchange seen: {'yes' if rd['hybrid'] else 'no'}</div>
<div class="dim">Assumptions: {hz['shelf_life']:g}y data shelf life, {hz['migration']:g}y migration, CRQC by {hz['crqc_year']} ({hz['years_to_crqc']}y)</div>
</div>
{endpoints_html(r.endpoints)}
{base}
{pol}
<h2>Migration queue</h2>
<div class="scroll"><table><thead><tr><th></th><th>Tier</th><th>Asset</th><th>Why</th><th>Do this</th><th>Exposure</th><th>Seen</th><th>Conf.</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=8 class=dim>No cryptography found.</td></tr>'}</tbody></table></div>
<h2>Hygiene alerts</h2>{alerts}
<h2>Where each asset lives</h2>{''.join(detail)}
<h2>Crypto libraries</h2>
<div class="scroll"><table><thead><tr><th>Library</th><th>Source</th><th>Version</th><th>Imported by</th><th>PQ-capable</th><th>Where declared</th></tr></thead>
<tbody>{libs or '<tr><td colspan=6 class=dim>No known crypto libraries declared.</td></tr>'}</tbody></table></div>
<h2>Held back by the den</h2>
<p class="dim">{'; '.join(f'{v} {k}' for k, v in why.most_common())}</p>
<details><summary>Show {len(q)} sightings that did not enter the CBOM</summary><div class="occ">{quar}</div></details>
{''.join(f'<p class="dim">{e(n)}</p>' for n in r.notes)}
<footer>CycloneDX 1.6 CBOM in cbom.json, SARIF 2.1.0 in wolfpack.sarif, full audit trail in findings.json</footer>
</main></body></html>"""


def terminal(r):
    st, rd = r.stats, r.readiness
    out = [f"\nwolfpack {__version__}  {r.project}{_ablation(st)}",
           f"scouts {st['raw_sightings']} raw  ->  den {st['accepted']} verified, {st['quarantined']} held, {st['rejected']} rejected, "
           f"{st['suppressed']} suppressed  ->  alpha {st['promoted_on_second_look']} promoted, {st['trails_followed']} trails  ->  {len(r.assets)} assets",
           f"quantum-safe asymmetric: {rd['pq_safe']}/{rd['asymmetric']} ({rd['percent']}%)   hybrid KEX: {'yes' if rd['hybrid'] else 'no'}"]
    for ep in r.endpoints:
        if ep.get("error"):
            out.append(f"  endpoint {ep['target']}: unreachable ({ep['error']})")
        else:
            out.append(f"  endpoint {ep['target']}: {ep.get('version')}, PQ groups: {', '.join(ep.get('pq_groups', [])) or 'none'}, preferred {ep.get('preferred_group')}")
    out.append("")
    w = max([len(a.variant) for a in r.assets] + [10])
    for a in r.assets:
        out.append(f"  {MARK[a.tier]}  {a.tier:<8} {a.variant:<{w}}{' new' if a.new_files else '    '}  {a.exposure:<28} {len(a.sightings):>3}x  {a.action[:60]}")
    if r.alerts:
        out.append("")
        for s, t, where, _ in r.alerts:
            out.append(f"  ! {s:<8} {t}  ({where})")
    if r.compliance:
        c = r.compliance
        out.append(f"\npolicy ({', '.join(c['profiles']) or 'own rules'}, as of {c['as_of']}): "
                   f"{'passes' if c['passed'] else 'FAILS'}, {c['overdue']} overdue, {c['upcoming']} due later")
        for v in c["violations"][:12]:
            out.append(f"  {'overdue ' if v['overdue'] else 'by ' + str(v['deadline']):<8} {v['rule']:<22} {v['asset'] or '(whole scan)'}: {v['message']}")
    for n in r.notes:
        out.append(f"  note: {n}")
    return "\n".join(out)
