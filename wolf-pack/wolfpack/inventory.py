"""The organisation's view: CBOMs from many repositories, images and endpoints (or from other tools) merged into one inventory."""
import json
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from html import escape as e
from pathlib import Path

from . import __version__
from .alpha import TIERS
from .elders import CATALOG, HYBRIDS, GROVER, LEGACY, SAFE, SHOR, lookup, pq_from_text
from .report import CSS, MARK

ESTIMATE = {LEGACY: "critical", SHOR: "high", GROVER: "low", SAFE: "ok"}
ASYMMETRIC = {"pke", "signature", "key-agree", "kem", "other"}
RANK = {t: i for i, t in enumerate(TIERS)}


def algo_of(name):
    """Catalogue entry for a component name such as RSA-2048, AES-128-GCM or ECDSA-SHA-256, trying shorter prefixes."""
    parts = name.split("-")
    for n in range(len(parts), 0, -1):
        a = lookup("-".join(parts[:n])) or pq_from_text("-".join(parts[:n]))
        if a:
            return a
    return None


def estimate(algo, name):
    """A tier from the algorithm alone, for CBOMs without Wolf Pack's: legacy or under 112-bit strength is critical."""
    if not algo:
        return None
    bits = re.search(r"(?<!\d)(\d{3,4})(?!\d)", name)
    if algo in ("RSA", "DSA", "DH") and bits and int(bits.group(1)) < 2048:
        return "critical"
    return ESTIMATE.get(CATALOG[algo].threat)


def prop(component, key):
    return next((p.get("value") for p in component.get("properties", []) if p.get("name") == key), None)


def cbom_files(paths):
    out = []
    for p in map(Path, paths):
        out += sorted(p.rglob("cbom.json")) if p.is_dir() else [p]
    return out


def load(path, taken):
    """One system from one CBOM. Tiers come from Wolf Pack's own properties; other tools' CBOMs get a tier estimated from the catalogue."""
    bom = json.loads(Path(path).read_text(encoding="utf-8"))
    meta = bom.get("metadata") or {}
    name = (meta.get("component") or {}).get("name") or Path(path).parent.name or Path(path).stem
    base, n = name, 2
    while name in taken:
        name, n = f"{base} ({n})", n + 1
    taken.add(name)
    tool = next((f"{t.get('name')} {t.get('version', '')}".strip() for t in (meta.get("tools") or {}).get("components", [])), "unknown")
    assets = []
    for c in bom.get("components", []):
        cp = c.get("cryptoProperties") or {}
        if c.get("type") != "cryptographic-asset" or cp.get("assetType") != "algorithm":
            continue
        algo = algo_of(c.get("name", ""))
        tier = prop(c, "wolfpack:tier")
        estimated = tier not in RANK
        if estimated:
            tier = estimate(algo, c.get("name", ""))
        assets.append({"name": c.get("name", "?"), "algo": algo, "tier": tier, "estimated": estimated, "component": c,
                       "policy": [p for p in (prop(c, "wolfpack:policy") or "").split("; ") if p],
                       "recommendation": prop(c, "wolfpack:recommendation") or (CATALOG[algo].replace if algo else ""),
                       "occurrences": (c.get("evidence") or {}).get("occurrences", [])})
    assets.sort(key=lambda a: (RANK.get(a["tier"], len(TIERS)), a["name"]))
    return {"name": name, "source": str(path), "tool": tool, "assets": assets, "readiness": readiness(assets)}


def readiness(assets):
    asym = {a["algo"] for a in assets if a["algo"] and CATALOG[a["algo"]].primitive in ASYMMETRIC}
    safe = {a for a in asym if CATALOG[a].threat == SAFE}
    tiers = {t: sum(1 for a in assets if a["tier"] == t) for t in TIERS}
    worst = next((t for t in TIERS if tiers[t]), None)
    return {"asymmetric": len(asym), "pq_safe": len(safe), "percent": round(100 * len(safe) / len(asym)) if asym else 0,
            "hybrid": any(a["algo"] in HYBRIDS for a in assets), "tiers": tiers, "worst": worst,
            "policy_breaches": sum(1 for a in assets if a["policy"]),
            "estimated": any(a["estimated"] for a in assets)}


def weakest_first(systems):
    return sorted(systems, key=lambda s: (RANK.get(s["readiness"]["worst"], len(TIERS)), *[-s["readiness"]["tiers"][t] for t in TIERS],
                                          s["readiness"]["percent"], s["name"]))


def usage(systems):
    """{algorithm family: [(system, tier, variant), ...]}, for "where is each algorithm used"."""
    out = defaultdict(list)
    for s in systems:
        for a in s["assets"]:
            out[CATALOG[a["algo"]].family if a["algo"] else a["name"]].append((s["name"], a["tier"], a["name"]))
    return out


def slug(s):
    return re.sub(r"[^A-Za-z0-9.-]+", "-", s).strip("-") or "system"


def build(org, systems):
    """A CycloneDX 1.6 CBOM for the organisation: each system is an application that depends on the algorithms it uses."""
    comps, deps, seen, refs = [], [], {}, {}
    for s in systems:
        ref = f"system/{slug(s['name'])}"
        while ref in refs.values():
            ref += "-x"
        refs[s["name"]] = ref
        r = s["readiness"]
        comps.append({"type": "application", "bom-ref": ref, "name": s["name"],
                      "properties": [{"name": "wolfpack:source", "value": s["source"]}, {"name": "wolfpack:tool", "value": s["tool"]},
                                     {"name": "wolfpack:pq-ready-percent", "value": str(r["percent"])},
                                     {"name": "wolfpack:worst-tier", "value": r["worst"] or "none"}]})
    for s in systems:
        uses = []
        for a in s["assets"]:
            cref = f"crypto/{slug(a['name'])}"
            if cref not in seen:
                c = {k: v for k, v in a["component"].items() if k in ("type", "name", "cryptoProperties")}
                seen[cref] = dict(c, **{"bom-ref": cref, "evidence": {"occurrences": []}, "properties": []})
                comps.append(seen[cref])
            c = seen[cref]
            c["evidence"]["occurrences"] += [dict(o, location=f"{s['name']}: {o.get('location', '')}") for o in a["occurrences"]]
            worst = prop(c, "wolfpack:tier")
            if a["tier"] and (worst is None or RANK[a["tier"]] < RANK[worst]):
                c["properties"] = [p for p in c["properties"] if p["name"] != "wolfpack:tier"] + [{"name": "wolfpack:tier", "value": a["tier"]}]
            uses.append(cref)
        deps.append({"ref": refs[s["name"]], "dependsOn": sorted(set(uses))})
    for c in seen.values():
        n = sum(1 for d in deps if c["bom-ref"] in d["dependsOn"])
        c["properties"].append({"name": "wolfpack:systems", "value": str(n)})
        if not c["evidence"]["occurrences"]:
            del c["evidence"]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "tools": {"components": [{"type": "application", "name": "wolfpack", "version": __version__}]},
                         "component": {"type": "application", "name": org, "bom-ref": "organisation"}},
            "components": comps, "dependencies": [{"ref": "organisation", "dependsOn": [refs[s["name"]] for s in systems]}] + deps}


def summary(org, systems):
    asym = {a["algo"] for s in systems for a in s["assets"] if a["algo"] and CATALOG[a["algo"]].primitive in ASYMMETRIC}
    safe = {a for a in asym if CATALOG[a].threat == SAFE}
    return {"organisation": org, "wolfpack": __version__, "systems": len(systems),
            "algorithms": len({a["name"] for s in systems for a in s["assets"]}),
            "pq_ready_percent": round(100 * len(safe) / len(asym)) if asym else 0,
            "systems_at": {t: sum(1 for s in systems if s["readiness"]["worst"] == t) for t in TIERS},
            "by_system": [{"name": s["name"], "source": s["source"], "tool": s["tool"], **s["readiness"]} for s in weakest_first(systems)]}


def html(org, systems, history=()):
    systems = weakest_first(systems)
    sm = summary(org, systems)
    at = sm["systems_at"]
    rows = []
    for s in systems:
        r = s["readiness"]
        top = s["assets"][0] if s["assets"] else None
        rows.append(f"<tr class={r['worst'] or 'ok'}><td class=m>{MARK.get(r['worst'], '')}</td><td>{e(s['name'])}"
                    f"{'<span class=new>estimated</span>' if r['estimated'] else ''}</td>"
                    f"<td>{r['tiers']['critical']}</td><td>{r['tiers']['high']}</td><td>{r['percent']}%</td><td>{'yes' if r['hybrid'] else 'no'}</td>"
                    f"<td>{r['policy_breaches'] or '<span class=dim>0</span>'}</td>"
                    f"<td class=w>{e(top['name']) + ' → ' + e(top['recommendation']) if top and top['tier'] in ('critical', 'high') else '<span class=dim>none</span>'}</td></tr>")
    use = []
    for fam, where in sorted(usage(systems).items(), key=lambda kv: (min(RANK.get(t, 9) for _, t, _ in kv[1]), -len({n for n, *_ in kv[1]}), kv[0])):
        worst = min((t for _, t, _ in where if t), key=lambda t: RANK[t], default=None)
        names = sorted({n for n, *_ in where})
        use.append(f"<tr><td class=m>{MARK.get(worst, '')}</td><td>{e(fam)}</td><td>{len(names)}</td><td class=w>{e(', '.join(names))}</td>"
                   f"<td class='w dim'>{e(', '.join(sorted({v for *_, v in where})))}</td></tr>")
    first = sorted(((a, s) for s in systems for a in s["assets"] if a["tier"] in ("critical", "high")),
                   key=lambda x: (RANK[x[0]["tier"]], x[1]["name"], x[0]["name"]))[:25]
    todo = "".join(f"<tr><td class=m>{MARK[a['tier']]}</td><td>{e(s['name'])}</td><td>{e(a['name'])}</td><td class=w>{e(a['recommendation'])}</td>"
                   f"<td class=dim>{len(a['occurrences'])}</td></tr>" for a, s in first)
    est = [s["name"] for s in systems if s["readiness"]["estimated"]]
    return f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{e(org)}: cryptographic inventory</title><style>{CSS}</style><main>
<h1>{e(org)}</h1><p class=sub>Organisation cryptographic inventory from {sm['systems']} CBOM(s). Wolf Pack {__version__}.</p>
<div class=pack><div><span>systems</span><b>{sm['systems']}</b><small>{at['critical']} with a critical finding</small></div>
<div><span>distinct algorithms</span><b>{sm['algorithms']}</b><small>across all systems</small></div>
<div><span>quantum-safe asymmetric</span><b>{sm['pq_ready_percent']}%</b><small>of asymmetric algorithms in use</small></div>
<div><span>systems at high or worse</span><b>{at['critical'] + at['high']}</b><small>{at['high']} high, {at['critical']} critical</small></div></div>
{trend_html(list(history))}
<h2>Systems, weakest first</h2><div class=scroll tabindex=0><table><tr><th></th><th>system</th><th>critical</th><th>high</th><th>quantum-safe</th><th>hybrid</th><th>policy</th><th>worst finding → replacement</th></tr>
{''.join(rows)}</table></div>
<h2>Migrate first</h2><div class=scroll tabindex=0><table><tr><th></th><th>system</th><th>algorithm</th><th>replacement</th><th>places</th></tr>{todo or '<tr><td colspan=5 class=dim>nothing at high or critical</td></tr>'}</table></div>
<h2>Where each algorithm is used</h2><div class=scroll tabindex=0><table><tr><th></th><th>algorithm</th><th>systems</th><th>which</th><th>variants</th></tr>{''.join(use)}</table></div>
<footer>{'Tiers for ' + e(', '.join(est)) + ' are estimated from the algorithm alone: those CBOMs came from another tool or carry no Wolf Pack tiers. ' if est else ''}Each system's own report has the evidence behind every finding.</footer>
</main></html>"""


def terminal(org, systems):
    sm = summary(org, systems)
    lines = [f"{org}: {sm['systems']} systems, {sm['algorithms']} distinct algorithms, {sm['pq_ready_percent']}% of asymmetric algorithms quantum-safe", ""]
    for s in weakest_first(systems):
        r = s["readiness"]
        lines.append(f"  {MARK.get(r['worst'], '    ')}  {r['worst'] or '-':<8} {s['name']:<32} {r['tiers']['critical']} critical, {r['tiers']['high']} high, "
                     f"{r['percent']}% quantum-safe{' (estimated)' if r['estimated'] else ''}")
    return "\n".join(lines)


def record(history, org, systems):
    """Appends this run to a JSON-lines history and returns every run so far, oldest first."""
    sm = summary(org, systems)
    row = {"date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "systems": sm["systems"], "pq_ready_percent": sm["pq_ready_percent"],
           "critical": sm["systems_at"]["critical"], "high": sm["systems_at"]["high"],
           "breaches": sum(s["readiness"]["policy_breaches"] for s in systems)}
    history = Path(history)
    rows = [json.loads(line) for line in history.read_text(encoding="utf-8").splitlines() if line.strip()] if history.exists() else []
    if rows and rows[-1]["date"] == row["date"]:
        rows[-1] = row
    else:
        rows.append(row)
    history.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return rows


def trend_html(rows):
    """Quantum-safe share over time as an inline SVG line, with the numbers in a table beside it."""
    if len(rows) < 2:
        return ""
    w, h, pad = 560, 160, 30
    xs = [pad + i * (w - 2 * pad) / (len(rows) - 1) for i in range(len(rows))]
    ys = [h - pad - r["pq_ready_percent"] * (h - 2 * pad) / 100 for r in rows]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    dots = "".join(f"<circle cx={x:.1f} cy={y:.1f} r=3 fill=currentColor />" for x, y in zip(xs, ys))
    axis = (f"<text x={pad} y={h - 8} font-size=11 fill=currentColor>{e(rows[0]['date'])}</text>"
            f"<text x={w - pad} y={h - 8} font-size=11 fill=currentColor text-anchor=end>{e(rows[-1]['date'])}</text>"
            f"<text x=4 y={pad + 4} font-size=11 fill=currentColor>100%</text><text x=4 y={h - pad + 4} font-size=11 fill=currentColor>0%</text>")
    svg = (f"<svg viewBox='0 0 {w} {h}' role=img aria-label='Share of quantum-safe asymmetric algorithms over time' style='max-width:100%;height:auto'>"
           f"<line x1={pad} y1={h - pad} x2={w - pad} y2={h - pad} stroke=currentColor stroke-width=1 /><polyline points='{line}' fill=none stroke=currentColor stroke-width=2 />{dots}{axis}</svg>")
    table = "".join(f"<tr><td>{e(r['date'])}</td><td>{r['pq_ready_percent']}%</td><td>{r['critical']}</td><td>{r['high']}</td><td>{r['breaches']}</td></tr>" for r in rows[-12:])
    return (f"<h2>Readiness over time</h2>{svg}<div class=scroll tabindex=0><table><tr><th>date</th><th>quantum-safe</th><th>systems critical</th>"
            f"<th>systems high</th><th>policy breaches</th></tr>{table}</table></div>")


def run(paths, org, out, history=None):
    taken = set()
    systems = [load(p, taken) for p in cbom_files(paths)]
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rows = record(history, org, systems) if history else []
    (out / "cbom.json").write_text(json.dumps(build(org, systems), indent=1), encoding="utf-8")
    (out / "inventory.json").write_text(json.dumps(summary(org, systems) | ({"history": rows} if rows else {}), indent=1), encoding="utf-8")
    (out / "inventory.html").write_text(html(org, systems, rows), encoding="utf-8")
    return systems
