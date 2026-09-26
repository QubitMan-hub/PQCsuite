"""Compliance evidence: every certificate, endpoint, tunnel and backup mapped to NIST IR 8547 and NSA CNSA 2.0.

NIST IR 8547 (initial public draft, November 2024): quantum-vulnerable public-key algorithms at 112-bit security are deprecated
after 2030 and all of them are disallowed after 2035; ML-KEM and ML-DSA are the replacements.
CNSA 2.0 (NSA, 2022, updated 2024): ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384/512, used exclusively by the category's deadline.
"""
import datetime as dt
import html
import json

CNSA2_DEADLINE = {"tls": 2033, "ssh": 2033, "vpn": 2030, "pki": 2033, "backup": 2033}
CNSA2_CATEGORY = {"tls": "web browsers, servers and cloud services", "ssh": "operating systems and services",
                  "vpn": "traditional networking equipment (VPNs, routers)", "pki": "certificates and signing", "backup": "custom applications and data at rest"}
STATUS = {"ready": "quantum-safe", "transition": "quantum-safe, classical fallback still allowed", "action": "action needed"}


def _row(kind, name, detail, status, nist, cnsa2, evidence):
    return {"kind": kind, "name": name, "detail": detail, "status": status, "nist_ir_8547": nist, "cnsa2": cnsa2,
            "cnsa2_deadline": CNSA2_DEADLINE[kind], "evidence": evidence}


def certificates(records):
    out = []
    for r in records:
        if r.status != "valid":
            continue
        cnsa = r.algorithm == "ML-DSA-87"
        out.append(_row("pki", r.common_name, f"{r.kind} certificate, {r.algorithm}, expires {r.not_after[:10]}", "ready",
                        "approved (FIPS 204)", "compliant" if cnsa else "needs ML-DSA-87", {"serial": r.serial}))
    return out


def endpoints(results):
    out = []
    for r in results:
        kind = r.get("protocol", "tls")
        if r["grade"] == "F":
            out.append(_row(kind, r["target"], f"unreachable: {r.get('error')}", "action", "unknown", "unknown", {"grade": "F"}))
            continue
        key = (r.get("certificate") or {}).get("key", "")
        classical_key = kind == "tls" and not key.startswith("ML-DSA")
        status = {"A": "ready", "B": "transition", "C": "action"}[r["grade"]]
        if status == "ready" and classical_key:
            status = "transition"
        nist = ("classical key exchange: disallowed after 2035" if r["grade"] == "C" else
                "classical fallback accepted: remove before 2035" if r["grade"] == "B" else "post-quantum key exchange")
        if classical_key and key:
            nist += f"; {key} certificate: deprecated after 2030 (112-bit), disallowed after 2035"
        out.append(_row(kind, r["target"], f"negotiates {r.get('negotiated')}; accepts {', '.join(r['accepts'])}" + (f"; key {key}" if key else ""),
                        status, nist, "compliant" if r.get("cnsa2") else "not compliant", {"grade": r["grade"]}))
    return out


def tunnels(items):
    out = []
    for t in items:
        if "error" in t:
            continue
        kex = t["key_exchange"]
        pq = "ML_KEM" in kex
        cnsa = "ML_KEM_1024" in kex and "ECP_384" in kex and "AES_GCM_16" in t["encryption"]
        out.append(_row("vpn", t["peer"], f"{t['state']}, {kex}, {t['encryption']}, PPK {'yes' if t['ppk'] else 'no'}",
                        "ready" if pq and t["ppk"] else "transition" if pq else "action",
                        "post-quantum key exchange" + ("" if t["ppk"] else "; authentication still classical") if pq else "classical key exchange: disallowed after 2035",
                        "compliant" if cnsa else "needs profile = \"high\" (P-384 + ML-KEM-1024)", {"key_exchange": kex}))
    return out


def backups(items):
    out = []
    for b in items:
        if "error" in b:
            continue
        cnsa = "ML-KEM-1024" in b["suite"]
        out.append(_row("backup", b["name"], f"{b['kind']} created {b['created'][:10]}, {b['suite']}, signed by {b['signed_by'] or 'nobody'}", "ready",
                        "post-quantum key encapsulation (FIPS 203)", "compliant" if cnsa else "needs recipients made with `vault keygen --cnsa2`", {"file": b.get("file")}))
    return out


def report(rows):
    counts = {s: sum(r["status"] == s for r in rows) for s in STATUS}
    return {"generated": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(), "assets": len(rows), "status": counts,
            "cnsa2_compliant": sum(r["cnsa2"] == "compliant" for r in rows), "items": rows}


def to_html(rep, title="Post-quantum compliance evidence"):
    e = html.escape
    cls = {"ready": "ok", "transition": "warn", "action": "bad"}
    rows = "".join(
        f"<tr><td>{e(r['kind'])}</td><td>{e(r['name'])}</td><td class={cls[r['status']]}>{e(STATUS[r['status']])}</td><td>{e(r['nist_ir_8547'])}</td>"
        f"<td class={'ok' if r['cnsa2'] == 'compliant' else 'warn'}>{e(r['cnsa2'])}<br><small>by {r['cnsa2_deadline']} ({e(CNSA2_CATEGORY[r['kind']])})</small></td>"
        f"<td><small>{e(r['detail'])}</small></td></tr>" for r in sorted(rep["items"], key=lambda r: (list(STATUS).index(r["status"]) * -1, r["kind"], r["name"])))
    s = rep["status"]
    return f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>{e(title)}</title>
<style>:root{{--ink:#15171a;--mute:#6b7076;--line:#e3e5e8;--bg:#fff;--ok:#0b6b3a;--warn:#7a5a00;--bad:#9a2412}}
@media(prefers-color-scheme:dark){{:root{{--ink:#eceef0;--mute:#9aa0a6;--line:#2a2d31;--bg:#111315;--ok:#4ade80;--warn:#facc15;--bad:#fb923c}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1180px;margin:0 auto;padding:32px 16px}}
h1{{font-size:24px;margin:0 0 4px}}p{{color:var(--mute);margin:0 0 20px;max-width:80ch}}.stats{{display:flex;flex-wrap:wrap;gap:32px;margin-bottom:24px}}
.stats b{{display:block;font-size:28px}}.stats span{{color:var(--mute)}}.scroll{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;min-width:900px}}
th,td{{text-align:left;padding:8px 10px 8px 0;border-bottom:1px solid var(--line);vertical-align:top}}th{{font-size:12px;color:var(--mute);font-weight:500}}
small{{color:var(--mute)}}.ok{{color:var(--ok)}}.warn{{color:var(--warn)}}.bad{{color:var(--bad);font-weight:600}}</style>
<main><h1>{e(title)}</h1><p>Generated {rep['generated']} by pqcsuite. NIST IR 8547 (draft): quantum-vulnerable public-key algorithms deprecated after 2030
(112-bit) and disallowed after 2035. NSA CNSA 2.0: ML-KEM-1024, ML-DSA-87, AES-256, used exclusively by each category's deadline.</p>
<div class=stats><div><b>{rep['assets']}</b><span>assets</span></div><div><b class=ok>{s['ready']}</b><span>quantum-safe</span></div>
<div><b class=warn>{s['transition']}</b><span>with classical fallback</span></div><div><b class=bad>{s['action']}</b><span>need action</span></div>
<div><b>{rep['cnsa2_compliant']}</b><span>meet CNSA 2.0</span></div></div>
<div class=scroll><table><thead><tr><th>Type</th><th>Asset</th><th>Status</th><th>NIST IR 8547</th><th>CNSA 2.0</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></div></main></html>"""


def to_json(rep):
    return json.dumps(rep, indent=1, default=str)
