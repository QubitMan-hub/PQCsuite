"""Compliance evidence: every certificate, endpoint, tunnel and backup mapped to NIST IR 8547 and NSA CNSA 2.0.

NIST IR 8547 (initial public draft, November 2024): quantum-vulnerable public-key algorithms at 112-bit security are deprecated
after 2030 and all of them are disallowed after 2035; ML-KEM and ML-DSA are the replacements.
CNSA 2.0 (NSA, 2022, updated 2024): ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384/512, used exclusively by the category's deadline.
"""
import datetime as dt
import html
import json
from pathlib import Path

from ..brand import page

CNSA2_DEADLINE = {"tls": 2033, "ssh": 2033, "vpn": 2030, "pki": 2033, "backup": 2033, "code": 2033}
CNSA2_CATEGORY = {"tls": "web browsers, servers and cloud services", "ssh": "operating systems and services",
                  "vpn": "traditional networking equipment (VPNs, routers)", "pki": "certificates and signing", "backup": "custom applications and data at rest",
                  "code": "custom applications and legacy software"}
CNSA2_ALGORITHMS = ("ML-KEM-1024", "ML-DSA-87", "AES-256", "SHA-384", "SHA-512", "LMS", "XMSS")
LIMIT = 64_000_000
STATUS = {"ready": "quantum-safe", "transition": "quantum-safe, classical fallback still allowed", "action": "action needed"}


def _row(kind, name, detail, status, nist, cnsa2, evidence):
    return {"kind": kind, "name": name, "detail": detail, "status": status, "nist_ir_8547": nist, "cnsa2": cnsa2,
            "cnsa2_deadline": CNSA2_DEADLINE[kind], "evidence": evidence}


def certificates(records):
    out = []
    now = dt.datetime.now(dt.timezone.utc)
    for r in records:
        if r.status != "valid":
            continue
        cnsa = r.algorithm == "ML-DSA-87"
        expired = dt.datetime.fromisoformat(r.not_after) < now
        out.append(_row("pki", r.common_name, f"{r.kind} certificate, {r.algorithm}, {'expired' if expired else 'expires'} {r.not_after[:10]}",
                        "action" if expired else "ready", "expired: renew it" if expired else "approved (FIPS 204)",
                        "compliant" if cnsa and not expired else "needs ML-DSA-87" if not cnsa else "expired", {"serial": r.serial}))
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
        if r.get("legacy"):
            status, nist = "action", nist + f"; {' and '.join(r['legacy'])} accepted: disallowed now (NIST SP 800-52r2)"
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
        ciphers = [t["encryption"]] + [c["encryption"] for c in t.get("children", [])]
        cnsa = "ML_KEM_1024" in kex and "ECP_384" in kex and all(c == "AES_GCM_16_256" for c in ciphers)
        out.append(_row("vpn", t["peer"], f"{t['state']}, {kex}, {t['encryption']}, PPK {'yes' if t['ppk'] else 'no'}",
                        "ready" if pq and t["ppk"] else "transition" if pq else "action",
                        "post-quantum key exchange" + ("" if t["ppk"] else "; authentication still classical") if pq else "classical key exchange: disallowed after 2035",
                        "compliant" if cnsa else "needs profile = \"high\" (P-384 + ML-KEM-1024, AES-256-GCM)", {"key_exchange": kex}))
    return out


def backups(items):
    out = []
    for b in items:
        if "error" in b:
            continue
        cnsa = "ML-KEM-1024" in b["suite"]
        out.append(_row("backup", b["name"], f"unverified header: {b['kind']} created {b['created'][:10]}, {b['suite']}, claimed signer {b['signed_by'] or 'none'}", "ready",
                        "post-quantum key encapsulation (FIPS 203)", "compliant" if cnsa else "needs recipients made with `vault keygen --cnsa2`",
                        {"file": b.get("file"), "authenticated": False}))
    return out


def code(path):
    """Rows from a Wolf Pack scan: its output folder (cbom.json, plus findings.json for security patterns) or a cbom.json file.
    Read as data; Wolf Pack itself is not imported. Each row cites where the asset was seen and, when known, which functions reach it."""
    path = Path(path)
    folder = path if path.is_dir() else path.parent
    bom, findings = _load(path / "cbom.json" if path.is_dir() else path), folder / "findings.json"
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components"), list):
        raise ValueError(f"{path} is not a CycloneDX CBOM; give a Wolf Pack output folder or its cbom.json")
    project = str(((bom.get("metadata") or {}).get("component") or {}).get("name") or folder.name)
    out = []
    for c in bom["components"]:
        if not isinstance(c, dict) or c.get("type") != "cryptographic-asset":
            continue
        props = {p.get("name"): str(p.get("value", "")) for p in c.get("properties") or [] if isinstance(p, dict)}
        tier, name = props.get("wolfpack:tier", "medium"), str(c.get("name", "?"))
        seen = [f"{o.get('location')}:{o.get('line')}" if o.get("line") else str(o.get("location")) for o in (c.get("evidence") or {}).get("occurrences") or []
                if isinstance(o, dict)]
        try:
            callers = json.loads(props.get("wolfpack:code-impact") or "{}").get("callers") or []
        except (ValueError, AttributeError):
            callers = []
        where = ", ".join(seen[:3]) + (f" and {len(seen) - 3} more" if len(seen) > 3 else "")
        detail = f"{project}: {props.get('wolfpack:usage', 'used')} in {where or 'unknown location'}; {props.get('wolfpack:exposure', 'code')}"
        detail += f"; reached from {', '.join(map(str, callers[:3]))}" if callers else ""
        detail += f"; next: {props['wolfpack:recommendation']}" if props.get("wolfpack:recommendation") else ""
        cnsa = any(name.startswith(a) for a in CNSA2_ALGORITHMS)
        out.append(_row("code", name, detail, "action" if tier in ("critical", "high") else "transition" if tier == "medium" else "ready",
                        props.get("wolfpack:nist-status") or "not classified", "compliant" if cnsa else "not a CNSA 2.0 algorithm",
                        {"project": project, "tier": tier, "locations": seen[:20], "callers": callers[:20]}))
    report = _load(findings) if findings.is_file() else {}
    for p in report.get("patterns", []) if isinstance(report, dict) else []:
        if isinstance(p, dict) and p.get("severity") in ("critical", "high"):
            out.append(_row("code", f"{p.get('rule')} {p.get('title')}", f"{project}: {p.get('file')}:{p.get('line')} ({p.get('cwe')}); fix: {p.get('fix')}",
                            "action", "undermines the protection of whatever algorithm is chosen", "not compliant",
                            {"project": project, "pattern": p.get("rule"), "locations": [f"{p.get('file')}:{p.get('line')}"]}))
    return out


def _load(path):
    with open(path, "rb") as f:
        raw = f.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError(f"{path} is larger than {LIMIT // 1_000_000} MB")
    try:
        return json.loads(raw)
    except ValueError:
        raise ValueError(f"{path} is not valid JSON") from None


def report(rows):
    counts = {s: sum(r["status"] == s for r in rows) for s in STATUS}
    return {"generated": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(), "assets": len(rows), "status": counts,
            "cnsa2_compliant": sum(r["cnsa2"] == "compliant" for r in rows), "items": rows}


def to_html(rep, title="Post-quantum compliance evidence"):
    e = html.escape
    cls = {"ready": "ok", "transition": "warn", "action": "bad"}
    rows = "".join(
        f"<tr><td>{e(r['kind'])}</td><td>{e(r['name'])}</td><td><span class='pill {cls[r['status']]}'>{e(STATUS[r['status']])}</span></td><td>{e(r['nist_ir_8547'])}</td>"
        f"<td class={'ok' if r['cnsa2'] == 'compliant' else 'warn'}>{e(r['cnsa2'])}<br><small>by {r['cnsa2_deadline']} ({e(CNSA2_CATEGORY[r['kind']])})</small></td>"
        f"<td><small>{e(r['detail'])}</small></td></tr>" for r in sorted(rep["items"], key=lambda r: (list(STATUS).index(r["status"]) * -1, r["kind"], r["name"])))
    s = rep["status"]
    tiles = "".join(f"<div class=tile><span>{label}</span><b class={tone}>{value}</b></div>" for label, value, tone in (
        ("assets", rep["assets"], ""), ("quantum-safe", s["ready"], "ok"), ("with classical fallback", s["transition"], "warn"),
        ("need action", s["action"], "bad"), ("meet CNSA 2.0", rep["cnsa2_compliant"], "")))
    sub = ("NIST IR 8547 (draft): quantum-vulnerable public-key algorithms deprecated after 2030 (112-bit) and disallowed after 2035. "
           "NSA CNSA 2.0: ML-KEM-1024, ML-DSA-87, AES-256, used exclusively by each category's deadline. "
           "Backup classifications describe unverified headers; authenticate archives with vault verify and a recipient key before relying on their integrity or signer.")
    body = (f"<div class=tiles>{tiles}</div><section class=panel><h2>Every asset</h2><div class=scroll><table><thead><tr><th>Type</th><th>Asset</th>"
            f"<th>Status</th><th>NIST IR 8547</th><th>CNSA 2.0</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></div></section>")
    return page(title, "Compliance evidence", sub, body)


def to_json(rep):
    return json.dumps(rep, indent=1, default=str)
