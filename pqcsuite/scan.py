"""Post-quantum readiness of TLS endpoints: which key exchanges each accepts, what it negotiates, and its certificate."""
import datetime as dt
import html
import json
import socket
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from . import tls
from .ca import algorithm_of
from .edge import hostport
from .tls.openssl import Context

PQ = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024"]
CNSA2_GROUPS = {"SecP384r1MLKEM1024", "MLKEM1024"}
CLASSICAL = ["X25519", "secp256r1", "secp384r1"]
GRADES = {
    "A": "post-quantum key exchange only",
    "B": "post-quantum key exchange, classical still accepted",
    "C": "classical only: traffic recorded today can be decrypted later",
    "F": "unreachable or no TLS 1.3",
}


def key_name(key):
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return algorithm_of(key) or type(key).__name__


def _hello(host, port, groups, server_name, timeout):
    ctx = Context(False, groups, None, tls.CIPHERSUITES, verify=False)
    try:
        with ctx.wrap(socket.create_connection((host, port), timeout=timeout), server_name, timeout) as conn:
            return conn.group, conn.peer_certificate()
    finally:
        ctx.close()


SSH_PQ = ("mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384", "sntrup761x25519-sha512",
          "sntrup761x25519-sha512@openssh.com")
SSH_META = ("ext-info-", "kex-strict-", "kex-guess")


def ssh_kexinit(host, port, timeout):
    """The server's banner and algorithm lists, read from its KEXINIT (it sends one right after the banners)."""
    import struct
    with socket.create_connection((host, port), timeout=timeout) as s:
        f = s.makefile("rb")
        banner = b""
        for _ in range(20):
            banner = f.readline(512)
            if banner.startswith(b"SSH-"):
                break
        if not banner.startswith(b"SSH-"):
            raise OSError("not an SSH server")
        s.sendall(b"SSH-2.0-pqcsuite_scan\r\n")
        n, pad = struct.unpack(">IB", f.read(5))
        if n > 35000:
            raise OSError("oversized SSH packet")
        payload = f.read(n - 1)[:n - 1 - pad]
    if not payload or payload[0] != 20:
        raise OSError("the server did not send KEXINIT")
    lists, i = [], 17
    for _ in range(2):
        (m,) = struct.unpack(">I", payload[i:i + 4])
        lists.append(payload[i + 4:i + 4 + m].decode("ascii", "replace").split(","))
        i += 4 + m
    return banner.decode("ascii", "replace").strip(), lists[0], lists[1]


def probe_ssh(host, port, timeout):
    out = {"target": f"ssh://{host}:{port}", "protocol": "ssh", "accepts": [], "negotiated": None, "certificate": None, "error": None, "cnsa2": False}
    try:
        banner, kex, hostkeys = ssh_kexinit(host, port, timeout)
    except (OSError, ValueError) as e:
        out["error"], out["grade"] = str(e), "F"
        return out
    kex = [k for k in kex if not k.startswith(SSH_META)]
    pq = [k for k in kex if k in SSH_PQ]
    out |= {"accepts": kex, "negotiated": pq[0] if pq else (kex[0] if kex else None), "banner": banner, "host_keys": hostkeys,
            "certificate": {"key": ", ".join(hostkeys[:3]), "expires": "", "days_left": 9999, "quantum_safe": False}}
    out["grade"] = "A" if pq and len(pq) == len(kex) else "B" if pq else "C" if kex else "F"
    return out


def probe(target, server_name=None, timeout=8.0):
    if target.startswith("ssh://"):
        host, port = hostport(target[6:], "")
        return probe_ssh(host, port or 22, timeout)
    host, port = hostport(target, "")
    port = port or 443
    out = {"target": f"{host}:{port}", "protocol": "tls", "accepts": [], "negotiated": None, "certificate": None, "error": None, "cnsa2": False}
    try:
        out["negotiated"], cert = _hello(host, port, ":".join(PQ + CLASSICAL), server_name or host, timeout)
    except (tls.TLSError, OSError) as e:
        out["error"], out["grade"] = str(e), "F"
        return out
    if cert:
        days = (cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days
        key = key_name(cert.public_key())
        out["certificate"] = {"subject": cert.subject.rfc4514_string(), "key": key, "expires": cert.not_valid_after_utc.date().isoformat(),
                              "days_left": days, "quantum_safe": key.startswith("ML-DSA")}
    for g in PQ + CLASSICAL:
        try:
            _hello(host, port, g, server_name or host, timeout)
            out["accepts"].append(g)
        except (tls.TLSError, OSError):
            pass
    pq = any(g in out["accepts"] for g in PQ)
    classical = any(g in out["accepts"] for g in CLASSICAL)
    out["grade"] = "A" if pq and not classical else "B" if pq else "C" if classical else "F"
    cert_key = (out["certificate"] or {}).get("key")
    out["cnsa2"] = bool(out["accepts"]) and set(out["accepts"]) <= CNSA2_GROUPS and cert_key == "ML-DSA-87"
    return out


def scan(targets, workers=16, timeout=8.0):
    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(lambda t: probe(t, timeout=timeout), targets))


def summary(results):
    counts = {g: sum(r["grade"] == g for r in results) for g in GRADES}
    certs = [r["certificate"] for r in results if r["certificate"]]
    return {"endpoints": len(results), "grades": counts, "pq_key_exchange": counts["A"] + counts["B"], "cnsa2": sum(r.get("cnsa2", False) for r in results),
            "pq_certificates": sum(c["quantum_safe"] for c in certs), "expiring_30d": sum(c["days_left"] < 30 for c in certs)}


def report_html(results, title="Post-quantum readiness"):
    s, e = summary(results), html.escape
    rows = "".join(
        f"<tr><td>{e(r['target'])}</td><td class=g{r['grade']}>{r['grade']}</td><td>{e(r['negotiated'] or '')}</td>"
        f"<td>{e(', '.join(r['accepts']) or (r['error'] or ''))}</td>"
        f"<td>{e((r['certificate'] or {}).get('key', ''))}</td><td>{e((r['certificate'] or {}).get('expires', ''))}</td></tr>"
        for r in sorted(results, key=lambda r: (r["grade"], r["target"])))
    legend = "".join(f"<li><b class=g{g}>{g}</b> {e(t)} <span>{s['grades'][g]}</span></li>" for g, t in GRADES.items())
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>
:root{{--ink:#15171a;--mute:#6b7076;--line:#e3e5e8;--bg:#fff;--a:#0b6b3a;--b:#6b5a00;--c:#9a3412;--f:#6b7076}}
@media(prefers-color-scheme:dark){{:root{{--ink:#eceef0;--mute:#9aa0a6;--line:#2a2d31;--bg:#111315;--a:#4ade80;--b:#facc15;--c:#fb923c}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1080px;margin:0 auto;padding:32px 16px}}h1{{font-size:24px;margin:0 0 4px}}p{{color:var(--mute);margin:0 0 24px}}
.stats{{display:flex;flex-wrap:wrap;gap:32px;margin-bottom:24px}}.stats b{{display:block;font-size:28px}}.stats span{{color:var(--mute)}}
ul{{list-style:none;padding:0;margin:0 0 24px;display:grid;gap:6px}}li span{{color:var(--mute);margin-left:6px}}
.scroll{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;min-width:720px}}th,td{{text-align:left;padding:8px 10px 8px 0;border-bottom:1px solid var(--line)}}
th{{font-size:12px;color:var(--mute);font-weight:500}}.gA{{color:var(--a);font-weight:700}}.gB{{color:var(--b);font-weight:700}}.gC{{color:var(--c);font-weight:700}}.gF{{color:var(--f);font-weight:700}}
</style><main><h1>{e(title)}</h1><p>{s['endpoints']} endpoints scanned {now} by pqcsuite</p>
<div class=stats><div><b>{s['pq_key_exchange']}/{s['endpoints']}</b><span>offer post-quantum key exchange</span></div>
<div><b>{s['pq_certificates']}</b><span>use ML-DSA certificates</span></div><div><b>{s['cnsa2']}</b><span>meet CNSA 2.0</span></div><div><b>{s['expiring_30d']}</b><span>certificates expire within 30 days</span></div></div>
<ul>{legend}</ul><div class=scroll><table><thead><tr><th>Endpoint</th><th>Grade</th><th>Negotiated</th><th>Accepted key exchanges</th><th>Certificate key</th><th>Expires</th></tr></thead>
<tbody>{rows}</tbody></table></div></main></html>"""


def load_targets(items):
    targets = []
    for item in items:
        if item.endswith(".txt") or item.endswith(".lst"):
            with open(item, encoding="utf-8") as f:
                targets += [l.split("#")[0].strip() for l in f if l.split("#")[0].strip()]
        else:
            targets.append(item)
    return targets


def to_json(results):
    return json.dumps({"summary": summary(results), "endpoints": results}, indent=1)
