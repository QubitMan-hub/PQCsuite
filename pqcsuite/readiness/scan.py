"""Post-quantum readiness of TLS endpoints: which key exchanges each accepts, what it negotiates, and its certificate."""
import datetime as dt
import html
import json
import logging
import socket
import warnings
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .. import explain, read_text, tls
from ..pki import algorithm_of
from ..tls import hostport
from ..tls.openssl import Context

log = logging.getLogger("pqcsuite.readiness")
PQ = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024"]
CNSA2_GROUPS = {"SecP384r1MLKEM1024", "MLKEM1024"}
CLASSICAL = ["X25519", "secp256r1", "secp384r1", "secp521r1", "X448", "ffdhe2048", "ffdhe3072"]
LEGACY_TLS = ("TLSv1", "TLSv1_1")
GRADES = {
    "A": "post-quantum key exchange only",
    "B": "post-quantum key exchange, classical still accepted",
    "C": "classical only: traffic recorded today can be decrypted later",
    "F": "unreachable, or no TLS at all",
}


def key_name(key):
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return algorithm_of(key) or type(key).__name__


def _legacy(host, port, server_name, timeout):
    """(version, certificate) from a server that refuses TLS 1.3 but still talks TLS 1.2 or older."""
    import ssl
    from cryptography import x509
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=server_name) as s:
        der = s.getpeercert(binary_form=True)
        return s.version(), x509.load_der_x509_certificate(der) if der else None


def _old_versions(host, port, server_name, timeout):
    """TLS 1.0 and 1.1, which should be off everywhere; each is tried on its own."""
    import ssl
    found = []
    for name in LEGACY_TLS:
        v = getattr(ssl.TLSVersion, name)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ctx.maximum_version = v
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=server_name):
                found.append({"TLSv1": "TLSv1.0", "TLSv1_1": "TLSv1.1"}[name])
        except (OSError, ValueError):
            pass
    return found


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
        try:
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
        except struct.error:
            raise OSError("the server sent a truncated SSH packet") from None
    return banner.decode("ascii", "replace").strip(), lists[0], lists[1]


def probe_ssh(host, port, timeout):
    out = {"target": f"ssh://{_join(host, port)}", "protocol": "ssh", "accepts": [], "negotiated": None, "certificate": None, "error": None, "cnsa2": False}
    try:
        banner, kex, hostkeys = ssh_kexinit(host, port, timeout)
    except (OSError, ValueError) as e:
        out["error"], out["grade"] = explain(e), "F"
        return out
    kex = [k for k in kex if not k.startswith(SSH_META)]
    pq = [k for k in kex if k in SSH_PQ]
    out |= {"accepts": kex, "negotiated": pq[0] if pq else (kex[0] if kex else None), "banner": banner, "host_keys": hostkeys,
            "certificate": {"key": ", ".join(hostkeys[:3]), "expires": "", "days_left": 9999, "quantum_safe": False}}
    out["grade"] = "A" if pq and len(pq) == len(kex) else "B" if pq else "C" if kex else "F"
    return out


def _cert_info(cert):
    if not cert:
        return None
    try:
        key = key_name(cert.public_key())
    except Exception:
        key = cert.public_key_algorithm_oid.dotted_string
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "key": key,
            "expires": cert.not_valid_after_utc.date().isoformat(),
            "days_left": (cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days, "quantum_safe": key.startswith("ML-DSA")}


def endpoint(target):
    """(protocol, host, port) of a target written as host, host:port, [v6]:port, https://host/path or ssh://host[:port]."""
    ssh = target.startswith("ssh://")
    t = target.split("://", 1)[-1].split("/", 1)[0]
    host, port = (t.strip("[]"), None) if ":" not in t or t.endswith("]") else hostport(t, "")
    if not host:
        raise ValueError(f"expected host, host:port or ssh://host, got {target!r}")
    return ("ssh" if ssh else "tls"), host, port or (22 if ssh else 443)


def probe(target, server_name=None, timeout=8.0):
    kind, host, port = endpoint(target)
    if kind == "ssh":
        return probe_ssh(host, port, timeout)
    out = {"target": _join(host, port), "protocol": "tls", "accepts": [], "negotiated": None, "certificate": None, "error": None, "cnsa2": False}
    try:
        out["negotiated"], cert = _hello(host, port, ":".join(PQ + CLASSICAL), server_name or host, timeout)
    except (tls.TLSError, OSError) as e:
        try:
            version, cert = _legacy(host, port, server_name or host, timeout)
        except (OSError, ValueError):
            out["error"], out["grade"] = explain(e), "F"
            return out
        out["negotiated"], out["accepts"], out["grade"] = version, [version], "C"
        out["certificate"] = _cert_info(cert)
        out["legacy"] = _old_versions(host, port, server_name or host, timeout)
        return out
    out["certificate"] = _cert_info(cert)
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
    out["legacy"] = _old_versions(host, port, server_name or host, timeout)
    return out


def scan(targets, workers=16, timeout=8.0):
    """Every target gets a result: one server answering in a way nobody planned for is graded F, not the end of the scan."""
    def one(t):
        try:
            return probe(t, timeout=timeout)
        except Exception as e:
            log.exception("readiness: probing %s failed", t)
            return {"target": t, "protocol": "ssh" if t.startswith("ssh://") else "tls", "accepts": [], "negotiated": None,
                    "certificate": None, "error": f"unexpected answer: {e}", "cnsa2": False, "grade": "F"}
    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(one, targets))


def summary(results):
    counts = {g: sum(r["grade"] == g for r in results) for g in GRADES}
    certs = [r["certificate"] for r in results if r["certificate"]]
    return {"endpoints": len(results), "grades": counts, "pq_key_exchange": counts["A"] + counts["B"], "cnsa2": sum(r.get("cnsa2", False) for r in results),
            "pq_certificates": sum(c["quantum_safe"] for c in certs), "expiring_30d": sum(c["days_left"] < 30 for c in certs)}


def report_html(results, title="Post-quantum readiness"):
    s, e = summary(results), html.escape
    rows = "".join(
        f"<tr><td>{e(r['target'])}</td><td class=g{r['grade']}>{r['grade']}</td><td>{e(r['negotiated'] or '')}</td>"
        f"<td>{e(', '.join(r['accepts']) or (r['error'] or ''))}"
        f"{'<br><small>also accepts ' + e(' and '.join(r['legacy'])) + ': switch it off</small>' if r.get('legacy') else ''}</td>"
        f"<td>{e((r['certificate'] or {}).get('key', ''))}<br><small>{e((r['certificate'] or {}).get('issuer', ''))}</small></td>"
        f"<td>{e((r['certificate'] or {}).get('expires', ''))}</td></tr>"
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
<ul>{legend}</ul><div class=scroll><table><thead><tr><th>Endpoint</th><th>Grade</th><th>Negotiated</th><th>Accepted key exchanges</th><th>Certificate key and issuer</th><th>Expires</th></tr></thead>
<tbody>{rows}</tbody></table></div></main></html>"""


def _join(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def load_targets(items):
    targets = []
    for item in items:
        if item.endswith(".txt") or item.endswith(".lst"):
            targets += [l.split("#")[0].strip() for l in read_text(item).splitlines() if l.split("#")[0].strip()]
        else:
            targets.append(item)
    return targets


def to_json(results):
    return json.dumps({"summary": summary(results), "endpoints": results}, indent=1)
