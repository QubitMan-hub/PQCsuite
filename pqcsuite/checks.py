"""Deployment checks for `pqcsuite doctor --ca DIR --config FILE --backups DIR`: each check is (level, message) with level ok,
warn or fail."""
import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509

from . import read_toml
from .pki import CA, CAError, encrypted, now, signed_by


def _private(path):
    """A key file readable by everyone fails, by its group warns (Kubernetes mounts secrets group-readable for fsGroup). POSIX
    permissions only; Windows ACLs are not checked."""
    if os.name == "nt":
        return []
    mode = os.stat(path).st_mode
    if mode & 0o004:
        return [("fail", f"{path} can be read by every user (chmod 600 it)")]
    return [("warn", f"{path} can be read by its group (chmod 600 it unless the group is this service's)")] if mode & 0o040 else []


def ca(root):
    root, out = Path(root), []
    try:
        c = CA(root)
    except (CAError, OSError, ValueError) as e:
        return [("fail", f"CA at {root}: {e}")]
    left = (c.cert.not_valid_after_utc - now()).days
    out.append(("ok" if left > 365 else "warn", f"CA {c.cert.subject.rfc4514_string()} ({c.algorithm}) valid for {left} more days"))
    if (root / "signer.json").exists():
        out.append(("ok", "CA key is held by an external signer (KMS or HSM)"))
    else:
        out += _private(root / "ca.key")
        out.append(("ok", "CA key is encrypted") if encrypted(root / "ca.key") else
                   ("warn", "CA key is not encrypted (created with --no-encrypt): anyone who copies ca.key can issue certificates; use KMS, an HSM or an encrypted key"))
    try:
        records = c.records()
    except (OSError, ValueError, TypeError) as e:
        return out + [("fail", f"{root / 'index.json'} cannot be read ({e}): restore it from a backup")]
    crl = root / "crl.pem"
    try:
        listed = x509.load_pem_x509_crl(crl.read_bytes()) if crl.exists() else None
    except ValueError:
        listed = False
    if listed is None:
        out.append(("fail", f"no {crl}: mutual-TLS services cannot start (pqcsuite ca crl)"))
    elif listed is False or not signed_by(c.cert, listed.tbs_certlist_bytes, listed.signature):
        out.append(("fail", f"{crl} is damaged or not signed by this CA; every client would be refused (pqcsuite ca crl)"))
    else:
        missing = [r.common_name for r in records if r.status == "revoked" and listed.get_revoked_certificate_by_serial_number(int(r.serial, 16)) is None]
        if missing:
            out.append(("fail", f"{len(missing)} revoked certificate(s) not in crl.pem ({', '.join(missing[:5])}): run pqcsuite ca crl"))
        nxt = listed.next_update_utc
        days = (nxt - now()) / dt.timedelta(days=1)
        out.append(("fail" if days < 0 else "warn" if days < 2 else "ok",
                    f"CRL {'expired' if days < 0 else 'valid for'} {abs(days):.1f} days{'' if days >= 2 else ': run pqcsuite ca maintain'}"))
    newest = {}
    for r in records:
        if r.status == "valid" and r.kind != "ca" and r.path and dt.datetime.fromisoformat(r.not_after) > now():
            newest[r.path] = max(newest.get(r.path, r), r, key=lambda x: x.not_after)
    gone = [r for r in newest.values() if not all((Path(r.path) / f).exists() for f in ("cert.pem", "key.pem", "chain.pem"))]
    if gone:
        out.append(("warn", f"{len(gone)} valid certificate(s) recorded without their files ({', '.join(r.common_name for r in gone[:5])}): "
                            "moved elsewhere, or a crash while issuing; revoke any whose files are gone for good"))
    soon = c.expiring(30)
    out.append(("warn", f"{len(soon)} certificate(s) expire within 30 days: {', '.join(r.common_name for r in soon[:5])} "
                        "(pqcsuite ca maintain renews them)") if soon else ("ok", "no certificate expires within 30 days"))
    return out


def backups(folder, days=2):
    """Vault archives: each readable, each opened by at least two keys, and the newest of each source recent."""
    from .vault import VaultError, read_header
    folder, out = Path(folder), []
    archives = sorted(folder.glob("*.pqv"))
    if not archives:
        return [("fail", f"no Vault archives in {folder}")]
    newest, lone, broken = {}, [], []
    for p in archives:
        try:
            with open(p, "rb") as f:
                h = read_header(f)
        except (VaultError, OSError, KeyError):
            broken.append(p.name)
            continue
        if len({r["id"] for r in h["recipients"]}) < 2:
            lone.append(p.name)
        newest[h["name"]] = max(newest.get(h["name"], 0), p.stat().st_mtime)
    if broken:
        out.append(("fail", f"{len(broken)} archive(s) in {folder} cannot be read: {', '.join(broken[:5])}"))
    out.append(("warn", f"{len(lone)} archive(s) open with a single key, so losing it loses them ({', '.join(lone[:3])}): "
                        "`pqcsuite vault share FILE --key KEY -r recovery.pub` adds a recovery key without re-encrypting")
               if lone else ("ok", f"every archive in {folder} opens with at least two keys"))
    for name, mtime in sorted(newest.items()):
        age = (dt.datetime.now().timestamp() - mtime) / 86400
        out.append(("warn" if age > days else "ok", f"newest backup of {name} is {age:.1f} days old"
                    + (f" (more than {days}): is the scheduled backup still running?" if age > days else "")))
    return out


def _files(where, d, names):
    out = []
    for k in [n for n in names if not (n == "crl" and d.get("crl_url"))]:  # with crl_url the copy appears at the first fetch
        p = d.get(k)
        if not p:
            continue
        if not Path(p).exists():
            out.append(("fail", f"{where}: {k} = {p} does not exist"))
        elif k in ("key", "private_key"):
            out += _private(p)
    return out


def config(path):
    """Load the file with the loader for its kind, then look for settings that work but weaken the deployment."""
    from .console import Settings
    from .tls.edge import load_config as edge
    from .vpn import load_config as vpn
    from .vpn.wireguard import load_gateway
    try:
        doc = read_toml(path)
    except OSError as e:
        return [("fail", f"{path}: {e.strerror or e}")]
    except ValueError as e:
        return [("fail", str(e))]
    kind = next((k for k in ("edge", "site", "wireguard", "console") if k in doc), None)
    if not kind:
        return [("fail", f"{path}: no [[edge]], [site], [wireguard] or [console] section")]
    try:
        {"edge": edge, "site": vpn, "wireguard": load_gateway, "console": Settings.load}[kind](path)
    except (OSError, ValueError, CAError) as e:
        return [("fail", f"{path}: {e}")]
    out = [("ok", f"{path}: {kind} configuration loads")]
    keys = ("cert", "key", "ca", "crl", "fallback_cert", "fallback_key", "private_key")
    for i, r in enumerate(doc.get("edge", [])):
        where = f"{path} edge {r.get('name', i + 1)}"
        out += _files(where, r, keys)
        if r.get("policy") == "transition":
            out.append(("warn", f"{where}: policy transition lets clients without post-quantum key exchange in; fine for browsers, "
                                "use strict for everything else"))
        if r.get("require_client_cert") and not r.get("crl"):
            out.append(("fail", f"{where}: mutual TLS without a CRL accepts revoked clients"))
        if r.get("crl") and not r.get("crl_url"):
            out.append(("warn", f"{where}: the CRL is a local file; unless this machine is the CA, set crl_url so revocations arrive"))
    for section in ("site", "wireguard"):
        s = doc.get(section)
        if s:
            out += _files(f"{path} [{section}]", s, keys)
            if not s.get("crl"):
                out.append(("fail", f"{path} [{section}]: no crl, so revoked peers keep getting keys"))
            elif not s.get("crl_url"):
                out.append(("warn", f"{path} [{section}]: the CRL is a local file; set crl_url unless this machine is the CA"))
    c = doc.get("console")
    if c:
        host = str(c.get("listen", "127.0.0.1:8900")).rsplit(":", 1)[0].strip("[]")
        try:
            local = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local:
            out.append(("warn", f"{path} [console]: listens on {host} over plain HTTP; keep it on localhost or put the edge in front"))
        if c.get("ca") and not (Path(c["ca"]) / "ca.crt").exists():
            out.append(("fail", f"{path} [console]: ca = {c['ca']} holds no CA (no ca.crt), so the console will not start"))
        out += [("warn", f"{path} [console]: backups folder {b} does not exist") for b in c.get("backups", []) if not Path(b).is_dir()]
    return out
