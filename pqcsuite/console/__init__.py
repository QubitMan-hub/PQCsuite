"""The console: one page for certificates, edges, VPN tunnels, backups and readiness scans.

It listens on localhost and wants a bearer token on every API call. Put `pqcsuite edge --policy transition` in front of it for
remote access: browsers already do X25519MLKEM768, though they cannot verify ML-DSA certificates yet.
"""
import hmac
import json
import logging
import os
import secrets
import threading
import time
import tomllib
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from .. import NAME, __version__
from ..ca import CA, CAError
from ..edge import hostport

log = logging.getLogger("pqcsuite.console")


@dataclass
class Settings:
    listen: str = "127.0.0.1:8900"
    ca: str = ""
    edges: list = field(default_factory=list)
    vpn: list = field(default_factory=list)
    wireguard: list = field(default_factory=list)
    backups: list = field(default_factory=list)
    scan_targets: list = field(default_factory=list)
    fleet: str = ""
    audit_log: str = "console-audit.jsonl"

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            d = tomllib.load(f).get("console", {})
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"[console]: unknown settings {', '.join(sorted(unknown))}")
        return cls(**d)


class App:
    def __init__(self, settings, token=None):
        self.s = settings
        self.token = token or os.environ.get("PQCSUITE_CONSOLE_TOKEN") or secrets.token_urlsafe(24)
        self.last_scan, self.scanning = None, False
        self.lock = threading.Lock()

    def ca(self):
        if not self.s.ca:
            raise CAError("no CA configured (start the console with --ca)")
        pw = os.environ.get("PQCSUITE_CA_PASSPHRASE")
        key = Path(self.s.ca) / "ca.key"
        encrypted = key.exists() and b"ENCRYPTED" in key.read_bytes()[:64]
        return CA(self.s.ca, pw.encode() if pw and encrypted else None)

    def audit(self, action, detail):
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action, **detail})
        with self.lock, open(self.s.audit_log, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        log.info("console: %s %s", action, detail)

    def certificates(self):
        ca = self.ca()
        import datetime as dt
        now = dt.datetime.now(dt.timezone.utc)
        rows = [vars(r) | {"days_left": (dt.datetime.fromisoformat(r.not_after) - now).days} for r in ca.records()]
        return {"root": {"subject": ca.cert.subject.rfc4514_string(), "expires": ca.cert.not_valid_after_utc.date().isoformat(),
                         "algorithm": ca.signer.algorithm}, "certificates": rows}

    def edges(self):
        out = []
        for url in self.s.edges:
            try:
                with urllib.request.urlopen(url.rstrip("/") + "/status", timeout=3) as r:
                    out += [{"source": url, "name": k, **v} for k, v in json.loads(r.read()).items()]
            except OSError as e:
                out.append({"source": url, "error": str(e)})
        return out

    def tunnels(self):
        from ..vpn.charon import Charon, CharonError
        out = []
        for uri in self.s.vpn:
            try:
                with Charon(uri) as ch:
                    out += [{"source": uri, **t} for t in ch.tunnels()]
            except (CharonError, OSError, ImportError) as e:
                out.append({"source": uri, "error": str(e)})
        return out

    def remote_users(self):
        out = []
        for url in self.s.wireguard:
            try:
                with urllib.request.urlopen(url.rstrip("/") + "/status", timeout=3) as r:
                    out += [{"source": url, "user": k, **v} for k, v in json.loads(r.read()).items() if k != "_events"]
            except (OSError, ValueError) as e:
                out.append({"source": url, "error": str(e)})
        return out

    def backups(self):
        from ..vault import VaultError, inspect
        out = []
        for folder in self.s.backups:
            for f in sorted(Path(folder).glob("*.pqv"), reverse=True)[:200]:
                try:
                    out.append({"file": str(f), **inspect(f)})
                except (VaultError, OSError, ValueError) as e:
                    out.append({"file": str(f), "error": str(e)})
        return out

    def fleet(self):
        from ..fleet import Service
        if not self.s.fleet:
            return []
        return Service(self.s.fleet).agents()

    def set_desired(self, b):
        from ..fleet import Service
        if not self.s.fleet:
            raise ValueError("no fleet folder configured (start the console with --fleet)")
        Service(self.s.fleet).set_desired(str(b["name"]), str(b["config"]))
        self.audit("fleet_config", {"agent": b["name"], "bytes": len(str(b["config"]))})
        return {"saved": b["name"]}

    def run_scan(self, targets):
        from .. import scan
        with self.lock:
            if self.scanning:
                raise CAError("a scan is already running")
            self.scanning = True

        def work():
            try:
                results = scan.scan(targets)
                self.last_scan = {"finished": time.time(), "summary": scan.summary(results), "endpoints": results}
            finally:
                self.scanning = False
        threading.Thread(target=work, daemon=True).start()

    def overview(self):
        out = {"product": NAME, "version": __version__}
        try:
            certs = self.certificates()["certificates"]
            out["certificates"] = {"valid": sum(c["status"] == "valid" for c in certs), "revoked": sum(c["status"] == "revoked" for c in certs),
                                   "expiring_30d": sum(c["status"] == "valid" and c["days_left"] <= 30 for c in certs)}
        except CAError as e:
            out["certificates"] = {"error": str(e)}
        edges = self.edges()
        out["edges"] = {"routes": sum("error" not in e for e in edges), "unreachable": sum("error" in e for e in edges),
                        "active": sum(e.get("active", 0) for e in edges), "handshakes": sum(e.get("handshakes", 0) for e in edges),
                        "failed": sum(e.get("handshake_failed", 0) for e in edges)}
        tun = [t for t in self.tunnels() if "error" not in t]
        users = [u for u in self.remote_users() if "error" not in u]
        out["vpn"] = {"tunnels": len(tun), "quantum_safe": sum(t["state"] == "ESTABLISHED" and t["ppk"] and "ML_KEM" in t["key_exchange"] for t in tun),
                      "remote_users": len(users), "remote_online": sum(time.time() - u.get("latest_handshake", 0) < 180 for u in users)}
        b = [x for x in self.backups() if "error" not in x]
        out["backups"] = {"count": len(b), "latest": b[0]["created"] if b else None, "signed": sum(bool(x["signed_by"]) for x in b)}
        out["readiness"] = self.last_scan["summary"] if self.last_scan else None
        agents = self.fleet()
        out["fleet"] = {"agents": len(agents), "online": sum(a["online"] for a in agents), "in_sync": sum(a["in_sync"] for a in agents)}
        return out

    def handle(self, method, path, body):
        routes = {
            ("GET", "/api/overview"): lambda: self.overview(),
            ("GET", "/api/certificates"): lambda: self.certificates(),
            ("GET", "/api/edges"): lambda: self.edges(),
            ("GET", "/api/tunnels"): lambda: self.tunnels(),
            ("GET", "/api/remote"): lambda: self.remote_users(),
            ("GET", "/api/backups"): lambda: self.backups(),
            ("GET", "/api/fleet"): lambda: self.fleet(),
            ("POST", "/api/fleet/desired"): lambda: self.set_desired(body),
            ("GET", "/api/scan"): lambda: {"running": self.scanning, "last": self.last_scan, "targets": self.s.scan_targets},
            ("POST", "/api/certificates/issue"): lambda: self.issue(body),
            ("POST", "/api/certificates/revoke"): lambda: self.revoke(body),
            ("POST", "/api/certificates/maintain"): lambda: self.maintain(),
            ("POST", "/api/scan"): lambda: self.start_scan(body),
        }
        fn = routes.get((method, path))
        if not fn:
            return 404, {"error": "no such endpoint"}
        try:
            return 200, fn()
        except (CAError, ValueError, KeyError, OSError) as e:
            return 400, {"error": str(e)}

    def issue(self, b):
        kind, cn = b["kind"], str(b["common_name"]).strip()
        if not cn:
            raise ValueError("a common name is needed")
        names = [n.strip() for n in str(b.get("names", "")).split(",") if n.strip()]
        out, rec = self.ca().issue(cn, kind, names, int(b.get("days", 397)))
        self.audit("issue", {"serial": rec.serial, "common_name": cn, "kind": kind})
        return {"serial": rec.serial, "folder": str(out)}

    def revoke(self, b):
        ca = self.ca()
        ca.revoke(b["serial"], b.get("reason", "unspecified"))
        self.audit("revoke", {"serial": b["serial"], "reason": b.get("reason", "unspecified")})
        return {"revoked": b["serial"]}

    def maintain(self):
        renewed, skipped = self.ca().maintain()
        self.audit("maintain", {"renewed": [r.serial for r in renewed]})
        return {"renewed": [r.common_name for r in renewed], "skipped": [r.common_name for r in skipped]}

    def start_scan(self, b):
        targets = [t.strip() for t in str(b.get("targets", "")).replace("\n", ",").split(",") if t.strip()] or self.s.scan_targets
        if not targets:
            raise ValueError("no targets to scan")
        if len(targets) > 500:
            raise ValueError("at most 500 targets per scan")
        self.run_scan(targets)
        self.audit("scan", {"targets": len(targets)})
        return {"started": len(targets)}


def page():
    return resources.files(__package__).joinpath("console.html").read_bytes()


def serve(app):
    html = page()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"{NAME}/{__version__}"

        def reply(self, status, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def authorised(self):
            given = self.headers.get("Authorization", "").removeprefix("Bearer ")
            return hmac.compare_digest(given.encode(), app.token.encode())

        def route(self, method):
            path = self.path.split("?")[0]
            if method == "GET" and path in ("/", "/index.html"):
                return self.reply(200, html, "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.reply(404, {"error": "not found"})
            if not self.authorised():
                return self.reply(401, {"error": "missing or wrong token"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1 << 20:
                return self.reply(413, {"error": "request too large"})
            try:
                body = json.loads(self.rfile.read(n)) if n else {}
            except ValueError:
                return self.reply(400, {"error": "invalid JSON"})
            self.reply(*app.handle(method, path, body))

        def do_GET(self):
            self.route("GET")

        def do_POST(self):
            self.route("POST")

        def log_message(self, fmt, *args):
            log.debug(fmt, *args)

    httpd = ThreadingHTTPServer(hostport(app.s.listen, "127.0.0.1"), Handler)
    return httpd
