"""The console: one page for certificates, edges, VPN tunnels, backups and readiness scans.

It listens on localhost and wants a bearer token on every API call. Put `pqcsuite tls edge --policy transition` in front of it for
remote access: browsers already do X25519MLKEM768, though they cannot verify ML-DSA certificates yet.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from .. import HTTP_IDLE, NAME, __version__, build, content_length, read_toml
from ..pki import CA, CAError, encrypted
from ..tls import hostport

log = logging.getLogger("pqcsuite.console")
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@dataclass
class Settings:
    listen: str = "127.0.0.1:8900"
    ca: str = ""
    edges: list = field(default_factory=list)
    vpn: list = field(default_factory=list)
    wireguard: list = field(default_factory=list)
    backups: list = field(default_factory=list)
    scan_targets: list = field(default_factory=list)
    scan_every_hours: float = 0.0
    check_updates: bool = False
    audit_log: str = "console-audit.jsonl"

    @classmethod
    def load(cls, path):
        d = read_toml(path).get("console", {})
        s = build(cls, d, "[console]")
        if s.scan_every_hours and s.scan_every_hours < 0.25:
            raise ValueError("[console]: scan_every_hours must be at least 0.25 (15 minutes), or 0 for no scheduled scans")
        return s


class App:
    def __init__(self, settings, token=None):
        self.s = settings
        self.token = token or os.environ.get("PQCSUITE_CONSOLE_TOKEN") or secrets.token_urlsafe(24)
        self.last_scan, self.scanning, self.scan_error = None, False, None
        self.latest, self.latest_checked = None, 0.0
        self.lock = threading.Lock()

    def ca(self):
        if not self.s.ca:
            raise CAError("no CA configured (start the console with --ca)")
        pw = os.environ.get("PQCSUITE_CA_PASSPHRASE")
        return CA(self.s.ca, pw.encode() if pw and encrypted(Path(self.s.ca) / "ca.key") else None)

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
                         "algorithm": ca.algorithm}, "certificates": rows}

    def edges(self):
        out = []
        for url in self.s.edges:
            try:
                with NO_PROXY.open(url.rstrip("/") + "/status", timeout=3) as r:
                    status = json.loads(r.read())
                if not (isinstance(status, dict) and all(isinstance(v, dict) for v in status.values())):
                    raise ValueError("this address does not answer like an edge's /status")
                out += [{"source": url, "name": k, **v} for k, v in status.items()]
            except (OSError, ValueError) as e:
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
                with NO_PROXY.open(url.rstrip("/") + "/status", timeout=3) as r:
                    status = json.loads(r.read())
                users = {k: v for k, v in status.items() if k != "_events"} if isinstance(status, dict) else None
                if users is None or not all(isinstance(v, dict) for v in users.values()):
                    raise ValueError("this address does not answer like a WireGuard gateway's /status")
                out += [{"source": url, "user": k, **v} for k, v in users.items()]
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

    def run_scan(self, targets):
        from ..readiness import scan
        with self.lock:
            if self.scanning:
                raise CAError("a scan is already running")
            self.scanning, self.scan_error = True, None

        def work():
            try:
                results = scan.scan(targets)
                before = {e["target"]: e["grade"] for e in (self.last_scan or {}).get("endpoints", [])}
                changes = [{"target": r["target"], "before": before.get(r["target"]), "after": r["grade"]}
                           for r in results if self.last_scan and before.get(r["target"]) != r["grade"]]
                for c in changes:
                    log.warning("readiness: %s went from %s to %s", c["target"], c["before"] or "not scanned", c["after"])
                self.last_scan = {"finished": time.time(), "summary": scan.summary(results), "endpoints": results, "changes": changes}
            except Exception as e:
                log.exception("readiness scan failed")
                self.scan_error = f"the scan failed: {e}"
            finally:
                self.scanning = False
        threading.Thread(target=work, daemon=True).start()

    def schedule(self):
        """With scan_every_hours and scan_targets set, scan them now and then again every scan_every_hours; each scan lists
        the endpoints whose grade changed since the one before."""
        if not (self.s.scan_every_hours and self.s.scan_targets):
            return

        def loop():
            while True:
                if not self.scanning:
                    try:
                        self.run_scan(self.s.scan_targets)
                        self.audit("scan", {"targets": len(self.s.scan_targets), "scheduled": True})
                    except (CAError, OSError) as e:
                        log.error("scheduled scan: %s", e)
                time.sleep(self.s.scan_every_hours * 3600)
        threading.Thread(target=loop, daemon=True, name="scheduled-scan").start()

    def update(self):
        """The newest release when check_updates is on and it is newer than this one; looked up at most once a day, in the
        background, so a network without internet access only loses the notice."""
        if not self.s.check_updates:
            return None
        if time.time() - self.latest_checked > 86400:
            self.latest_checked = time.time()

            def check():
                from .. import latest_release
                try:
                    self.latest = latest_release()
                except (OSError, ValueError) as e:
                    log.info("update check failed: %s", e)
            threading.Thread(target=check, daemon=True).start()
        return self.latest if self.latest and self.latest["newer"] else None

    def overview(self):
        out = {"product": NAME, "version": __version__, "update": self.update()}
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
        out["readiness"] = self.last_scan["summary"] | {"changes": len(self.last_scan.get("changes", [])),
                                                        "finished": self.last_scan["finished"]} if self.last_scan else None
        return out

    def handle(self, method, path, body):
        routes = {
            ("GET", "/api/overview"): lambda: self.overview(),
            ("GET", "/api/certificates"): lambda: self.certificates(),
            ("GET", "/api/edges"): lambda: self.edges(),
            ("GET", "/api/tunnels"): lambda: self.tunnels(),
            ("GET", "/api/remote"): lambda: self.remote_users(),
            ("GET", "/api/backups"): lambda: self.backups(),
            ("GET", "/api/scan"): lambda: {"running": self.scanning, "last": self.last_scan, "error": self.scan_error, "targets": self.s.scan_targets,
                                           "every_hours": self.s.scan_every_hours},
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
        except KeyError as e:
            return 400, {"error": f"missing field {e.args[0]}"}
        except (CAError, ValueError, OSError) as e:
            return 400, {"error": str(e)}
        except Exception:
            log.exception("%s %s failed", method, path)
            return 500, {"error": "internal error; the details are in the console's log"}

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
        raw = b.get("targets", "")
        items = raw if isinstance(raw, list) else str(raw).replace("\n", ",").split(",")
        targets = [str(t).strip() for t in items if str(t).strip()] or self.s.scan_targets
        from ..readiness.scan import endpoint
        for t in targets:
            endpoint(t)
        if not targets:
            raise ValueError("no targets to scan")
        if len(targets) > 500:
            raise ValueError("at most 500 targets per scan")
        self.run_scan(targets)
        self.audit("scan", {"targets": len(targets)})
        return {"started": len(targets)}


def page():
    return resources.files(__package__).joinpath("console.html").read_bytes()


def policy(html):
    """The page's one inline script is allowed by its hash, so no other script can run even if markup were ever injected."""
    script = re.search(rb"<script>(.*?)</script>", html, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script).digest()).decode()
    return f"default-src 'self'; img-src 'self' data:; font-src data:; style-src 'self' 'unsafe-inline'; script-src 'sha256-{digest}'; frame-ancestors 'none'"


class Backoff:
    """After 10 wrong tokens from one address within a minute, that address is refused until the minute is over."""

    def __init__(self, limit=10, window=60.0):
        self.limit, self.window, self.lock, self.failures = limit, window, threading.Lock(), {}

    def blocked(self, addr):
        with self.lock:
            recent = [t for t in self.failures.get(addr, []) if time.monotonic() - t < self.window]
            self.failures[addr] = recent
            return len(recent) >= self.limit

    def failed(self, addr):
        with self.lock:
            self.failures.setdefault(addr, []).append(time.monotonic())


def serve(app):
    html = page()
    csp, backoff = policy(html), Backoff()

    class Handler(BaseHTTPRequestHandler):
        timeout = HTTP_IDLE
        server_version = f"{NAME}/{__version__}"

        def reply(self, status, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", csp)
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
            if backoff.blocked(self.client_address[0]):
                return self.reply(429, {"error": "too many wrong tokens; wait a minute"})
            if not self.authorised():
                backoff.failed(self.client_address[0])
                return self.reply(401, {"error": "missing or wrong token"})
            n = content_length(self.headers)
            if n is None:
                return self.reply(400, {"error": "bad Content-Length"})
            if n > 1 << 20:
                return self.reply(413, {"error": "request too large"})
            try:
                body = json.loads(self.rfile.read(n)) if n else {}
            except ValueError:
                return self.reply(400, {"error": "invalid JSON"})
            if not isinstance(body, dict):
                return self.reply(400, {"error": "the body must be a JSON object"})
            self.reply(*app.handle(method, path, body))

        def do_GET(self):
            self.route("GET")

        def do_POST(self):
            self.route("POST")

        def log_message(self, fmt, *args):
            log.debug(fmt, *args)

    httpd = ThreadingHTTPServer(hostport(app.s.listen, "127.0.0.1"), Handler)
    return httpd
