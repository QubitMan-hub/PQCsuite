"""The Acxelin TLS console: the certificate authority (create, issue, revoke, refresh the CRL), edges (status, connection test) and health.

Runs on acxelin-core's console mechanism; this module is only the product's pages, routes and state. A CA passphrase is held in
memory for the life of the console and is never written anywhere, so a restart locks an encrypted CA again.
"""
import datetime as dt
import functools
import json
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from acxelin_core import console as core
from acxelin_core import shell, tls
from acxelin_core.files import write
from acxelin_core.http import explain, hostport
from acxelin_core.pki import CA, CAError, encrypted
from cryptography import x509
from cryptography.x509.oid import NameOID

from . import __version__, checks, policies
from .common import env

NAME = re.compile(r"[A-Za-z0-9*._-]{1,253}")
MAX_EDGES = 50


def task(fn):
    """Routes raise ValueError for a refused request; CA, TLS and file errors become the same, in words."""
    @functools.wraps(fn)
    def run(self, body):
        try:
            return fn(self, body)
        except (CAError, tls.TLSError, OSError) as e:
            raise ValueError(explain(e)) from None
    return run


def _text(body, key, what, limit=253):
    v = body.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"Enter {what}")
    if len(v.strip()) > limit:
        raise ValueError(f"{what[0].upper() + what[1:]} is too long")
    return v.strip()


class TLSConsole:
    def __init__(self, home, ca_dir=None):
        self.home = Path(home)
        self.ca_dir = Path(ca_dir) if ca_dir else self.home / "ca"
        self.passphrase = None
        self.lock = threading.Lock()
        given = env("ACXELIN_TLS_CA_PASSPHRASE", "PQCSUITE_CA_PASSPHRASE")  # a service's secret, so nobody types it into a browser
        if given and self._exists() and encrypted(self.ca_dir / "ca.key"):
            try:
                CA(self.ca_dir, given.encode()).signer
                self.passphrase = given.encode()
            except CAError:
                pass

    # --- the certificate authority

    def _exists(self):
        return (self.ca_dir / "ca.crt").exists()

    def _ca(self):
        if not self._exists():
            raise ValueError("There is no certificate authority yet: create one first")
        if encrypted(self.ca_dir / "ca.key") and not self.passphrase:
            raise ValueError("The CA key is locked: unlock it with its passphrase")
        return CA(self.ca_dir, self.passphrase)

    def _crl(self):
        f = self.ca_dir / "crl.pem"
        if not f.exists():
            return None
        crl = x509.load_pem_x509_crl(f.read_bytes())
        left = (crl.next_update_utc - dt.datetime.now(dt.timezone.utc)).total_seconds() / 86400
        return {"next_update": crl.next_update_utc.isoformat(), "days_left": round(left, 1)}

    @task
    def status(self, body):
        if not self._exists():
            return 200, {"configured": False}
        ca = CA(self.ca_dir)
        rows = ca.records()
        soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).isoformat()
        enc = encrypted(self.ca_dir / "ca.key")
        return 200, {"configured": True, "home": str(self.home), "name": next((str(a.value) for a in ca.cert.subject if a.oid == NameOID.COMMON_NAME), ""), "algorithm": ca.algorithm,
                     "encrypted": enc, "unlocked": bool(self.passphrase) or not enc, "crl": self._crl(),
                     "counts": {"valid": sum(r.status == "valid" for r in rows), "revoked": sum(r.status == "revoked" for r in rows),
                                "expiring": sum(r.status == "valid" and r.not_after < soon for r in rows)}}

    @task
    def create(self, body):
        name = _text(body, "name", "a name for the certificate authority", 120)
        if self._exists():
            raise ValueError("A certificate authority already exists here")
        pw = body.get("passphrase")
        if pw is not None and not isinstance(pw, str):
            raise ValueError("The passphrase must be text")
        key = pw.encode() if pw else None
        CA.init(self.ca_dir, name, passphrase=key)
        ca = CA(self.ca_dir, key)
        ca.crl(7)
        with self.lock:
            self.passphrase = key
        return 200, {"name": name, "algorithm": ca.algorithm}

    @task
    def unlock(self, body):
        pw = body.get("passphrase")
        if not isinstance(pw, str) or not pw:
            raise ValueError("Enter the CA passphrase")
        if not self._exists():
            raise ValueError("There is no certificate authority yet: create one first")
        CA(self.ca_dir, pw.encode()).signer  # raises "wrong passphrase" without echoing it
        with self.lock:
            self.passphrase = pw.encode()
        return 200, {"unlocked": True}

    # --- certificates

    @task
    def certificates(self, body):
        if not self._exists():
            return 200, {"certificates": []}
        rows = sorted(CA(self.ca_dir).records(), key=lambda r: r.not_after)
        return 200, {"certificates": [{"serial": r.serial, "common_name": r.common_name, "kind": r.kind, "algorithm": r.algorithm, "not_after": r.not_after,
                                       "status": r.status, "reason": r.reason} for r in rows]}

    @task
    def issue(self, body):
        ca = self._ca()
        kind = body.get("kind")
        if kind not in ("server", "client"):
            raise ValueError("Choose server or client")
        cn = _text(body, "common_name", "the name the certificate is for")
        names = body.get("names") or []
        names = [n.strip() for n in (re.split(r"[,\n]", names) if isinstance(names, str) else names) if isinstance(n, str) and n.strip()]
        for n in [cn, *names]:
            if not NAME.fullmatch(n) and not _is_ip(n):
                raise ValueError(f"{n!r} is not a valid name: use letters, digits, dots, dashes and underscores")
        days = body.get("days", 397)
        if type(days) is not int or not 1 <= days <= 3650:
            raise ValueError("Days must be a whole number from 1 to 3650")
        folder = Path("issued") / f"{re.sub(r'[^A-Za-z0-9.-]', '_', cn)}-{secrets.token_hex(3)}"
        _, rec = ca.issue(cn, kind, names, days, out=self.home / folder)
        return 200, {"serial": rec.serial, "common_name": cn, "kind": kind, "folder": folder.as_posix(), "files": ["chain.pem", "key.pem"]}

    @task
    def revoke(self, body):
        ca = self._ca()
        serial = _text(body, "serial", "the serial from the certificate list", 80)
        try:
            ca.revoke(serial, body.get("reason") or "unspecified")
        except CAError as e:
            raise ValueError(str(e) if "serial" in str(e).lower() else f"serial {serial}: {e}") from None
        return 200, {"revoked": serial, "crl": self._crl()}

    @task
    def refresh(self, body):
        self._ca().crl(7)
        return 200, self._crl()

    # --- edges

    def _edges(self):
        f = self.home / "edges.json"
        return json.loads(f.read_text()) if f.exists() else []

    @task
    def add_edge(self, body):
        url = _text(body, "url", "the edge's metrics address, such as http://127.0.0.1:9100", 300).rstrip("/")
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Enter an http or https address, such as http://127.0.0.1:9100")
        with self.lock:
            edges = self._edges()
            if url not in edges:
                if len(edges) >= MAX_EDGES:
                    raise ValueError(f"At most {MAX_EDGES} edges")
                write(self.home / "edges.json", json.dumps(edges + [url]).encode())
        return 200, {"url": url}

    @task
    def remove_edge(self, body):
        url = _text(body, "url", "the edge to remove", 300)
        with self.lock:
            write(self.home / "edges.json", json.dumps([u for u in self._edges() if u != url]).encode())
        return 200, {"removed": url}

    @staticmethod
    def _fetch(url):
        try:
            with urllib.request.urlopen(url + "/status", timeout=3) as r:
                return {"url": url, "status": json.loads(r.read(1 << 20)), "error": None}
        except (OSError, ValueError) as e:
            return {"url": url, "status": None, "error": f"cannot read {url}/status: {explain(e) if isinstance(e, OSError) else 'not an Acxelin TLS edge'}; start the edge with --metrics HOST:PORT"}

    @task
    def edges(self, body):
        urls = self._edges()
        with ThreadPoolExecutor(max_workers=8) as pool:
            return 200, {"edges": list(pool.map(self._fetch, urls))}

    @task
    def test_edge(self, body):
        if not self._exists():
            raise ValueError("There is no certificate authority yet: create one first; the test trusts its certificate")
        host, port = hostport(_text(body, "target", "the edge to test, as host:port", 300), "")
        name = body.get("server_name") or host
        chosen = body.get("policy") or "strict"
        if chosen not in policies.POLICIES:
            raise ValueError("Choose strict, transition or cnsa2")
        ctx = tls.client_context(policies.policy(chosen), self.ca_dir / "ca.crt")
        try:
            with tls.connect(host, port, ctx, name, 5) as c:
                info = c.info()
        finally:
            ctx.close()
        return 200, {k: info.get(k) for k in ("version", "cipher", "group", "peer", "peer_key")}

    # --- health

    @task
    def health(self, body):
        rows = [{k: r[k] for k in ("level", "message", "action")} for r in checks.prerequisites()]
        if self._exists():
            rows += [{"level": level, "message": message, "action": ""} for level, message in checks.ca(self.ca_dir)]
        return 200, {"checks": rows, "version": __version__}


def _is_ip(s):
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def page():
    return shell.render((Path(__file__).parent / "console.html").read_text(encoding="utf-8"))


def build(home, ca_dir=None):
    t = TLSConsole(home, ca_dir)
    routes = {("GET", "/api/status"): t.status, ("POST", "/api/ca/create"): t.create, ("POST", "/api/ca/unlock"): t.unlock,
              ("GET", "/api/certificates"): t.certificates, ("POST", "/api/certificates/issue"): t.issue, ("POST", "/api/certificates/revoke"): t.revoke,
              ("POST", "/api/crl/refresh"): t.refresh, ("GET", "/api/edges"): t.edges, ("POST", "/api/edges/add"): t.add_edge,
              ("POST", "/api/edges/remove"): t.remove_edge, ("POST", "/api/edges/test"): t.test_edge, ("GET", "/api/health"): t.health}
    return core.App(page(), routes)


def run(home, port=8900, open_browser=True, ca_dir=None, host="127.0.0.1"):
    """Start the console and sign this browser in: the launch address carries a single-use ticket in its fragment."""
    import webbrowser
    app = build(home, ca_dir)
    server = core.start(app, home, port, host)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/#{app.sessions.ticket()}"
    if open_browser and webbrowser.open(url):
        print(f"Acxelin TLS console is open in your browser (http://127.0.0.1:{port}). Press Ctrl+C to stop.")
    else:
        core.link_running(port, home)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def cmd_console(a):
    import os
    import sys
    home = Path(a.home or os.environ.get("ACXELIN_TLS_HOME") or Path.home() / ".acxelin-tls")
    if a.action == "link":
        try:
            if core.link_running(a.port, home) is None:
                print("acxelin-tls: console link prints only to a terminal; run it in an interactive session", file=sys.stderr)
        except (OSError, ValueError) as e:
            sys.exit(f"acxelin-tls: no console is running on port {a.port} ({e}); start one with `acxelin-tls console`")
        return 0
    return run(home, a.port, open_browser=not a.no_browser and not a.container, ca_dir=a.ca, host="0.0.0.0" if a.container else "127.0.0.1")


def add(sub):
    p = sub.add_parser("console", help="open the console in your browser; `console link` prints a fresh launch address for a console already running")
    p.set_defaults(func=cmd_console)
    p.add_argument("action", nargs="?", choices=["link"])
    p.add_argument("--port", type=int, default=8900)
    p.add_argument("--home", metavar="DIR", help="where the console keeps the CA, issued certificates and its token (default: ~/.acxelin-tls)")
    p.add_argument("--ca", metavar="DIR", help="manage this CA folder (default: HOME/ca)")
    p.add_argument("--container", action="store_true", help="inside a container: listen on every interface so a published port reaches it (publish it to 127.0.0.1 only)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser; print the launch address instead")
