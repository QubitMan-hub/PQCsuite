"""Fleet management: agents report to a central service over post-quantum mutual TLS and run the edge routes it assigns them.

The fleet service keeps each agent's last report in `<dir>/agents/<name>.json` and serves the desired edge configuration from
`<dir>/desired/<name>.toml` (or `desired/default.toml`). Configuration is validated on both sides; an agent that receives a
broken one keeps running the last good one and says so in its next report.
"""
import hashlib
import json
import logging
import os
import platform
import socket
import tempfile
import threading
import time
from pathlib import Path

from . import __version__, tls
from .ca import write
from .edge import Edge, hostport, load_config
from .tls.http import HTTPError, handler, request
from .tls.server import Server

log = logging.getLogger("pqcsuite.fleet")


def validate_config(text):
    """Parse an edge TOML document as the agent would; raises ValueError with the reason."""
    if not text.strip():
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as f:
        f.write(text)
    try:
        routes, _ = load_config(f.name)
        for r in routes:
            r.validate()
        return routes
    finally:
        os.unlink(f.name)


def _name(conn):
    from .vpn.controller import common_name
    cert = conn.peer_certificate()
    return common_name(cert) if cert else ""


class Service:
    def __init__(self, root):
        self.root = Path(root)
        (self.root / "agents").mkdir(parents=True, exist_ok=True)
        (self.root / "desired").mkdir(parents=True, exist_ok=True)

    def desired(self, name):
        for f in (self.root / "desired" / f"{name}.toml", self.root / "desired" / "default.toml"):
            if f.exists():
                return f.read_text(encoding="utf-8")
        return ""

    def set_desired(self, name, text):
        validate_config(text)
        if not name.replace("-", "").replace(".", "").replace("_", "").isalnum():
            raise ValueError("agent names are letters, digits, dots, dashes and underscores")
        write(self.root / "desired" / f"{name}.toml", text.encode())

    def __call__(self, method, path, headers, body, conn):
        name = _name(conn)
        if not name:
            raise HTTPError(401, "agents must present a certificate")
        if (method, path) != ("POST", "/v1/report"):
            raise HTTPError(404, "no such endpoint")
        try:
            report = json.loads(body)
        except ValueError:
            raise HTTPError(400, "the report must be JSON") from None
        report = {k: report.get(k) for k in ("hostname", "version", "platform", "config", "config_error", "edges", "certificate", "interval")}
        report |= {"name": name, "last_seen": time.time(), "address": conn.sock.getpeername()[0]}
        write(self.root / "agents" / f"{name}.json", json.dumps(report, default=str).encode())
        text = self.desired(name)
        out = {"config": text, "config_version": hashlib.sha256(text.encode()).hexdigest()[:16]}
        return 200, json.dumps(out).encode(), {"Content-Type": "application/json"}

    def agents(self):
        out = []
        for f in sorted((self.root / "agents").glob("*.json")):
            a = json.loads(f.read_text(encoding="utf-8"))
            a["online"] = time.time() - a["last_seen"] < 3 * (a.get("interval") or 30)
            a["desired_version"] = hashlib.sha256(self.desired(a["name"]).encode()).hexdigest()[:16]
            a["in_sync"] = a.get("config") == a["desired_version"] and not a.get("config_error")
            out.append(a)
        return out


def serve(root, listen, cert, key, ca, crl=None, key_passphrase=None):
    make = lambda: tls.server_context(cert, key, ca, True, "strict", key_passphrase, any_purpose=True)
    return Server(hostport(listen), make, handler(Service(root)), watch=[cert, key, ca], crl=crl, ca=ca, name="fleet")


class Agent:
    """Reports to the fleet service every `interval` seconds and runs the edge routes it is given."""

    def __init__(self, url, cert_dir, interval=30, server_name=None):
        from .est import _target
        self.host, self.port = _target(url)
        self.server_name = server_name or self.host
        self.dir = Path(cert_dir)
        self.interval = interval
        self.edges, self.version, self.error = {}, "", ""
        self.stop = threading.Event()

    def context(self):
        return tls.client_context(self.dir / "ca.crt", self.dir / "chain.pem", self.dir / "key.pem")

    def report(self):
        from cryptography import x509
        cert = x509.load_pem_x509_certificate((self.dir / "cert.pem").read_bytes())
        return {"hostname": socket.gethostname(), "version": __version__, "platform": platform.platform(), "interval": self.interval,
                "config": self.version, "config_error": self.error,
                "certificate": {"serial": format(cert.serial_number, "x"), "expires": cert.not_valid_after_utc.isoformat()},
                "edges": {n: {"mode": e.route.mode, "listen": e.route.listen, "target": e.route.target, **e.stats.snapshot()}
                          for n, e in self.edges.items()}}

    def apply(self, text, version):
        if version == self.version:
            return
        self.error = ""
        try:
            routes = validate_config(text)
        except (ValueError, OSError) as e:
            self.error = f"kept config {self.version or 'none'}: new config {version} is invalid: {e}"
            log.error("%s", self.error)
            return
        wanted = {r.name: r for r in routes}
        for name in list(self.edges):
            if wanted.get(name) != self.edges[name].route:
                self.edges.pop(name).stop()
        for name, route in wanted.items():
            if name not in self.edges:
                try:
                    self.edges[name] = Edge(route).start()
                except (tls.TLSError, OSError, ValueError) as e:
                    self.error = f"route {name} did not start: {e}"
                    log.error("%s", self.error)
        self.version = version
        log.info("applied config %s: %d route(s)", version, len(wanted))

    def once(self):
        with tls.connect(self.host, self.port, self.context(), self.server_name, timeout=15) as conn:
            status, _, body = request(conn, "POST", "/v1/report", self.host, json.dumps(self.report(), default=str).encode(),
                                      {"Content-Type": "application/json"})
        if status != 200:
            raise tls.TLSError(f"fleet service said {status}: {body.decode(errors='replace')}")
        reply = json.loads(body)
        self.apply(reply["config"], reply["config_version"])

    def run(self):
        while not self.stop.is_set():
            try:
                self.once()
            except (tls.TLSError, HTTPError, OSError, ValueError) as e:
                log.warning("report failed: %s", e)
            self.stop.wait(self.interval)

    def shutdown(self):
        self.stop.set()
        for e in self.edges.values():
            e.stop()
