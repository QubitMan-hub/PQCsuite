"""The edge: post-quantum TLS in front of any TCP service, and a tunnel that lets legacy clients reach one.

terminate  PQC TLS clients -> edge -> plain TCP upstream (a web server, database, MQTT broker...)
originate  plain local clients -> edge -> PQC TLS remote (usually another edge in terminate mode)
"""
import json
import logging
import os
import selectors
import socket
import subprocess
import sys
import threading
import time
import tomllib
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import HTTP_IDLE, build, explain, tls
from . import hostport
from .server import Server, Stats

log = logging.getLogger("pqcsuite.edge")


@dataclass
class Route:
    name: str
    mode: str
    listen: str
    target: str
    policy: str = "strict"
    cert: str = ""
    key: str = ""
    key_passphrase_env: str = ""
    ca: str = ""
    require_client_cert: bool = False
    crl: str = ""
    server_name: str = ""
    proxy_protocol: bool = False
    max_connections: int = 512
    idle_timeout: float = 3600.0
    handshake_timeout: float = 10.0
    fallback_cert: str = ""
    fallback_key: str = ""

    def passphrase(self):
        if not self.key_passphrase_env:
            return None
        if self.key_passphrase_env not in os.environ:
            raise ValueError(f"{self.name}: environment variable {self.key_passphrase_env} is not set")
        return os.environ[self.key_passphrase_env].encode()

    def validate(self):
        if self.mode not in ("terminate", "originate"):
            raise ValueError(f"{self.name}: mode must be terminate or originate")
        hostport(self.listen), hostport(self.target)
        if self.mode == "terminate" and not (self.cert and self.key):
            raise ValueError(f"{self.name}: terminate needs cert and key")
        if bool(self.fallback_cert) != bool(self.fallback_key):
            raise ValueError(f"{self.name}: fallback_cert and fallback_key go together")
        if self.fallback_cert and (self.mode != "terminate" or self.policy != "transition"):
            raise ValueError(f"{self.name}: a fallback certificate is for terminate routes with policy = \"transition\"")
        if self.mode == "originate" and not self.ca:
            raise ValueError(f"{self.name}: originate needs the ca that signed the remote's certificate")
        tls.policy(self.policy)


def pump(conn, raw, idle_timeout):
    """Copy bytes both ways between a TLS connection and a plain socket until either side closes or goes idle."""
    raw.settimeout(idle_timeout)
    with selectors.DefaultSelector() as sel:
        sel.register(conn.sock, selectors.EVENT_READ, "tls")
        sel.register(raw, selectors.EVENT_READ, "raw")
        while True:
            ready = {"tls"} if conn.pending() else {k.data for k, _ in sel.select(idle_timeout)}
            if not ready:
                raise TimeoutError(f"idle for {idle_timeout:g}s")
            if "tls" in ready:
                data = conn.recv(wait=False)
                if data == b"":
                    return
                if data:
                    raw.sendall(data)
            if "raw" in ready:
                data = raw.recv(65536)
                if not data:
                    return
                conn.sendall(data)


def proxy_header(client, local):
    fam = "TCP6" if ":" in client[0] else "TCP4"
    return f"PROXY {fam} {client[0]} {local[0]} {client[1]} {local[1]}\r\n".encode()


class Edge:
    def __init__(self, route):
        route.validate()
        self.route = route
        self.stats = Stats()
        self.server = self.listener = None

    def bind(self, reuse_port=False):
        """Open the listening socket now, so start() and stop() cannot race the serving thread."""
        r = self.route
        if r.mode == "terminate":
            fallback = (r.fallback_cert, r.fallback_key) if r.fallback_cert else None
            make = lambda: tls.server_context(r.cert, r.key, r.ca or None, r.require_client_cert, r.policy, r.passphrase(), fallback=fallback)
            self.server = Server(hostport(r.listen), make, self._terminate, watch=[r.cert, r.key, r.ca, r.fallback_cert, r.fallback_key], crl=r.crl or None,
                                 ca=r.ca or None, max_connections=r.max_connections, handshake_timeout=r.handshake_timeout, name=r.name,
                                 reuse_port=reuse_port)
            self.stats = self.server.stats
            self.port = self.server.port
        else:
            self.watch = [p for p in (r.ca, r.cert, r.key) if p]
            self.mtimes = [os.stat(p).st_mtime for p in self.watch]
            self.ctx = tls.client_context(r.ca, r.cert or None, r.key or None, r.policy, r.passphrase())
            self.listener = socket.create_server(hostport(r.listen, "127.0.0.1"), backlog=128, reuse_port=reuse_port)
            self.port = self.listener.getsockname()[1]
            log.info("%s: listening on %s, tunnelling to %s", r.name, r.listen, r.target)
        return self

    def serve_forever(self):
        if not (self.server or self.listener):
            self.bind()
        if self.server:
            self.server.serve_forever()
        else:
            self._originate_forever()

    def start(self):
        self.bind()
        threading.Thread(target=self.serve_forever, daemon=True, name=self.route.name).start()
        return self

    def _terminate(self, conn, addr):
        r = self.route
        try:
            up = socket.create_connection(hostport(r.target), timeout=r.handshake_timeout)
        except OSError as e:
            self.stats.add("upstream_failed")
            log.warning("%s: upstream %s unreachable: %s", r.name, r.target, explain(e))
            return
        with up:
            if r.proxy_protocol:
                up.sendall(proxy_header(addr, conn.sock.getsockname()))
            pump(conn, up, r.idle_timeout)

    def client_context(self):
        """The originate context, rebuilt when its certificate, key or CA changed (renewals need no restart)."""
        r = self.route
        try:
            mtimes = [os.stat(p).st_mtime for p in self.watch]
            if mtimes != self.mtimes:
                self.ctx = tls.client_context(r.ca, r.cert or None, r.key or None, r.policy, r.passphrase())
                self.mtimes = mtimes
                self.stats.add("reloads")
                log.info("%s: reloaded certificates", r.name)
        except (tls.TLSError, OSError, ValueError) as e:
            self.stats.add("reload_failed")
            log.error("%s: keeping the old certificates, reload failed: %s", r.name, e)
        return self.ctx

    def _originate_forever(self):
        r, host_port = self.route, hostport(self.route.target)
        slots = threading.BoundedSemaphore(r.max_connections)

        def run(client):
            try:
                with tls.connect(*host_port, self.client_context(), r.server_name or host_port[0], r.handshake_timeout) as conn:
                    info = conn.info()
                    with self.stats.lock:
                        self.stats.counts["handshakes"] += 1
                        self.stats.groups[info["group"]] += 1
                        self.stats.active += 1
                    try:
                        pump(conn, client, r.idle_timeout)
                    finally:
                        with self.stats.lock:
                            self.stats.active -= 1
            except (tls.TLSError, OSError) as e:
                self.stats.add("handshake_failed")
                log.warning("%s: tunnel to %s failed: %s", r.name, r.target, explain(e))
            finally:
                client.close()
                slots.release()

        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            if not slots.acquire(blocking=False):
                self.stats.add("refused_busy")
                client.close()
                continue
            threading.Thread(target=run, args=(client,), daemon=True).start()

    def stop(self):
        if self.server:
            self.server.stop()
        elif self.listener:
            try:
                self.listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.listener.close()


def load_config(path):
    """Read [[edge]] routes from a TOML file."""
    with open(path, "rb") as f:
        doc = tomllib.load(f)
    routes = []
    for i, e in enumerate(doc.get("edge", [])):
        routes.append(build(Route, {"name": f"edge{i + 1}", **e}, f"edge #{i + 1}"))
    if not routes:
        raise ValueError(f"{path} has no [[edge]] sections")
    return routes, doc.get("metrics", {}).get("listen")


WORKER = "PQCSUITE_EDGE_WORKER"


class Workers:
    """Copies of this edge in other processes, sharing its ports through SO_REUSEPORT (Linux), restarted when one exits.

    Each worker prints its stats as a JSON line every second, so /metrics and /status add up across processes, and
    exits when that write fails because the parent is gone.
    """

    def __init__(self, n):
        self.argv = [sys.executable, "-m", "pqcsuite", *sys.argv[1:]]
        self.reports, self.stopping = {}, False
        self.procs = [self._start() for _ in range(n - 1)]
        threading.Thread(target=self._supervise, daemon=True).start()

    def _start(self):
        p = subprocess.Popen(self.argv, stdout=subprocess.PIPE, text=True, env={**os.environ, WORKER: "1"})
        threading.Thread(target=self._read, args=(p,), daemon=True).start()
        return p

    def _read(self, p):
        for line in p.stdout:
            try:
                self.reports[p.pid] = json.loads(line)
            except ValueError:
                pass
        for s in self.reports.get(p.pid, {}).values():
            s["active"] = 0

    def _supervise(self):
        while not self.stopping:
            time.sleep(1)
            for i, p in enumerate(self.procs):
                if p.poll() is not None and not self.stopping:
                    log.error("worker %d exited with status %s, starting another", p.pid, p.returncode)
                    self.procs[i] = self._start()

    def stop(self):
        self.stopping = True
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            p.wait()


def report(edges):
    """The worker side of Workers."""
    try:
        while True:
            time.sleep(1)
            print(json.dumps({e.route.name: e.stats.snapshot() for e in edges}), flush=True)
    except OSError:
        os._exit(0)


def totals(edge, workers=None):
    s = edge.stats.snapshot()
    for rep in list(workers.reports.values()) if workers else ():
        for k, v in rep.get(edge.route.name, {}).items():
            if k == "groups":
                for g, c in v.items():
                    s["groups"][g] = s["groups"].get(g, 0) + c
            else:
                s[k] = s.get(k, 0) + v
    return s


def metrics_text(edges, workers=None):
    lines = ["# TYPE pqcsuite_connections_active gauge", "# TYPE pqcsuite_events_total counter", "# TYPE pqcsuite_group_total counter"]
    for e in edges:
        s, n = totals(e, workers), e.route.name
        lines.append(f'pqcsuite_connections_active{{edge="{n}"}} {s.pop("active")}')
        for g, c in s.pop("groups").items():
            lines.append(f'pqcsuite_group_total{{edge="{n}",group="{g}"}} {c}')
        lines += [f'pqcsuite_events_total{{edge="{n}",event="{k}"}} {v}' for k, v in s.items()]
    return "\n".join(lines) + "\n"


def serve_metrics(address, edges, workers=None):
    class Handler(BaseHTTPRequestHandler):
        timeout = HTTP_IDLE

        def do_GET(self):
            if self.path == "/healthz":
                body, ctype = b"ok\n", "text/plain"
            elif self.path == "/metrics":
                body, ctype = metrics_text(edges, workers).encode(), "text/plain; version=0.0.4"
            elif self.path == "/status":
                body, ctype = json.dumps({e.route.name: {"mode": e.route.mode, "listen": e.route.listen, "target": e.route.target,
                                                         "policy": e.route.policy, **totals(e, workers)} for e in edges}).encode(), "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(hostport(address, "127.0.0.1"), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    log.info("metrics on http://%s:%d/metrics", *httpd.server_address[:2])
    return httpd
