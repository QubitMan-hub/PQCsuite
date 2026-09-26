"""A threaded PQC TLS 1.3 server: connection limits, handshake timeouts, CRL checks, certificate hot-reload and stats."""
import logging
import os
import socket
import threading
import time
from collections import Counter

from cryptography import x509

from ..pki import CAError, check_revocation
from .openssl import TLSError

log = logging.getLogger("pqcsuite.tls")


class Revocation:
    """Checks client certificates against a CRL file, re-reading it whenever it changes. Fails closed."""

    def __init__(self, crl_path, ca_path):
        with open(ca_path, "rb") as f:
            self.crl_path, self.cas = crl_path, x509.load_pem_x509_certificates(f.read())
        self.mtime, self.data = None, None

    def check(self, serial, chain=()):
        """`chain` is the verified chain above the certificate, where an intermediate CA's certificate comes from."""
        m = os.stat(self.crl_path).st_mtime
        if m != self.mtime:
            with open(self.crl_path, "rb") as f:
                self.data, self.mtime = f.read(), m
        check_revocation(serial, self.data, self.cas + list(chain))


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts, self.groups, self.active = Counter(), Counter(), 0

    def add(self, key, n=1):
        with self.lock:
            self.counts[key] += n

    def snapshot(self):
        with self.lock:
            return {"active": self.active, **self.counts, "groups": dict(self.groups)}


class Server:
    """Accepts TCP connections, runs the PQC handshake, and hands each verified Connection to `handler(conn, address)`.

    `make_context` is called again whenever a watched file (certificate, key, CA) changes, so renewed certificates take effect
    without a restart. Existing connections keep the context they started with.
    """

    def __init__(self, address, make_context, handler, watch=(), crl=None, ca=None, max_connections=512,
                 handshake_timeout=10.0, name="tls"):
        self.address, self.make_context, self.handler, self.name = address, make_context, handler, name
        self.ctx = make_context()
        self.watch = {p: os.stat(p).st_mtime for p in watch if p}
        self.revocation = Revocation(crl, ca) if crl else None
        self.slots = threading.BoundedSemaphore(max_connections)
        self.handshake_timeout = handshake_timeout
        self.stats = Stats()
        self.stopping = threading.Event()
        self.threads = set()
        self.sock = socket.create_server(address, reuse_port=False, backlog=128)
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]

    def reload_if_changed(self):
        """Rebuild the context when a watched file changed. A missing or broken file keeps the old context serving."""
        try:
            changed = [p for p, m in self.watch.items() if os.stat(p).st_mtime != m]
            if not changed:
                return False
            ctx = self.make_context()
            self.watch = {p: os.stat(p).st_mtime for p in self.watch}
        except (TLSError, OSError, ValueError) as e:
            log.error("%s: keeping the old certificates, reload failed: %s", self.name, e)
            self.stats.add("reload_failed")
            return False
        self.ctx = ctx
        log.info("%s: reloaded certificates after %s changed", self.name, ", ".join(map(str, changed)))
        self.stats.add("reloads")
        return True

    def serve_forever(self):
        log.info("%s: listening on %s:%d", self.name, self.address[0] or "*", self.port)
        last_watch = time.monotonic()
        while not self.stopping.is_set():
            if time.monotonic() - last_watch > 5:
                self.reload_if_changed()
                last_watch = time.monotonic()
            try:
                sock, addr = self.sock.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError as e:
                if self.stopping.is_set():
                    break
                self.stats.add("accept_failed")
                log.error("%s: accept failed, retrying: %s", self.name, e)
                time.sleep(0.5)
                continue
            if not self.slots.acquire(blocking=False):
                self.stats.add("refused_busy")
                log.warning("%s: refusing %s, connection limit reached", self.name, addr[0])
                sock.close()
                continue
            t = threading.Thread(target=self._run, args=(sock, addr, self.ctx), daemon=True)
            self.threads.add(t)
            t.start()

    def _run(self, sock, addr, ctx):
        peer = f"{addr[0]}:{addr[1]}"
        conn = None
        try:
            try:
                conn = ctx.wrap(sock, timeout=self.handshake_timeout)
                cert = conn.peer_certificate()
                if self.revocation and cert:
                    self.revocation.check(cert.serial_number, conn.peer_chain()[1:])
            except (TLSError, CAError, OSError) as e:
                self.stats.add("handshake_failed")
                log.warning("%s: rejected %s: %s", self.name, peer, e)
                return
            info = conn.info()
            with self.stats.lock:
                self.stats.counts["handshakes"] += 1
                self.stats.groups[info["group"]] += 1
                self.stats.active += 1
            log.info("%s: %s %s %s %s peer=%s", self.name, peer, info["version"], info["group"], info["cipher"], info["peer"] or "-")
            try:
                self.handler(conn, addr)
            except (TLSError, OSError) as e:
                log.info("%s: %s closed: %s", self.name, peer, e)
            except Exception:
                self.stats.add("handler_failed")
                log.exception("%s: %s: handler failed", self.name, peer)
            finally:
                with self.stats.lock:
                    self.stats.active -= 1
        finally:
            if conn:
                conn.close()
            else:
                sock.close()
            self.slots.release()
            self.threads.discard(threading.current_thread())

    def start(self):
        t = threading.Thread(target=self.serve_forever, daemon=True, name=self.name)
        t.start()
        return t

    def stop(self, grace=10.0):
        """Stop accepting, then give open connections up to `grace` seconds to finish."""
        self.stopping.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        deadline = time.monotonic() + grace
        for t in list(self.threads):
            t.join(max(0, deadline - time.monotonic()))
