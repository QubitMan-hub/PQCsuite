"""Runs one site: agrees keys with each peer over post-quantum mutual TLS, loads them into charon, rotates them, and cuts
tunnels whose peer certificate has been revoked."""
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import Counter

from cryptography.x509.oid import NameOID

from .. import tls
from ..ca import CAError
from ..edge import hostport
from ..tls.server import Revocation, Server
from .charon import Charon, CharonError, conn_config, ppk_pattern

log = logging.getLogger("pqcsuite.vpn")
LABEL = "EXPORTER-pqcsuite-ipsec-v1"
TAG = re.compile(r"^[0-9a-f]{12}$")


def common_name(cert):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else ""


def context(a, b, tag):
    return "|".join(sorted((a, b)) + [tag]).encode()


def read_line(conn, limit=4096):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = conn.recv(limit - len(buf), timeout=10)
        if not chunk or len(buf) + len(chunk) >= limit:
            raise tls.TLSError("key agreement message missing or too long")
        buf += chunk
    return json.loads(buf)


class Controller:
    def __init__(self, site, charon=None):
        self.site = site
        self.charon = charon or Charon(site.vici)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.keys = {p.name: [] for p in site.peers}
        self.serials = {}
        self.last_agreed = {}
        self.counts = Counter()
        self.revocation = Revocation(site.crl, site.ca) if site.crl else None
        self.server = None

    def passphrase(self):
        env = self.site.key_passphrase_env
        return os.environ[env].encode() if env else None

    def install(self, peer, tag, material, cert):
        """Load the PSK and PPK derived from one key agreement; keep the previous PPK so SAs being rebuilt still find it."""
        psk, ppk = material[:32], material[32:]
        ppk_id = f"{tag}.{ppk_pattern(self.site.name, peer.name)}"
        with self.lock:
            self.charon.load_keys(self.site.name, peer.name, psk, ppk, ppk_id, tag)
            if peer.initiate:
                self.charon.load_conn(conn_config(self.site, peer, ppk_id))
            self.keys[peer.name].append(tag)
            for old in self.keys[peer.name][:-2]:
                self.charon.unload_key(f"ppk-{peer.name}-{old}")
            self.keys[peer.name] = self.keys[peer.name][-2:]
        self.serials[peer.name] = cert.serial_number
        self.last_agreed[peer.name] = time.time()
        self.counts["key_agreements"] += 1
        log.info("%s: new keys %s (PSK + PPK from ML-DSA mutual TLS)", peer.name, tag)

    def agree(self, peer):
        """Initiator side: connect to the peer's keyring, prove who we are, derive the keys, wait for the peer to confirm."""
        ctx = tls.client_context(self.site.ca, self.site.cert, self.site.key, "strict", self.passphrase())
        with tls.connect(*hostport(peer.keyring, peer.address), ctx, server_name=peer.name, timeout=10) as conn:
            cert = conn.peer_certificate()
            if common_name(cert) != peer.name:
                raise tls.TLSError(f"{peer.keyring} presented {common_name(cert)!r}, expected {peer.name!r}")
            if self.revocation:
                self.revocation.check(cert.serial_number)
            tag = secrets.token_hex(6)
            conn.sendall(json.dumps({"v": 1, "site": self.site.name, "tag": tag}).encode() + b"\n")
            material = conn.export(LABEL, context(self.site.name, peer.name, tag), 64)
            if read_line(conn).get("ok") is not True:
                raise tls.TLSError(f"{peer.name} refused the key agreement")
        self.install(peer, tag, material, cert)
        return tag

    def respond(self, conn, addr):
        """Responder side, called by the keyring server after mutual TLS and the CRL check succeeded."""
        cert = conn.peer_certificate()
        name = common_name(cert)
        peer = self.site.peer(name)
        msg = read_line(conn)
        if not peer or peer.initiate or msg.get("site") != name or not TAG.match(str(msg.get("tag", ""))):
            self.counts["key_agreements_refused"] += 1
            log.warning("keyring: refused %s from %s", name or "unknown", addr[0])
            conn.sendall(b'{"ok": false}\n')
            return
        self.install(peer, msg["tag"], conn.export(LABEL, context(self.site.name, name, msg["tag"]), 64), cert)
        conn.sendall(b'{"ok": true}\n')

    def tunnel(self, name):
        """The newest IKE SA with this peer; during a rotation the old one lingers until the responder replaces it."""
        with self.lock:
            return min((t for t in self.charon.tunnels() if t["peer"] == name), key=lambda t: t["established_s"], default=None)

    def initiator_loop(self, peer):
        rotate, backoff = peer.rotate_minutes * 60, 5
        while not self.stop.is_set():
            t = self.tunnel(peer.name)
            due = time.time() - self.last_agreed.get(peer.name, 0) >= rotate
            if due or not t or t["state"] != "ESTABLISHED":
                try:
                    self.agree(peer)
                    with self.lock:
                        self.charon.initiate(peer.name)
                    self.counts["rotations" if t else "connects"] += 1
                    backoff = 5
                except (tls.TLSError, CAError, CharonError, OSError, ValueError) as e:
                    self.counts["failures"] += 1
                    log.warning("%s: %s; retrying in %ds", peer.name, e, backoff)
                    self.stop.wait(backoff)
                    backoff = min(backoff * 2, 300)
                    continue
            self.stop.wait(min(30, rotate))

    def enforce_revocations(self):
        """Cut the tunnel and drop the keys of any peer whose certificate appears on the CRL."""
        if not self.revocation:
            return
        for name, serial in list(self.serials.items()):
            try:
                self.revocation.check(serial)
            except CAError as e:
                if "revoked" not in str(e):
                    log.error("CRL problem, keeping tunnels as they are: %s", e)
                    return
                log.warning("%s: %s; closing its tunnel and discarding its keys", name, e)
                with self.lock:
                    self.charon.terminate(name)
                    for tag in self.keys[name]:
                        self.charon.unload_key(f"ppk-{name}-{tag}")
                    self.charon.unload_key(f"psk-{name}")
                    self.keys[name] = []
                self.serials.pop(name)
                self.counts["revoked_peers"] += 1

    def start(self):
        s = self.site
        log.info("%s: charon %s, ML-KEM available: %s", s.name, self.charon.version(), ", ".join(self.charon.ml_kem()) or "none")
        if not self.charon.ml_kem():
            raise CharonError("this strongSwan has no ML-KEM; build 6.0.2+ with the openssl (OpenSSL 3.5+) or ml plugin")
        for p in s.peers:
            if not p.initiate:
                self.charon.load_conn(conn_config(s, p))
        if s.keyring_listen:
            make = lambda: tls.server_context(s.cert, s.key, s.ca, True, "strict", self.passphrase())
            self.server = Server(hostport(s.keyring_listen), make, self.respond, watch=[s.cert, s.key, s.ca], crl=s.crl or None,
                                 ca=s.ca, max_connections=64, name="keyring")
            self.server.start()
        for p in s.peers:
            if p.initiate:
                threading.Thread(target=self.initiator_loop, args=(p,), daemon=True, name=p.name).start()

        def watch():
            while not self.stop.wait(15):
                try:
                    self.enforce_revocations()
                except (CharonError, OSError) as e:
                    log.error("revocation check failed: %s", e)
        threading.Thread(target=watch, daemon=True, name="revocations").start()

    def shutdown(self):
        self.stop.set()
        if self.server:
            self.server.stop(2)

    def status(self):
        tunnels = {t["peer"]: t for t in self.charon.tunnels()}
        return {p.name: {"initiate": p.initiate, "profile": p.profile, "keys_age_s": int(time.time() - self.last_agreed[p.name])
                         if p.name in self.last_agreed else None, "tunnel": tunnels.get(p.name)} for p in self.site.peers} | {
            "_events": dict(self.counts)}

    def metrics(self):
        lines = ["# TYPE pqcsuite_vpn_tunnel_up gauge", "# TYPE pqcsuite_vpn_bytes_total counter", "# TYPE pqcsuite_vpn_events_total counter"]
        tunnels = {t["peer"]: t for t in self.charon.tunnels()}
        for p in self.site.peers:
            t = tunnels.get(p.name)
            up = int(bool(t and t["state"] == "ESTABLISHED" and t["ppk"]))
            lines.append(f'pqcsuite_vpn_tunnel_up{{peer="{p.name}"}} {up}')
            for c in (t or {}).get("children", []):
                lines.append(f'pqcsuite_vpn_bytes_total{{peer="{p.name}",direction="in"}} {c["bytes_in"]}')
                lines.append(f'pqcsuite_vpn_bytes_total{{peer="{p.name}",direction="out"}} {c["bytes_out"]}')
        lines += [f'pqcsuite_vpn_events_total{{event="{k}"}} {v}' for k, v in self.counts.items()]
        return "\n".join(lines) + "\n"
