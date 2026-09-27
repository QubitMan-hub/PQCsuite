"""Post-quantum WireGuard: remote access for laptops, and site-to-site links, on a WireGuard data plane.

WireGuard's handshake is X25519, but it mixes an optional 32-byte pre-shared key into every handshake. Here that key comes from
post-quantum mutual TLS: the client and the gateway prove who they are with ML-DSA certificates from our CA, agree keys over
X25519MLKEM768, and both derive the PSK from the TLS exporter, bound to both WireGuard public keys. An attacker who later breaks
X25519 still lacks the PSK. The PSK is replaced every few minutes; a client that stops re-agreeing (or whose certificate is
revoked) is removed from the gateway.

Each user (certificate common name) gets a stable address from the pool. A second device with the same certificate replaces
the first. A client listed under `sites` also routes the subnets behind it, which makes the same gateway a site-to-site hub.
"""
import base64
import ipaddress
import json
import logging
import os
import platform
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .. import build, explain, tls
from ..pki import CAError, write
from ..tls import hostport
from ..tls.server import Server
from .controller import TAG, common_name, read_line

log = logging.getLogger("pqcsuite.wireguard")
LABEL = "EXPORTER-pqcsuite-wireguard-v1"
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(data):
    return base64.b64encode(data).decode()


def private_key(path):
    """Load the WireGuard private key at `path`, creating it (owner-only) the first time."""
    path = Path(path)
    if not path.exists():
        k = x25519.X25519PrivateKey.generate()
        write(path, b64(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).encode(), secret=True)
    raw = base64.b64decode(path.read_text().strip())
    return b64(raw), b64(x25519.X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(*RAW))


def valid_key(text):
    try:
        return len(base64.b64decode(text, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def context(gateway, client, tag, client_public, gateway_public):
    return "|".join((gateway, client, tag, client_public, gateway_public)).encode()


class WGError(Exception):
    pass


SECRET = object()


class WG:
    """The `wg` tool, which drives the Linux kernel module and wireguard-go alike. Keys go through an owner-only temp file."""

    def __init__(self, interface, tool="wg"):
        self.interface, self.tool = interface, tool

    def run(self, *args, secret=None):
        name = None
        try:
            if secret:
                fd, name = tempfile.mkstemp()
                with os.fdopen(fd, "w") as f:
                    f.write(secret + "\n")
            r = subprocess.run([self.tool, *(name if a is SECRET else a for a in args)], capture_output=True, text=True, timeout=15)
        finally:
            if name:
                os.unlink(name)
        if r.returncode:
            raise WGError(f"wg {args[0]}: {r.stderr.strip() or r.returncode}")
        return r.stdout

    def set_private_key(self, key, listen_port=None):
        self.run("set", self.interface, "private-key", SECRET, *(["listen-port", str(listen_port)] if listen_port else []), secret=key)

    def set_peer(self, public, psk, allowed_ips, endpoint=None, keepalive=None):
        extra = (["endpoint", endpoint] if endpoint else []) + (["persistent-keepalive", str(keepalive)] if keepalive else [])
        self.run("set", self.interface, "peer", public, "preshared-key", SECRET, "allowed-ips", ",".join(allowed_ips), *extra, secret=psk)

    def remove_peer(self, public):
        self.run("set", self.interface, "peer", public, "remove")

    def peers(self):
        out = {}
        for line in self.run("show", self.interface, "dump").splitlines()[1:]:
            pub, psk, endpoint, allowed, handshake, rx, tx, _ = line.split("\t")
            out[pub] = {"endpoint": None if endpoint == "(none)" else endpoint, "allowed_ips": allowed.split(","), "psk": psk != "(none)",
                        "latest_handshake": int(handshake), "rx_bytes": int(rx), "tx_bytes": int(tx)}
        return out


def ensure_interface(name, address, routes=()):
    """Linux: create the WireGuard interface (kernel module, else wireguard-go), give it its address and routes, bring it up."""
    if platform.system() != "Linux":
        raise WGError("creating interfaces is automatic on Linux only; elsewhere use --config-out and the WireGuard app")
    ip = lambda *a: subprocess.run(["ip", *a], capture_output=True, text=True)
    if ip("link", "show", name).returncode:
        if ip("link", "add", name, "type", "wireguard").returncode:
            go = os.environ.get("PQCSUITE_WIREGUARD_GO") or shutil.which("wireguard-go")
            if not go:
                raise WGError("no WireGuard kernel module and no wireguard-go; install one of them")
            subprocess.run([go, name], capture_output=True, timeout=15, env=os.environ | {"WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD": "1"})
            if ip("link", "show", name).returncode:
                raise WGError(f"wireguard-go did not create {name}")
    for args in (("addr", "replace", address, "dev", name), ("link", "set", name, "up"),
                 *(("route", "replace", r, "dev", name) for r in routes)):
        r = ip(*args)
        if r.returncode:
            raise WGError(f"ip {' '.join(args)}: {r.stderr.strip()}")


@dataclass
class GatewayConfig:
    name: str
    endpoint: str
    keyring_listen: str
    pool: str
    cert: str
    key: str
    ca: str
    crl: str = ""
    key_passphrase_env: str = ""
    interface: str = "wg0"
    listen_port: int = 51820
    private_key: str = "wireguard.key"
    state: str = "wireguard-state.json"
    routes: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    users: list = field(default_factory=list)
    sites: dict = field(default_factory=dict)
    rotate_minutes: float = 2.0
    metrics: str = ""
    manage_interface: bool = True

    @property
    def network(self):
        return ipaddress.ip_network(self.pool)

    @property
    def address(self):
        return next(self.network.hosts())

    def validate(self):
        net = self.network
        if net.num_addresses < 4:
            raise ValueError("pool is too small")
        for r in self.routes + [n for v in self.sites.values() for n in v]:
            if ipaddress.ip_network(r).prefixlen == 0:
                raise ValueError("full-tunnel routes (0.0.0.0/0) are not supported yet; list the networks behind the gateway")
        hostport(self.endpoint)
        hostport(self.keyring_listen)
        if self.rotate_minutes < 0.25:
            raise ValueError("rotate_minutes must be at least 0.25")
        return self


def load_gateway(path):
    with open(path, "rb") as f:
        d = tomllib.load(f).get("wireguard")
    if d is None:
        raise ValueError(f"{path}: missing [wireguard]")
    return build(GatewayConfig, d, "[wireguard]").validate()


class Gateway:
    def __init__(self, cfg, wg=None):
        self.cfg = cfg
        self.wg = wg or WG(cfg.interface)
        self.private, self.public = private_key(cfg.private_key)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.clients = {}
        self.counts = Counter()
        self.leases = json.loads(Path(cfg.state).read_text()) if Path(cfg.state).exists() else {}
        self.server = None

    def lease(self, cn):
        if cn not in self.leases:
            taken = set(self.leases.values()) | {str(self.cfg.address)}
            free = next((str(h) for h in self.cfg.network.hosts() if str(h) not in taken), None)
            if not free:
                raise CAError("the address pool is full")
            self.leases[cn] = free
            write(Path(self.cfg.state), json.dumps(self.leases, indent=1).encode())
        return self.leases[cn]

    def respond(self, conn, addr):
        cert = conn.peer_certificate()
        cn = common_name(cert)
        msg = read_line(conn)
        pub, tag = str(msg.get("public", "")), str(msg.get("tag", ""))
        if (self.cfg.users and cn not in self.cfg.users) or not valid_key(pub) or not TAG.match(tag) or pub == self.public:
            self.counts["refused"] += 1
            log.warning("keyring: refused %s from %s", cn or "unknown", addr[0])
            conn.sendall(b'{"ok": false}\n')
            return
        psk = conn.export(LABEL, context(self.cfg.name, cn, tag, pub, self.public), 32)
        with self.lock:
            try:
                ip = self.lease(cn)
            except CAError as e:
                self.counts["refused"] += 1
                log.warning("keyring: refused %s: %s", cn, e)
                conn.sendall(b'{"ok": false}\n')
                return
            old = self.clients.get(cn)
            self.wg.set_peer(pub, b64(psk), [f"{ip}/32"] + self.cfg.sites.get(cn, []))
            if old and old["public"] != pub:
                self.wg.remove_peer(old["public"])
                self.counts["replaced_devices"] += 1
            self.clients[cn] = {"public": pub, "serial": cert.serial_number, "agreed": time.time(), "address": ip, "tag": tag}
        self.counts["key_agreements"] += 1
        log.info("%s: %s at %s, new PSK %s", cn, "rotated" if old else "connected", ip, tag)
        reply = {"ok": True, "address": f"{ip}/{self.cfg.network.prefixlen}", "gateway": self.cfg.name, "gateway_public": self.public,
                 "endpoint": self.cfg.endpoint, "routes": [str(self.cfg.network)] + self.cfg.routes, "dns": self.cfg.dns,
                 "rotate_s": int(self.cfg.rotate_minutes * 60)}
        conn.sendall(json.dumps(reply).encode() + b"\n")

    def expire(self, revocation=None):
        """Remove clients whose certificate was revoked, and clients that stopped re-agreeing keys."""
        stale = time.time() - 3 * self.cfg.rotate_minutes * 60 - 30
        for cn, c in list(self.clients.items()):
            reason = None
            if revocation:
                try:
                    revocation.check(c["serial"])
                except CAError as e:
                    if "revoked" not in str(e):
                        log.error("CRL problem, keeping clients as they are: %s", e)
                        return
                    reason, key = str(e), "revoked"
            if not reason and c["agreed"] < stale:
                reason, key = "stopped renewing its key", "expired"
            if reason:
                with self.lock:
                    self.wg.remove_peer(c["public"])
                    self.clients.pop(cn)
                self.counts[key] += 1
                log.warning("%s: %s; removed", cn, reason)

    def start(self):
        c = self.cfg
        if c.manage_interface:
            ensure_interface(c.interface, f"{c.address}/{c.network.prefixlen}", [n for v in c.sites.values() for n in v])
        self.wg.set_private_key(self.private, c.listen_port)
        for stale in self.wg.peers():
            self.wg.remove_peer(stale)
        make = lambda: tls.server_context(c.cert, c.key, c.ca, True, "strict", os.environ[c.key_passphrase_env].encode() if c.key_passphrase_env else None)
        self.server = Server(hostport(c.keyring_listen), make, self.respond, watch=[c.cert, c.key, c.ca], crl=c.crl or None,
                             ca=c.ca, max_connections=256, name="keyring")
        self.server.start()

        def watch():
            while not self.stop.wait(min(15, c.rotate_minutes * 30)):
                try:
                    self.expire(self.server.revocation)
                except (WGError, OSError) as e:
                    log.error("expiry check failed: %s", e)
        threading.Thread(target=watch, daemon=True, name="expiry").start()
        return self

    def shutdown(self):
        self.stop.set()
        if self.server:
            self.server.stop(2)

    def status(self):
        peers = self.wg.peers()
        return {cn: {"address": c["address"], "keys_age_s": int(time.time() - c["agreed"]), **peers.get(c["public"], {})}
                for cn, c in self.clients.items()} | {"_events": dict(self.counts)}

    def metrics(self):
        peers, now = self.wg.peers(), time.time()
        lines = ["# TYPE pqcsuite_wireguard_client_up gauge", "# TYPE pqcsuite_wireguard_bytes_total counter",
                 "# TYPE pqcsuite_wireguard_events_total counter"]
        for cn, c in self.clients.items():
            p = peers.get(c["public"], {})
            lines.append(f'pqcsuite_wireguard_client_up{{user="{cn}"}} {int(now - p.get("latest_handshake", 0) < 180)}')
            lines.append(f'pqcsuite_wireguard_bytes_total{{user="{cn}",direction="in"}} {p.get("rx_bytes", 0)}')
            lines.append(f'pqcsuite_wireguard_bytes_total{{user="{cn}",direction="out"}} {p.get("tx_bytes", 0)}')
        lines += [f'pqcsuite_wireguard_events_total{{event="{k}"}} {v}' for k, v in self.counts.items()]
        return "\n".join(lines) + "\n"


class Client:
    """A laptop or branch: agrees a PSK with the gateway, configures WireGuard, and repeats before the PSK goes stale."""

    def __init__(self, keyring, folder, interface="wg0", server_name=None, apply=True, config_out=None, key_passphrase=None, wg=None, ca=None):
        self.host, self.port = hostport(keyring)
        self.server_name = server_name or self.host
        self.dir = Path(folder)
        self.ca = ca or self.dir / "ca.crt"
        self.name = common_name(x509.load_pem_x509_certificate((self.dir / "cert.pem").read_bytes()))
        self.interface, self.apply_, self.config_out, self.passphrase = interface, apply, config_out, key_passphrase
        self.wg = wg or WG(interface)
        self.private, self.public = private_key(self.dir / "wireguard.key")
        self.applied, self.stop = None, threading.Event()

    def agree(self):
        ctx = tls.client_context(self.ca, self.dir / "chain.pem", self.dir / "key.pem", "strict", self.passphrase)
        tag = secrets.token_hex(6)
        with tls.connect(self.host, self.port, ctx, self.server_name, timeout=15) as conn:
            conn.sendall(json.dumps({"v": 1, "public": self.public, "tag": tag}).encode() + b"\n")
            reply = read_line(conn)
            if reply.get("ok") is not True or not valid_key(str(reply.get("gateway_public", ""))):
                raise tls.TLSError("the gateway refused the key agreement (is this certificate allowed?)")
            psk = conn.export(LABEL, context(common_name(conn.peer_certificate()), self.name, tag, self.public, reply["gateway_public"]), 32)
        return reply, b64(psk)

    def apply(self, reply, psk):
        if self.apply_:
            if self.applied != reply["address"]:
                ensure_interface(self.interface, reply["address"], [r for r in reply["routes"] if r != str(ipaddress.ip_interface(reply["address"]).network)])
                self.wg.set_private_key(self.private)
                self.applied = reply["address"]
            self.wg.set_peer(reply["gateway_public"], psk, reply["routes"], reply["endpoint"], 25)
        if self.config_out:
            write(Path(self.config_out), wg_quick(self.private, reply, psk).encode(), secret=True)

    def once(self):
        reply, psk = self.agree()
        self.apply(reply, psk)
        return reply

    def run(self):
        backoff = 5
        while not self.stop.is_set():
            try:
                reply = self.once()
                log.info("connected as %s through %s; next key in %ds", reply["address"], reply["endpoint"], reply["rotate_s"])
                backoff, wait = 5, reply["rotate_s"]
            except (tls.TLSError, WGError, OSError, ValueError, KeyError) as e:
                log.warning("key agreement failed: %s; retrying in %ds", explain(e), backoff)
                wait, backoff = backoff, min(backoff * 2, 60)
            self.stop.wait(wait)


def wg_quick(private, reply, psk):
    """A wg-quick / WireGuard app configuration. Its PSK is only good until the next rotation, so it is for inspection and
    for platforms where `pqcsuite vpn connect --config-out` keeps rewriting it."""
    dns = f"DNS = {', '.join(reply['dns'])}\n" if reply["dns"] else ""
    return (f"[Interface]\nPrivateKey = {private}\nAddress = {reply['address']}\n{dns}\n[Peer]\nPublicKey = {reply['gateway_public']}\n"
            f"PresharedKey = {psk}\nEndpoint = {reply['endpoint']}\nAllowedIPs = {', '.join(reply['routes'])}\nPersistentKeepalive = 25\n")
