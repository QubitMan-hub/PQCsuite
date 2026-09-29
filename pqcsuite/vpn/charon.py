"""strongSwan's charon, driven through its VICI API: no config files, no parsing of command output."""
import socket
import threading
from urllib.parse import urlparse

from . import PROFILES

try:
    from vici.exception import CommandException
except ImportError:
    CommandException = ()


class CharonError(Exception):
    pass


def connect(uri):
    try:
        import vici
    except ImportError:
        raise CharonError('the site-to-site VPN needs its extra: pip install "pqcsuite[vpn]"') from None
    u = urlparse(uri)
    try:
        if u.scheme == "unix":
            s = socket.socket(socket.AF_UNIX)
            s.connect(u.path)
        elif u.scheme == "tcp":
            s = socket.create_connection((u.hostname, u.port))
        else:
            raise CharonError(f"unsupported VICI address {uri}; use unix:///path or tcp://host:port")
    except OSError as e:
        raise CharonError(f"cannot reach charon at {uri}: {e} (is strongSwan running?)") from None
    s.settimeout(60)
    return vici.Session(s)


def text(v):
    return v.decode() if isinstance(v, bytes) else v


def cipher(sa):
    """The encryption as strongSwan names it in proposals, key size included: AES_GCM_16_256."""
    alg, size = text(sa.get("encr-alg", b"")), text(sa.get("encr-keysize", b""))
    return f"{alg}_{size}" if alg and size else alg


def ppk_pattern(site, peer):
    a, b = sorted((site, peer))
    return f"{a}.{b}.ppk.pqcsuite"


def conn_config(site, peer, ppk_id=None):
    """The VICI load-conn message for one peer. PSK authentication, PPK required, hybrid ML-KEM on IKE and every rekey."""
    ike, esp = PROFILES[peer.profile]
    return {peer.name: {
        "version": 2, "local_addrs": [site.address], "remote_addrs": [peer.address], "proposals": [ike],
        "ppk_id": ppk_id or f"*.{ppk_pattern(site.name, peer.name)}", "ppk_required": "yes",
        "rekey_time": "14400", "reauth_time": "0", "dpd_delay": "30",
        "unique": "replace", "mobike": "no",
        "local": {"auth": "psk", "id": site.name}, "remote": {"auth": "psk", "id": peer.name},
        "children": {"net": {"local_ts": peer.local_subnets, "remote_ts": peer.remote_subnets, "esp_proposals": [esp],
                             "rekey_time": "3600", "dpd_action": "restart" if peer.initiate else "clear",
                             "start_action": "none", "close_action": "none"}},
    }}


class Charon:
    def __init__(self, uri):
        self.uri = uri
        self.session = connect(uri)
        self.lock = threading.Lock()

    def close(self):
        self.session.transport.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _call(self, fn, *args):
        """One request at a time: the session is a single socket shared by the controller's threads and the metrics server."""
        try:
            with self.lock:
                result = fn(*args)
                return list(result) if hasattr(result, "__next__") else result
        except CommandException as e:
            raise CharonError(str(e)) from None

    def version(self):
        v = self._call(self.session.version)
        return f"{text(v['daemon'])} {text(v['version'])}"

    def ml_kem(self):
        """ML-KEM key exchanges this charon supports."""
        return sorted(text(k) for k in self._call(self.session.get_algorithms).get("ke", {}) if text(k).startswith("ML_KEM"))

    def load_keys(self, site, peer, psk, ppk, ppk_id, key_tag):
        self._call(self.session.load_shared, {"id": f"psk-{peer}", "type": "IKE", "data": psk, "owners": [site, peer]})
        self._call(self.session.load_shared, {"id": f"ppk-{peer}-{key_tag}", "type": "PPK", "data": ppk, "owners": [ppk_id]})

    def unload_key(self, key_id):
        self._call(self.session.unload_shared, {"id": key_id})

    def shared_ids(self):
        return [text(k) for k in self._call(self.session.get_shared).get("keys", [])]

    def load_conn(self, config):
        self._call(self.session.load_conn, config)

    def initiate(self, peer, timeout_ms=15000):
        return [text(m.get("msg", b"")) for m in self._call(self.session.initiate, {"ike": peer, "child": "net", "timeout": timeout_ms, "init-limits": "no"})]

    def terminate(self, peer):
        try:
            self._call(self.session.terminate, {"ike": peer, "timeout": 5000, "force": "yes"})
        except CharonError as e:
            if "no matching" not in str(e):
                raise

    def tunnels(self):
        """One dict per IKE SA: who, state, algorithms, whether a PPK was used, and its child SAs with traffic counters."""
        out = []
        for sa in self._call(self.session.list_sas):
            for name, ike in sa.items():
                kes = [text(ike.get(k)) for k in ["dh-group"] + [f"ake{i}" for i in range(1, 8)] if ike.get(k)]
                out.append({
                    "peer": text(name), "state": text(ike["state"]), "remote": text(ike.get("remote-host", b"")),
                    "established_s": int(text(ike.get("established", b"0"))), "encryption": cipher(ike),
                    "key_exchange": " + ".join(kes), "ppk": text(ike.get("ppk", b"no")) == "yes",
                    "children": [{"name": text(cn), "state": text(c["state"]), "encryption": cipher(c),
                                  "bytes_in": int(text(c.get("bytes-in", b"0"))), "bytes_out": int(text(c.get("bytes-out", b"0"))),
                                  "packets_in": int(text(c.get("packets-in", b"0"))), "packets_out": int(text(c.get("packets-out", b"0")))}
                                 for cn, c in ike.get("child-sas", {}).items()],
                })
        return out
