"""During an upgrade a gateway on Acxelin VPN 1.0 agrees keys with one still on PQC Suite 0.4.3, in both directions, over
real post-quantum mutual TLS: the same session gives both sides the same IKE PSK, PPK, PPK id and WireGuard PSK. The 0.4.3 side
is the released code itself, taken from the v0.4.3 tag (or ACXELIN_VPN_OLD, an unpacked 0.4.3 tree), never today's suite."""
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

from acxelin_core import tls
from acxelin_core.pki import CA
from acxelin_core.server import Server

try:
    tls.lib()
except tls.OpenSSLUnavailable as e:
    pytest.skip(str(e), allow_module_level=True)

ROOT = Path(__file__).resolve().parents[2]


def released():
    """The 0.4.3 `pqcsuite` package, first on the path, in place of anything already imported under that name."""
    old = os.environ.get("ACXELIN_VPN_OLD")
    if not old:
        tar = subprocess.run(["git", "archive", "v0.4.3", "pqcsuite"], cwd=ROOT, capture_output=True)
        if tar.returncode:
            pytest.skip(f"the v0.4.3 tag is not here (git fetch --tags): {tar.stderr.decode(errors='replace').strip()}", allow_module_level=True)
        old = tempfile.mkdtemp(prefix="pqcsuite-0.4.3-")
        tarfile.open(fileobj=io.BytesIO(tar.stdout)).extractall(old, filter="data")
    for name in [m for m in sys.modules if m == "pqcsuite" or m.startswith("pqcsuite.")]:
        del sys.modules[name]
    sys.path.insert(0, old)
    import pqcsuite
    assert Path(pqcsuite.__file__).resolve().is_relative_to(Path(old).resolve()) and pqcsuite.__version__ == "0.4.3", pqcsuite.__file__
    if os.environ.get("ACXELIN_OPENSSL"):
        os.environ.setdefault("PQCSUITE_OPENSSL", os.environ["ACXELIN_OPENSSL"])


released()

import acxelin_vpn  # noqa: E402
import pqcsuite.vpn as old_vpn  # noqa: E402
from acxelin_vpn import controller as new_ctl, wireguard as new_wg  # noqa: E402
from acxelin_vpn.policies import POLICY  # noqa: E402
from pqcsuite.vpn import controller as old_ctl, wireguard as old_wg  # noqa: E402


class Charon:
    """Records what a controller would load into strongSwan."""
    def __init__(self):
        self.loaded = []

    def load_keys(self, site, peer, psk, ppk, ppk_id, tag):
        self.loaded.append((psk, ppk, ppk_id, tag))

    def __getattr__(self, name):
        return lambda *a, **k: None


class WG:
    def __init__(self):
        self.peers_ = {}

    def set_private_key(self, key, listen_port=None):
        pass

    def set_peer(self, public, psk, allowed_ips, endpoint=None, keepalive=None):
        self.peers_[public] = psk

    def remove_peer(self, public):
        self.peers_.pop(public)

    def peers(self):
        return {}


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca = CA.init(d / "ca", "VPN Root")
    for name, kind in (("hq.acme", "site"), ("branch.acme", "site"), ("localhost", "server"), ("alice", "client")):
        ca.issue(name, kind, ["127.0.0.1"] if kind == "site" else (), out=d / name)
    (d / "alice" / "ca.crt").write_bytes((d / "ca" / "ca.crt").read_bytes())
    return d


def ipsec(pki, initiator, responder):
    def site(mod, name, other, **kw):
        peer = mod.Peer(other, "127.0.0.1", ["10.1.0.0/16"], ["10.2.0.0/16"], **kw)
        return mod.Site(name, "127.0.0.1", str(pki / name / "chain.pem"), str(pki / name / "key.pem"), str(pki / "ca" / "ca.crt"), peers=[peer])
    r_site = site(responder[0], "hq.acme", "branch.acme")
    r = responder[1].Controller(r_site, charon=Charon())
    server = Server(("127.0.0.1", 0), lambda: tls.server_context(POLICY, r_site.cert, r_site.key, r_site.ca, True), r.respond, name="keyring")
    server.start()
    try:
        i_site = site(initiator[0], "branch.acme", "hq.acme", initiate=True, keyring=f"127.0.0.1:{server.port}")
        i = initiator[1].Controller(i_site, charon=Charon())
        i.agree(i_site.peers[0])
    finally:
        server.stop(1)
    return i.charon.loaded, r.charon.loaded


NEW, OLD = (acxelin_vpn, new_ctl), (old_vpn, old_ctl)


@pytest.mark.parametrize("initiator,responder", [(NEW, OLD), (OLD, NEW)], ids=["new-initiates", "old-initiates"])
def test_ipsec_keys_agree_across_versions(pki, initiator, responder):
    mine, theirs = ipsec(pki, initiator, responder)
    assert len(mine) == len(theirs) == 1 and mine == theirs
    psk, ppk, ppk_id, tag = mine[0]
    assert len(psk) == len(ppk) == 32 and ppk_id == f"{tag}.branch.acme.hq.acme.ppk.pqcsuite"


@pytest.mark.parametrize("client,gateway", [(new_wg, old_wg), (old_wg, new_wg)], ids=["new-client", "old-client"])
def test_wireguard_psk_agrees_across_versions(pki, client, gateway, tmp_path):
    cfg = gateway.GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24",
                                cert=str(pki / "localhost" / "chain.pem"), key=str(pki / "localhost" / "key.pem"),
                                ca=str(pki / "ca" / "ca.crt"), private_key=str(tmp_path / "gw.key"), state=str(tmp_path / "state.json"),
                                routes=["192.168.10.0/24"], users=["alice"], manage_interface=False).validate()
    wg = WG()
    gw = gateway.Gateway(cfg, wg).start()
    try:
        c = client.Client(f"127.0.0.1:{gw.server.port}", pki / "alice", server_name="localhost", apply=False)
        reply, psk = c.agree()
    finally:
        gw.shutdown()
    assert wg.peers_[c.public] == psk and reply["gateway_public"] == gw.public
