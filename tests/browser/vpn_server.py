"""The VPN window for the browser tests: a CA, an EST service and a WireGuard gateway (with a stand-in for `wg`) on this
machine, an invitation file to open, and the window on 127.0.0.1:8901 with key "browser-test". Nothing touches the network.
Without OpenSSL 3.5 there is no gateway and no invitation file, and the journey that needs them is skipped."""
import json
import tempfile
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificate

from pqcsuite import tls
from pqcsuite.pki import CA, est
from pqcsuite.vpn import app
from pqcsuite.vpn.wireguard import Gateway, GatewayConfig


class FakeWG:
    def __init__(self):
        self.peers_ = {}

    def set_private_key(self, key, listen_port=None):
        pass

    def set_peer(self, public, psk, allowed_ips, endpoint=None, keepalive=None):
        self.peers_[public] = allowed_ips

    def remove_peer(self, public):
        self.peers_.pop(public)

    def peers(self):
        return {k: {"latest_handshake": 0, "rx_bytes": 0, "tx_bytes": 0} for k in self.peers_}


d = Path(tempfile.mkdtemp())
invitation = Path(__file__).parent / ".fixtures" / "laptop.pqcinvite"
invitation.parent.mkdir(exist_ok=True)
invitation.unlink(missing_ok=True)
try:
    tls.lib()
except tls.OpenSSLUnavailable as e:
    print(f"no gateway for the VPN window journey: {e}")
else:
    ca = CA.init(d / "pki", "VPN Root", passphrase=None)
    ca.issue("localhost", "server", out=d / "gw")
    ca.crl()
    cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24",
                        cert=str(d / "gw" / "chain.pem"), key=str(d / "gw" / "key.pem"), ca=str(d / "pki" / "ca.crt"), crl=str(d / "pki" / "crl.pem"),
                        private_key=str(d / "gw.key"), state=str(d / "state.json"), routes=["192.168.10.0/24"], manage_interface=False).validate()
    gw = Gateway(cfg, FakeWG()).start()
    srv = est.serve(d / "pki", "127.0.0.1:0", d / "gw" / "chain.pem", d / "gw" / "key.pem")
    srv.start()
    invitation.write_text(json.dumps({
        "pqcsuite_invite": 1, "name": "bob", "enroll": f"https://localhost:{srv.port}", "server_name": "localhost",
        "ca_fingerprint": est.fingerprint(load_pem_x509_certificate((d / "pki" / "ca.crt").read_bytes())),
        "gateway": f"127.0.0.1:{gw.server.port}", "expires": "2099-01-01T00:00:00+00:00", "token": est.create_token(ca, "bob", "client", hours=1)}))
window = app.App(folder=d / "vpn", apply=False)
window.token = "browser-test"
app.serve(window, ("127.0.0.1", 8901)).serve_forever()
