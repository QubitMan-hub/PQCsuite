"""Settings changed on a running gateway: some apply in place, others need a restart, and a CRL that is followed needs a local
copy. Moved from the suite's tests/test_changes.py with their assertions."""
import tempfile
import time
import unittest
from pathlib import Path

from acxelin_core.pki import CA
from test_wireguard import FakeWG

from acxelin_vpn import Peer, Site, validate
from acxelin_vpn.wireguard import Gateway, GatewayConfig


class GatewayReconfigureTest(unittest.TestCase):
    def test_users_change_in_place_and_other_settings_need_a_restart(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ca = CA.init(d / "pki", "Root")
            ca.issue("localhost", "server", out=d / "gw")
            cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24",
                                cert=str(d / "gw" / "chain.pem"), key=str(d / "gw" / "key.pem"), ca=str(d / "pki" / "ca.crt"),
                                private_key=str(d / "wg.key"), state=str(d / "state.json"), users=["alice", "bob"], manage_interface=False)
            gw = Gateway(cfg, FakeWG())
            gw.wg.set_peer("pub-bob", "psk", ["10.99.0.3/32"])
            gw.clients["bob"] = {"public": "pub-bob", "serial": 1, "agreed": time.time(), "address": "10.99.0.3", "tag": "t"}
            new = GatewayConfig(**(vars(cfg) | {"users": ["alice"], "dns": ["10.0.0.53"]}))
            self.assertTrue(gw.reconfigure(new))
            self.assertNotIn("bob", gw.clients)
            self.assertNotIn("pub-bob", gw.wg.peers())
            self.assertEqual(gw.cfg.dns, ["10.0.0.53"])
            self.assertFalse(gw.reconfigure(GatewayConfig(**(vars(new) | {"pool": "10.98.0.0/24"}))))


class VPNSettingsTest(unittest.TestCase):
    """VPN settings that follow a CRL need somewhere to keep the copy."""
    url = "http://127.0.0.1:9/crl.pem"

    def test_settings_need_somewhere_to_keep_the_copy(self):
        site = Site("hq", "1.2.3.4", "c", "k", "a", crl_url=self.url, peers=[Peer("b", "5.6.7.8", ["10.0.0.0/24"], ["10.1.0.0/24"], True, "b:7443")])
        with self.assertRaisesRegex(ValueError, "crl_url needs crl"):
            validate(site)
        cfg = GatewayConfig(name="vpn", endpoint="vpn:51820", keyring_listen="0.0.0.0:7443", pool="10.99.0.0/24", cert="c", key="k", ca="a",
                            crl_url=self.url)
        with self.assertRaisesRegex(ValueError, "crl_url needs crl"):
            cfg.validate()
        site.crl, cfg.crl = "copy.pem", "copy.pem"
        site.crl_every = cfg.crl_every = 0
        with self.assertRaisesRegex(ValueError, "crl_every"):
            validate(site)
        with self.assertRaisesRegex(ValueError, "crl_every"):
            cfg.validate()
