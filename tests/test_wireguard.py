"""WireGuard remote access. The unit tests run the real key agreement over post-quantum TLS against a stand-in for `wg`. The
integration test puts a gateway and a laptop in network namespaces with real WireGuard (kernel module, or wireguard-go named
by PQCSUITE_WIREGUARD_GO) and sends traffic through; it needs root, iproute2 and wireguard-tools."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from pqcsuite import tls
from pqcsuite.pki import CA
from pqcsuite.vpn.wireguard import Client, Gateway, GatewayConfig, private_key

try:
    tls.lib()
    REASON = None
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


class FakeWG:
    def __init__(self):
        self.peers_, self.private = {}, None

    def set_private_key(self, key, listen_port=None):
        self.private = key

    def set_peer(self, public, psk, allowed_ips, endpoint=None, keepalive=None):
        self.peers_[public] = {"psk": psk, "allowed_ips": allowed_ips, "endpoint": endpoint}

    def remove_peer(self, public):
        self.peers_.pop(public)

    def peers(self):
        return {k: {"latest_handshake": 0, "rx_bytes": 0, "tx_bytes": 0} for k in self.peers_}


class ConfigTest(unittest.TestCase):
    def config(self, **kw):
        return GatewayConfig(**({"name": "vpn", "endpoint": "vpn:51820", "keyring_listen": "0.0.0.0:7443", "pool": "10.99.0.0/24",
                                 "cert": "c", "key": "k", "ca": "a"} | kw))

    def test_validation(self):
        self.assertEqual(str(self.config().validate().address), "10.99.0.1")
        for bad in ({"routes": ["0.0.0.0/0"]}, {"pool": "10.0.0.0/31"}, {"rotate_minutes": 0.1}, {"sites": {"b": ["nope"]}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.config(**bad).validate()


@unittest.skipIf(REASON, REASON)
class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = Path(self.tmp.name)
        self.ca = CA.init(d / "pki", "VPN Root")
        self.ca.issue("localhost", "server", out=d / "gw")
        self.ca.crl()
        self.recs = {}
        for who in ("alice", "bob", "branch", "mallory"):
            _, self.recs[who] = self.ca.issue(who, "client", out=d / who)
            (d / who / "ca.crt").write_bytes((d / "pki" / "ca.crt").read_bytes())
        self.cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24",
                                 cert=str(d / "gw" / "chain.pem"), key=str(d / "gw" / "key.pem"), ca=str(d / "pki" / "ca.crt"),
                                 crl=str(d / "pki" / "crl.pem"), private_key=str(d / "gw.key"), state=str(d / "state.json"),
                                 routes=["192.168.10.0/24"], users=["alice", "bob", "branch"], sites={"branch": ["192.168.20.0/24"]},
                                 manage_interface=False).validate()
        self.wg = FakeWG()
        self.gw = Gateway(self.cfg, self.wg).start()
        self.addCleanup(self.gw.shutdown)

    def tearDown(self):
        self.tmp.cleanup()

    def client(self, who, folder=None):
        return Client(f"127.0.0.1:{self.gw.server.port}", folder or self.d / who, server_name="localhost", apply=False,
                      config_out=self.d / f"{who}.conf")

    def test_both_sides_hold_the_same_psk_and_addresses_are_stable(self):
        alice = self.client("alice")
        reply, psk = alice.agree()
        self.assertEqual(reply["address"], "10.99.0.2/24")
        self.assertEqual(reply["routes"], ["10.99.0.0/24", "192.168.10.0/24"])
        self.assertEqual(reply["gateway_public"], self.gw.public)
        self.assertEqual(self.wg.peers_[alice.public], {"psk": psk, "allowed_ips": ["10.99.0.2/32"], "endpoint": None})
        self.assertEqual(self.client("bob").agree()[0]["address"], "10.99.0.3/24")
        reply2, psk2 = alice.agree()
        self.assertEqual(reply2["address"], "10.99.0.2/24")
        self.assertNotEqual(psk, psk2)
        self.assertEqual(self.wg.peers_[alice.public]["psk"], psk2)
        alice.apply(reply2, psk2)
        self.assertIn(f"PresharedKey = {psk2}", (self.d / "alice.conf").read_text())
        self.assertEqual(Gateway(self.cfg, FakeWG()).lease("alice"), "10.99.0.2")

    def test_sites_route_their_subnets(self):
        b = self.client("branch")
        b.agree()
        self.assertEqual(self.wg.peers_[b.public]["allowed_ips"], ["10.99.0.2/32", "192.168.20.0/24"])

    def test_users_outside_the_list_are_refused(self):
        with self.assertRaisesRegex(tls.TLSError, "refused"):
            self.client("mallory").agree()
        self.assertEqual(self.wg.peers_, {})

    def test_a_new_device_replaces_the_old_one(self):
        first = self.client("alice")
        first.agree()
        laptop2 = self.d / "alice2"
        shutil.copytree(self.d / "alice", laptop2)
        (laptop2 / "wireguard.key").unlink()
        second = self.client("alice", laptop2)
        second.agree()
        self.assertNotEqual(first.public, second.public)
        self.assertEqual(list(self.wg.peers_), [second.public])

    def test_revoked_and_silent_clients_are_removed(self):
        alice, bob = self.client("alice"), self.client("bob")
        alice.agree()
        bob.agree()
        self.ca.revoke(self.recs["alice"].serial, "keyCompromise")
        time.sleep(0.05)
        self.gw.expire(self.gw.server.revocation)
        self.assertEqual(list(self.wg.peers_), [bob.public])
        with self.assertRaises((tls.TLSError, OSError)):
            alice.agree()
        self.gw.clients["bob"]["agreed"] -= 3600
        self.gw.expire(self.gw.server.revocation)
        self.assertEqual(self.wg.peers_, {})
        self.assertEqual(self.gw.counts["revoked"], 1)
        self.assertEqual(self.gw.counts["expired"], 1)
        self.assertIn('pqcsuite_wireguard_events_total{event="revoked"} 1', self.gw.metrics())

    def test_private_key_is_kept(self):
        self.assertEqual(private_key(self.d / "gw.key"), (self.gw.private, self.gw.public))

    def test_restart_forgets_every_old_peer(self):
        self.client("alice").agree()
        wg = FakeWG()
        wg.peers_ = dict(self.wg.peers_)
        self.gw.shutdown()
        self.gw = Gateway(self.cfg, wg).start()
        self.addCleanup(self.gw.shutdown)
        self.assertEqual(wg.peers_, {}, "a peer from before the restart would never be checked against the CRL again")

    def test_full_pool_refuses_cleanly(self):
        self.gw.cfg.pool = "10.98.0.0/30"
        self.client("alice").agree()
        with self.assertRaisesRegex(tls.TLSError, "refused"):
            self.client("bob").agree()


def wireguard_available():
    if not (sys.platform == "linux" and os.geteuid() == 0 and shutil.which("ip") and shutil.which("wg")):
        return False
    if os.environ.get("PQCSUITE_WIREGUARD_GO"):
        return True
    ok = subprocess.run(["ip", "link", "add", "pqcwgprobe", "type", "wireguard"], capture_output=True).returncode == 0
    subprocess.run(["ip", "link", "del", "pqcwgprobe"], capture_output=True)
    return ok


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


@unittest.skipUnless(not REASON and wireguard_available(), "needs root, iproute2, wireguard-tools and WireGuard (kernel or PQCSUITE_WIREGUARD_GO)")
class RemoteAccessTest(unittest.TestCase):
    """gateway (10.40.0.1, LAN 192.168.10.1) <- laptop (10.40.0.2) over WireGuard with a PSK from ML-DSA mutual TLS."""

    def setUp(self):
        self.d = d = Path(tempfile.mkdtemp())
        self.procs = []
        self.addCleanup(self.teardown)
        self.ca = CA.init(d / "pki", "VPN Root")
        self.ca.issue("vpn.acme", "server", ["10.40.0.1"], out=d / "gw")
        _, self.laptop = self.ca.issue("alice", "client", out=d / "alice")
        (d / "alice" / "ca.crt").write_bytes((d / "pki" / "ca.crt").read_bytes())
        self.ca.crl()
        sh("ip", "netns", "add", "pqc-wgs")
        sh("ip", "netns", "add", "pqc-wgc")
        sh("ip", "link", "add", "pqc-ws", "type", "veth", "peer", "name", "pqc-wc")
        for ns, dev, addr in (("pqc-wgs", "pqc-ws", "10.40.0.1"), ("pqc-wgc", "pqc-wc", "10.40.0.2")):
            sh("ip", "link", "set", dev, "netns", ns)
            sh("ip", "-n", ns, "addr", "add", f"{addr}/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "-n", "pqc-wgs", "addr", "add", "192.168.10.1/32", "dev", "lo")
        (d / "gw.toml").write_text(
            f'[wireguard]\nname = "vpn.acme"\nendpoint = "10.40.0.1:51820"\nkeyring_listen = "10.40.0.1:7443"\npool = "10.99.0.0/24"\n'
            f'routes = ["192.168.10.0/24"]\ninterface = "pqc-wgs0"\nrotate_minutes = 0.25\n'
            f"cert = '{d / 'gw' / 'chain.pem'}'\nkey = '{d / 'gw' / 'key.pem'}'\nca = '{d / 'pki' / 'ca.crt'}'\ncrl = '{d / 'pki' / 'crl.pem'}'\n"
            f"private_key = '{d / 'gw.key'}'\nstate = '{d / 'state.json'}'\n")
        self.spawn("pqc-wgs", "gateway", "--config", str(d / "gw.toml"), log=d / "gateway.log")
        self.wait(lambda: sh("ip", "netns", "exec", "pqc-wgs", "wg", "show", "pqc-wgs0", check=False).returncode == 0, "gateway did not start")
        time.sleep(0.5)
        self.spawn("pqc-wgc", "connect", "10.40.0.1:7443", "--cert-dir", str(d / "alice"), "--interface", "pqc-wgc0", "--server-name", "vpn.acme",
                   log=d / "client.log")

    def spawn(self, ns, *args, log):
        with open(log, "w") as out:
            self.procs.append(subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, "-m", "pqcsuite", "--verbose", "vpn", *args],
                                               stdout=out, stderr=subprocess.STDOUT))

    def teardown(self):
        for p in reversed(self.procs):
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for ns, dev in (("pqc-wgs", "pqc-wgs0"), ("pqc-wgc", "pqc-wgc0")):
            sh("ip", "-n", ns, "link", "del", dev, check=False)
            sh("ip", "netns", "del", ns, check=False)
        shutil.rmtree(self.d, ignore_errors=True)

    def wait(self, cond, message, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if cond():
                return
            time.sleep(0.5)
        logs = "\n".join(f"--- {f.name}\n" + f.read_text()[-3000:] for f in sorted(self.d.glob("*.log")))
        self.fail(f"{message}\n{logs}")

    def ping(self, target="192.168.10.1"):
        return sh("ip", "netns", "exec", "pqc-wgc", "ping", "-c", "1", "-W", "1", target, check=False).returncode == 0

    def test_traffic_rotation_and_revocation(self):
        self.wait(self.ping, "no traffic through the tunnel")
        dump = sh("ip", "netns", "exec", "pqc-wgs", "wg", "show", "pqc-wgs0", "preshared-keys").stdout.split()
        self.assertEqual(len(dump), 2)
        self.assertNotEqual(dump[1], "(none)")
        first_psk = dump[1]
        agreements = lambda: (self.d / "gateway.log").read_text().count("new PSK")
        self.wait(lambda: agreements() >= 2, "the PSK did not rotate", 40)
        self.assertNotEqual(sh("ip", "netns", "exec", "pqc-wgs", "wg", "show", "pqc-wgs0", "preshared-keys").stdout.split()[1], first_psk)
        self.wait(self.ping, "traffic stopped after the PSK rotated", 20)

        self.ca.revoke(self.laptop.serial, "keyCompromise")
        self.wait(lambda: not sh("ip", "netns", "exec", "pqc-wgs", "wg", "show", "pqc-wgs0", "peers").stdout.strip(),
                  "the gateway kept a revoked user", 30)
        self.assertFalse(self.ping())
        self.assertIn("revoked", (self.d / "gateway.log").read_text())


if __name__ == "__main__":
    unittest.main()
