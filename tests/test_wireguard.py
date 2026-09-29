"""WireGuard remote access. The unit tests run the real key agreement over post-quantum TLS against a stand-in for `wg`. The
integration test puts a gateway and a laptop in network namespaces with real WireGuard (kernel module, or wireguard-go named
by PQCSUITE_WIREGUARD_GO) and sends traffic through; it needs root, iproute2 and wireguard-tools."""
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from pqcsuite import tls
from pqcsuite.pki import CA
from pqcsuite.vpn.wireguard import Client, Gateway, GatewayConfig, private_key
from tests.helpers import REASON


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
        with self.assertRaisesRegex(ValueError, "full_tunnel = true"):
            self.config(routes=["0.0.0.0/0"]).validate()
        self.assertTrue(self.config(full_tunnel=True).validate().full_tunnel)


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

    def test_full_tunnel_sends_everything_through_the_gateway(self):
        self.gw.cfg.full_tunnel = True
        reply, _ = self.client("alice").agree()
        self.assertEqual(reply["routes"], ["0.0.0.0/0", "::/0"], "IPv6 goes into the tunnel too, where the gateway drops it")

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

    def test_a_client_that_comes_back_while_it_is_being_expired_stays_tracked(self):
        bob = self.client("bob")
        bob.agree()
        self.gw.clients["bob"]["agreed"] -= 3600
        self.gw.lock.acquire()
        t = threading.Thread(target=self.gw.expire)
        t.start()
        time.sleep(0.2)
        fresh = dict(self.gw.clients["bob"], agreed=time.time())
        self.gw.clients["bob"] = fresh
        self.gw.lock.release()
        t.join(5)
        self.assertIs(self.gw.clients.get("bob"), fresh)
        self.assertIn(bob.public, self.wg.peers_)

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


class Namespaces(unittest.TestCase):
    """Network namespaces joined by veth pairs, a CA, and pqcsuite processes run inside them."""
    NAMESPACES, TUNNELS = (), ()

    def setUp(self):
        self.d = d = Path(tempfile.mkdtemp())
        self.procs = []
        self.addCleanup(self.teardown)
        self.ca = CA.init(d / "pki", "VPN Root")
        self.ca.issue("vpn.acme", "server", [self.GATEWAY], out=d / "gw")
        _, self.laptop = self.ca.issue("alice", "client", out=d / "alice")
        (d / "alice" / "ca.crt").write_bytes((d / "pki" / "ca.crt").read_bytes())
        self.ca.crl()
        for ns in self.NAMESPACES:
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")

    def link(self, a, a_dev, a_addr, b, b_dev, b_addr):
        sh("ip", "link", "add", a_dev, "type", "veth", "peer", "name", b_dev)
        for ns, dev, addr in ((a, a_dev, a_addr), (b, b_dev, b_addr)):
            sh("ip", "link", "set", dev, "netns", ns)
            sh("ip", "-n", ns, "addr", "add", addr, "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")

    def gateway(self, ns, **extra):
        d = self.d
        (d / "gw.toml").write_text(
            f'[wireguard]\nname = "vpn.acme"\nendpoint = "{self.GATEWAY}:51820"\nkeyring_listen = "{self.GATEWAY}:7443"\n'
            f'interface = "{self.TUNNELS[0]}"\nrotate_minutes = 0.25\n' + "".join(f"{k} = {v}\n" for k, v in extra.items()) +
            f"cert = '{d / 'gw' / 'chain.pem'}'\nkey = '{d / 'gw' / 'key.pem'}'\nca = '{d / 'pki' / 'ca.crt'}'\ncrl = '{d / 'pki' / 'crl.pem'}'\n"
            f"private_key = '{d / 'gw.key'}'\nstate = '{d / 'state.json'}'\n")
        self.spawn(ns, "gateway", "--config", str(d / "gw.toml"), log=d / "gateway.log")
        self.wait(lambda: sh("ip", "netns", "exec", ns, "wg", "show", self.TUNNELS[0], check=False).returncode == 0, "gateway did not start")
        time.sleep(0.5)

    def connect(self, ns):
        self.spawn(ns, "connect", f"{self.GATEWAY}:7443", "--cert-dir", str(self.d / "alice"), "--interface", self.TUNNELS[1],
                   "--server-name", "vpn.acme", log=self.d / "client.log")

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
        for ns in self.NAMESPACES:
            for dev in self.TUNNELS:
                sh("ip", "-n", ns, "link", "del", dev, check=False)
            sh("ip", "netns", "del", ns, check=False)
        for dev in self.TUNNELS:
            Path(f"/run/pqcsuite/{dev}.conf").unlink(missing_ok=True)
        shutil.rmtree(self.d, ignore_errors=True)

    def wait(self, cond, message, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if cond():
                return
            time.sleep(0.5)
        logs = "\n".join(f"--- {f.name}\n" + f.read_text()[-3000:] for f in sorted(self.d.glob("*.log")))
        self.fail(f"{message}\n{logs}")

    def ping(self, ns, target):
        return sh("ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", target, check=False).returncode == 0


@unittest.skipUnless(not REASON and wireguard_available() and shutil.which("wg-quick"),
                     "needs root, iproute2, wireguard-tools and WireGuard (kernel or PQCSUITE_WIREGUARD_GO)")
class RemoteAccessTest(Namespaces):
    """gateway (10.40.0.1, LAN 192.168.10.1) <- laptop (10.40.0.2) over WireGuard with a PSK from ML-DSA mutual TLS."""
    NAMESPACES, TUNNELS, GATEWAY = ("pqc-wgs", "pqc-wgc"), ("pqc-wgs0", "pqc-wgc0"), "10.40.0.1"

    def setUp(self):
        super().setUp()
        self.link("pqc-wgs", "pqc-ws", "10.40.0.1/24", "pqc-wgc", "pqc-wc", "10.40.0.2/24")
        sh("ip", "-n", "pqc-wgs", "addr", "add", "192.168.10.1/32", "dev", "lo")
        self.gateway("pqc-wgs", pool='"10.99.0.0/24"', routes='["192.168.10.0/24"]')
        self.connect("pqc-wgc")

    def test_traffic_rotation_and_revocation(self):
        ping = lambda: self.ping("pqc-wgc", "192.168.10.1")
        self.wait(ping, "no traffic through the tunnel")
        dump = sh("ip", "netns", "exec", "pqc-wgs", "wg", "show", "pqc-wgs0", "preshared-keys").stdout.split()
        self.assertEqual(len(dump), 2)
        self.assertNotEqual(dump[1], "(none)")
        first_psk = dump[1]
        agreements = lambda: (self.d / "gateway.log").read_text().count("new PSK")
        self.wait(lambda: agreements() >= 2, "the PSK did not rotate", 40)
        self.assertNotEqual(sh("ip", "netns", "exec", "pqc-wgs", "wg", "show", "pqc-wgs0", "preshared-keys").stdout.split()[1], first_psk)
        self.wait(ping, "traffic stopped after the PSK rotated", 20)
        self.assertFalse(sh("ip", "netns", "exec", "pqc-wgc", "iptables", "-S", "PQCSUITE-KILLSWITCH", check=False).returncode == 0,
                         "a split tunnel must not block the rest of the laptop's traffic")

        self.ca.revoke(self.laptop.serial, "keyCompromise")
        self.wait(lambda: not sh("ip", "netns", "exec", "pqc-wgs", "wg", "show", "pqc-wgs0", "peers").stdout.strip(),
                  "the gateway kept a revoked user", 30)
        self.assertFalse(ping())
        self.assertIn("revoked", (self.d / "gateway.log").read_text())


@unittest.skipUnless(not REASON and wireguard_available() and shutil.which("wg-quick") and shutil.which("iptables"),
                     "needs root, iproute2, iptables, wireguard-tools and WireGuard (kernel or PQCSUITE_WIREGUARD_GO)")
class FullTunnelTest(Namespaces):
    """laptop (10.41.0.2) -> gateway (10.41.0.1, NAT) -> internet host (198.51.100.2). Without the tunnel the laptop could reach the
    host directly through the gateway's plain routing, which is what the kill switch must stop."""
    NAMESPACES, TUNNELS, GATEWAY = ("pqc-ftg", "pqc-ftc", "pqc-fti"), ("pqc-ftg0", "pqc-ftc0"), "10.41.0.1"
    HOST = "198.51.100.2"

    def setUp(self):
        super().setUp()
        # the laptop reaches the gateway only through its default route, as over the internet, not on its own LAN
        self.link("pqc-ftg", "pqc-fg-c", "10.41.0.1/24", "pqc-ftc", "pqc-fc", "10.41.0.2/32")
        self.link("pqc-ftg", "pqc-fg-i", "198.51.100.1/24", "pqc-fti", "pqc-fi", "198.51.100.2/24")
        sh("ip", "-n", "pqc-ftc", "route", "add", "default", "via", "10.41.0.1", "dev", "pqc-fc", "onlink")
        sh("ip", "-n", "pqc-fti", "route", "add", "10.41.0.0/24", "via", "198.51.100.1")
        sh("ip", "netns", "exec", "pqc-ftg", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        self.assertTrue(self.ping("pqc-ftc", self.HOST), "the laptop should reach the host directly before any VPN")
        self.gateway("pqc-ftg", pool='"10.98.0.0/24"', full_tunnel="true")
        self.connect("pqc-ftc")

    def through_tunnel(self):
        return "dev pqc-ftc0" in sh("ip", "netns", "exec", "pqc-ftc", "ip", "route", "get", self.HOST, check=False).stdout

    def test_all_traffic_through_the_tunnel_recovery_and_kill_switch(self):
        self.wait(lambda: self.through_tunnel() and self.ping("pqc-ftc", self.HOST), "no traffic through the full tunnel")
        rules = sh("ip", "netns", "exec", "pqc-ftc", "iptables", "-S", "PQCSUITE-KILLSWITCH").stdout
        self.assertIn("-j REJECT", rules)
        self.assertIn("-d 10.41.0.1/32 -p tcp -m tcp --dport 7443 -j ACCEPT", rules)

        # the gateway forgets the laptop, as after a long sleep: the laptop takes its tunnel down, agrees keys directly, comes back
        public = sh("ip", "netns", "exec", "pqc-ftg", "wg", "show", "pqc-ftg0", "peers").stdout.split()[0]
        sh("ip", "netns", "exec", "pqc-ftg", "wg", "set", "pqc-ftg0", "peer", public, "remove")
        self.wait(lambda: "taking the tunnel down" in (self.d / "client.log").read_text(), "the laptop did not notice the dead tunnel", 60)
        self.wait(lambda: self.through_tunnel() and self.ping("pqc-ftc", self.HOST), "the laptop did not come back", 60)

        # the client crashes and the tunnel is gone: the kill switch still stops traffic outside the tunnel
        self.procs[-1].kill()
        self.procs[-1].wait(5)
        env = os.environ | ({"WG_QUICK_USERSPACE_IMPLEMENTATION": os.environ["PQCSUITE_WIREGUARD_GO"],
                             "WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD": "1"} if os.environ.get("PQCSUITE_WIREGUARD_GO") else {})
        subprocess.run(["ip", "netns", "exec", "pqc-ftc", "wg-quick", "down", "/run/pqcsuite/pqc-ftc0.conf"], capture_output=True, env=env)
        self.assertFalse(self.through_tunnel())
        self.assertFalse(self.ping("pqc-ftc", self.HOST), "traffic left the laptop outside the tunnel")
        sh("ip", "netns", "exec", "pqc-ftc", sys.executable, "-c", "import socket; socket.create_connection(('10.41.0.1', 7443), 5).close()")

        sh("ip", "netns", "exec", "pqc-ftc", sys.executable, "-m", "pqcsuite", "vpn", "disconnect", "--interface", "pqc-ftc0")
        self.assertTrue(self.ping("pqc-ftc", self.HOST), "disconnect should lift the kill switch")


if __name__ == "__main__":
    unittest.main()
