"""VPN tests. The unit tests always run. The integration test builds two sites in Linux network namespaces with real strongSwan
charon daemons and real `pqcsuite vpn up` controllers; it needs root, iproute2, PQCSUITE_STRONGSWAN (a strongSwan 6.0.2+ prefix)
and OpenSSL 3.5+. Set PQCSUITE_VPN_DATAPLANE=1 where the kernel has ESP to also check traffic through the tunnel."""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from pqcsuite.pki import CA
from pqcsuite.vpn import PROFILES, Peer, Site, load_config, validate
from pqcsuite.vpn.charon import conn_config, ppk_pattern
from pqcsuite.vpn.controller import context


def site(**kw):
    peer = Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True, keyring="10.0.0.2:7443")
    return Site(**({"name": "hq.acme", "address": "10.0.0.1", "cert": "c", "key": "k", "ca": "a", "peers": [peer]} | kw))


class ConfigTest(unittest.TestCase):
    def test_every_exchange_is_hybrid_post_quantum(self):
        for ike, esp in PROFILES.values():
            self.assertIn("ke1_mlkem", ike)
            self.assertIn("ke1_mlkem", esp)
            self.assertIn("aes256gcm16", esp)

    def test_conn_requires_a_ppk_and_pins_it_per_peer(self):
        s = site()
        c = conn_config(s, s.peers[0], "abc123abc123." + ppk_pattern("hq.acme", "branch.acme"))["branch.acme"]
        self.assertEqual((c["ppk_required"], c["local"]["auth"], c["remote"]["id"]), ("yes", "psk", "branch.acme"))
        self.assertEqual(c["ppk_id"], "abc123abc123.branch.acme.hq.acme.ppk.pqcsuite")
        responder = conn_config(s, s.peers[0])["branch.acme"]
        self.assertEqual(responder["ppk_id"], "*.branch.acme.hq.acme.ppk.pqcsuite")
        self.assertEqual(c["children"]["net"]["remote_ts"], ["10.2.0.0/16"])

    def test_both_sides_derive_from_the_same_context(self):
        self.assertEqual(context("hq", "branch", "t"), context("branch", "hq", "t"))
        self.assertNotEqual(context("hq", "branch", "t"), context("hq", "branch", "u"))

    def test_validation(self):
        with self.assertRaisesRegex(ValueError, "keyring"):
            validate(site(peers=[Peer("b", "1.2.3.4", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True)]))
        with self.assertRaisesRegex(ValueError, "keyring_listen"):
            validate(site(peers=[Peer("b", "1.2.3.4", ["10.1.0.0/16"], ["10.2.0.0/16"])]))
        with self.assertRaisesRegex(ValueError, "profile"):
            validate(site(peers=[Peer("b", "1.2.3.4", [], [], True, "1.2.3.4:1", profile="fast")]))
        with self.assertRaises(ValueError):
            validate(site(peers=[Peer("b", "1.2.3.4", ["not-a-net"], [], True, "1.2.3.4:1")]))

    def test_key_agreement_messages_must_be_json_objects(self):
        from pqcsuite import tls
        from pqcsuite.vpn.controller import Controller, read_line

        class Conn:
            def __init__(self, data):
                self.data = data

            def recv(self, size, timeout):
                data, self.data = self.data, b""
                return data
        self.assertEqual(read_line(Conn(b'{"ok": true}\n')), {"ok": True})
        for bad in (b"[1]\n", b'"x"\n', b"{nope\n"):
            with self.assertRaisesRegex(tls.TLSError, "not a JSON object"):
                read_line(Conn(bad))
        site = Site(name="hq", address="10.0.0.1", ca="ca.crt", cert="c.pem", key="k.pem", key_passphrase_env="PQCSUITE_TEST_UNSET_VAR")
        with self.assertRaisesRegex(ValueError, "PQCSUITE_TEST_UNSET_VAR is not set"):
            Controller(site, charon=object()).passphrase()

    def test_one_vici_request_at_a_time(self):
        import threading
        from pqcsuite.vpn.charon import Charon

        class Session:
            busy, overlaps = False, 0

            def list_sas(self):
                if Session.busy:
                    Session.overlaps += 1
                Session.busy = True
                time.sleep(0.01)
                yield {}
                Session.busy = False
        ch = Charon.__new__(Charon)
        ch.session, ch.lock = Session(), threading.Lock()
        threads = [threading.Thread(target=ch.tunnels) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(Session.overlaps, 0)

    def test_example_configs_load(self):
        root = Path(__file__).parent.parent / "examples"
        for f in ("vpn-hq.toml", "vpn-branch.toml"):
            self.assertTrue(load_config(root / f).peers)


class FakeCharon:
    def __init__(self, keys, tunnels):
        self.keys, self.sas, self.terminated = set(keys), list(tunnels), []

    def shared_ids(self):
        return sorted(self.keys)

    def unload_key(self, key_id):
        self.keys.discard(key_id)

    def terminate(self, peer):
        self.terminated.append(peer)
        self.sas = [t for t in self.sas if t["peer"] != peer]

    def tunnels(self):
        return self.sas


class FreshnessTest(unittest.TestCase):
    def test_tunnels_without_fresh_key_agreement_are_cut(self):
        from pqcsuite.vpn.controller import Controller
        s = site(peers=[Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], rotate_minutes=1),
                        Peer("lab.acme", "10.0.0.3", ["10.1.0.0/16"], ["10.3.0.0/16"], rotate_minutes=1)], keyring_listen="0.0.0.0:7443")
        left_over = {"psk-branch.acme", "ppk-branch.acme-aaaaaaaaaaaa", "psk-lab.acme", "ppk-lab.acme-bbbbbbbbbbbb", "psk-other"}
        tunnels = [{"peer": "branch.acme", "state": "ESTABLISHED", "established_s": 5}, {"peer": "lab.acme", "state": "ESTABLISHED", "established_s": 5}]
        ch = FakeCharon(left_over, tunnels)
        ctl = Controller(s, charon=ch)
        ctl.enforce_freshness()
        self.assertEqual(ch.terminated, [])
        ctl.started -= 400
        ctl.last_agreed["lab.acme"] = time.time()
        ctl.enforce_freshness()
        self.assertEqual(ch.terminated, ["branch.acme"])
        self.assertEqual(ch.keys, {"psk-lab.acme", "ppk-lab.acme-bbbbbbbbbbbb", "psk-other"})
        self.assertEqual(ctl.counts["stale_peers"], 1)


SS = os.environ.get("PQCSUITE_STRONGSWAN")
READY = SS and os.geteuid() == 0 and shutil.which("ip") and sys.platform == "linux"


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


@unittest.skipUnless(READY, "needs root, iproute2 and PQCSUITE_STRONGSWAN")
class SiteToSiteTest(unittest.TestCase):
    """hq (10.30.0.1, LAN 192.168.10.0/24) <-> branch (10.30.0.2, LAN 192.168.20.0/24); branch initiates."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.procs = []
        self.addCleanup(self.teardown)
        ca = CA.init(self.d / "pki", "VPN Root")
        for name, addr in (("hq.acme", "10.30.0.1"), ("branch.acme", "10.30.0.2")):
            ca.issue(name, "site", [addr], out=self.d / name)
        ca.crl()
        self.ca = ca
        sh("ip", "netns", "add", "pqc-hq")
        sh("ip", "netns", "add", "pqc-br")
        sh("ip", "link", "add", "pqc-vh", "type", "veth", "peer", "name", "pqc-vb")
        for ns, dev, addr, lan, other_lan, gw in (("pqc-hq", "pqc-vh", "10.30.0.1", "192.168.10.1", "192.168.20.0/24", "10.30.0.2"),
                                                  ("pqc-br", "pqc-vb", "10.30.0.2", "192.168.20.1", "192.168.10.0/24", "10.30.0.1")):
            sh("ip", "link", "set", dev, "netns", ns)
            sh("ip", "-n", ns, "addr", "add", f"{addr}/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
            sh("ip", "-n", ns, "link", "set", "lo", "up")
            sh("ip", "-n", ns, "addr", "add", f"{lan}/32", "dev", "lo")
            sh("ip", "-n", ns, "route", "add", other_lan, "via", gw)
        common = f'ca = "{self.d}/pki/ca.crt"\ncrl = "{self.d}/pki/crl.pem"\n'
        (self.d / "hq.toml").write_text(textwrap.dedent(f"""
            [site]
            name = "hq.acme"
            address = "10.30.0.1"
            cert = "{self.d}/hq.acme/chain.pem"
            key = "{self.d}/hq.acme/key.pem"
            vici = "unix://{self.d}/hq.vici"
            keyring_listen = "10.30.0.1:7443"
            """) + common + textwrap.dedent("""
            [[peer]]
            name = "branch.acme"
            address = "10.30.0.2"
            local_subnets = ["192.168.10.0/24"]
            remote_subnets = ["192.168.20.0/24"]
            rotate_minutes = 1
            """))
        (self.d / "br.toml").write_text(textwrap.dedent(f"""
            [site]
            name = "branch.acme"
            address = "10.30.0.2"
            cert = "{self.d}/branch.acme/chain.pem"
            key = "{self.d}/branch.acme/key.pem"
            vici = "unix://{self.d}/br.vici"
            """) + common + textwrap.dedent("""
            [[peer]]
            name = "hq.acme"
            address = "10.30.0.1"
            local_subnets = ["192.168.20.0/24"]
            remote_subnets = ["192.168.10.0/24"]
            initiate = true
            keyring = "10.30.0.1:7443"
            rotate_minutes = 1
            """))
        for ns, tag in (("pqc-hq", "hq"), ("pqc-br", "br")):
            conf = self.d / f"{tag}.conf"
            conf.write_text(f"charon {{\n plugins {{ vici {{ socket = unix://{self.d}/{tag}.vici }} }}\n"
                            f" filelog {{ log {{ path = {self.d}/{tag}.log\n flush_line = yes\n default = 1\n }} }}\n}}\n")
            self.spawn("ip", "netns", "exec", ns, "unshare", "-m", "sh", "-c",
                       f"mount -t tmpfs tmpfs /run && STRONGSWAN_CONF={conf} exec {SS}/libexec/ipsec/charon")
        self.wait(lambda: (self.d / "hq.vici").exists() and (self.d / "br.vici").exists(), "charon did not start")
        for ns, tag in (("pqc-hq", "hq"), ("pqc-br", "br")):
            self.spawn("ip", "netns", "exec", ns, sys.executable, "-m", "pqcsuite", "vpn", "up", "--config", str(self.d / f"{tag}.toml"),
                       log=self.d / f"{tag}-controller.log")

    def spawn(self, *cmd, log=None):
        out = open(log, "w") if log else subprocess.DEVNULL
        self.procs.append(subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT))
        if log:
            out.close()

    def teardown(self):
        for p in reversed(self.procs):
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for ns in ("pqc-hq", "pqc-br"):
            sh("ip", "netns", "del", ns, check=False)
        if os.environ.get("PQCSUITE_KEEP_LOGS"):
            print(f"logs kept in {self.d}", file=sys.stderr)
        else:
            shutil.rmtree(self.d, ignore_errors=True)

    def wait(self, cond, message, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if cond():
                    return
            except Exception:
                pass
            time.sleep(0.5)
        logs = "\n".join(f"--- {f.name}\n" + f.read_text()[-3000:] for f in sorted(self.d.glob("*.log")))
        self.fail(f"{message}\n{logs}")

    def tunnel(self, tag):
        from pqcsuite.vpn.charon import Charon
        with Charon(f"unix://{self.d}/{tag}.vici") as ch:
            return min(ch.tunnels(), key=lambda t: t["established_s"], default=None)

    def test_quantum_safe_tunnel_rotation_and_revocation(self):
        up = lambda: (t := self.tunnel("hq")) and t["state"] == "ESTABLISHED" and t["ppk"]
        self.wait(up, "the tunnel did not come up with a PPK")
        t = self.tunnel("hq")
        self.assertIn("ML_KEM_768", t["key_exchange"])
        self.assertIn("CURVE_25519", t["key_exchange"])
        self.assertEqual(t["encryption"], "AES_GCM_16")

        if os.environ.get("PQCSUITE_VPN_DATAPLANE"):
            sh("ip", "netns", "exec", "pqc-br", "ping", "-c", "3", "-W", "2", "-I", "192.168.20.1", "192.168.10.1")
            child = self.tunnel("hq")["children"][0]
            self.assertEqual(child["state"], "INSTALLED")
            self.assertGreaterEqual(child["packets_in"], 3)

        agreements = lambda: (self.d / "hq-controller.log").read_text().count("new keys")
        born = lambda: time.time() - self.tunnel("br")["established_s"]
        self.wait(lambda: agreements() >= 2, "keys did not rotate within a minute", 90)
        rotated = time.time()
        self.wait(lambda: born() >= rotated - 3 and self.tunnel("br")["ppk"], "no new PPK-protected SA after rotation", 20)
        self.assertTrue(self.tunnel("br")["ppk"])

        serial = next(r.serial for r in self.ca.records() if r.common_name == "branch.acme")
        self.ca.revoke(serial, "keyCompromise")
        self.wait(lambda: self.tunnel("hq") is None, "hq kept the tunnel of a revoked branch", 40)
        log = (self.d / "hq-controller.log").read_text()
        self.assertIn("revoked", log)
