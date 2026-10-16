"""Changes made on the customer's side reach the running services without anyone copying files or restarting them: a CRL
published by the CA, edited configuration files, endpoints that change grade, and new releases."""
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509

from pqcsuite import JSON, latest_release, serve_http
from pqcsuite.console import App, Settings
from pqcsuite.pki import CA, shared
from pqcsuite.vpn.wireguard import Gateway, GatewayConfig
from tests.helpers import REASON, wait


def revoked(path):
    return {r.serial_number for r in x509.load_pem_x509_crl(shared(Path(path).read_bytes))}


NOT_HTTP = b"not http at all\r\n\r\n"


def garbage_server(test, answer):
    """An address that answers one request with `answer`, however broken."""
    srv = socket.create_server(("127.0.0.1", 0))
    test.addCleanup(srv.close)

    def serve():
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(answer)
        conn.close()
    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}"












@unittest.skipIf(REASON, REASON)
class GatewayReconfigureTest(unittest.TestCase):
    def test_users_change_in_place_and_other_settings_need_a_restart(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ca = CA.init(d / "pki", "Root")
            ca.issue("localhost", "server", out=d / "gw")
            cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24",
                                cert=str(d / "gw" / "chain.pem"), key=str(d / "gw" / "key.pem"), ca=str(d / "pki" / "ca.crt"),
                                private_key=str(d / "wg.key"), state=str(d / "state.json"), users=["alice", "bob"], manage_interface=False)
            from tests.test_wireguard import FakeWG
            gw = Gateway(cfg, FakeWG())
            gw.wg.set_peer("pub-bob", "psk", ["10.99.0.3/32"])
            gw.clients["bob"] = {"public": "pub-bob", "serial": 1, "agreed": time.time(), "address": "10.99.0.3", "tag": "t"}
            new = GatewayConfig(**(vars(cfg) | {"users": ["alice"], "dns": ["10.0.0.53"]}))
            self.assertTrue(gw.reconfigure(new))
            self.assertNotIn("bob", gw.clients)
            self.assertNotIn("pub-bob", gw.wg.peers())
            self.assertEqual(gw.cfg.dns, ["10.0.0.53"])
            self.assertFalse(gw.reconfigure(GatewayConfig(**(vars(new) | {"pool": "10.98.0.0/24"}))))


class ReadinessChangesTest(unittest.TestCase):
    def test_a_scan_lists_what_changed_since_the_one_before(self):
        runs = iter([[{"target": "a:443", "grade": "C"}, {"target": "b:443", "grade": "A"}],
                     [{"target": "a:443", "grade": "B"}, {"target": "b:443", "grade": "A"}, {"target": "c:443", "grade": "F"}]])
        with tempfile.TemporaryDirectory() as d:
            app = App(Settings(audit_log=str(Path(d) / "audit.jsonl")))
            with mock.patch("pqcsuite.readiness.scan.scan", lambda targets: next(runs)), \
                 mock.patch("pqcsuite.readiness.scan.summary", lambda r: {"endpoints": len(r), "pq_key_exchange": 0, "pq_certificates": 0}):
                app.run_scan(["a:443", "b:443"])
                self.assertTrue(wait(lambda: not app.scanning))
                self.assertEqual(app.last_scan["changes"], [])
                app.run_scan(["a:443", "b:443", "c:443"])
                self.assertTrue(wait(lambda: not app.scanning and len(app.last_scan["endpoints"]) == 3))
            self.assertEqual(app.last_scan["changes"], [{"target": "a:443", "before": "C", "after": "B"},
                                                        {"target": "c:443", "before": None, "after": "F"}])
            self.assertEqual(app.overview()["readiness"]["changes"], 2)

    def test_a_failed_scan_says_why(self):
        with tempfile.TemporaryDirectory() as d:
            app = App(Settings(audit_log=str(Path(d) / "audit.jsonl")))
            with mock.patch("pqcsuite.readiness.scan.scan", side_effect=RuntimeError("no route to host")):
                with self.assertLogs("pqcsuite", "ERROR"):
                    app.run_scan(["a:443"])
                    self.assertTrue(wait(lambda: not app.scanning))
            self.assertIn("no route to host", app.scan_error)

    def test_schedule_needs_targets_and_a_sane_interval(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "console.toml"
            p.write_text('[console]\nscan_targets = ["a:443"]\nscan_every_hours = 0.01\n')
            with self.assertRaisesRegex(ValueError, "at least 0.25"):
                Settings.load(p)


class UpdatesTest(unittest.TestCase):
    def serve(self, releases):
        httpd = serve_http("127.0.0.1:0", {"/releases": (JSON, lambda: json.dumps(releases))})
        self.addCleanup(httpd.shutdown)
        return f"http://127.0.0.1:{httpd.server_address[1]}/releases"

    def test_the_newest_suite_release_is_found(self):
        url = self.serve([{"tag_name": "wolf-pack-v9.0.0", "html_url": "w"}, {"tag_name": "v0.1.0", "html_url": "a"},
                          {"tag_name": "v0.10.0", "html_url": "b"}, {"tag_name": "v0.2.0", "html_url": "c"},
                          {"tag_name": "v1.0.0", "html_url": "d", "draft": True}, {"tag_name": "v2.0.0", "html_url": "e", "prerelease": True}])
        self.assertEqual(latest_release(url), {"version": "0.10.0", "url": "b", "newer": True})
        self.assertEqual(latest_release(self.serve([{"tag_name": "v0.1.0", "html_url": "a"}]))["newer"], False)
        self.assertIsNone(latest_release(self.serve([])))
        with self.assertRaisesRegex(ValueError, "must start with http"):
            latest_release("file:///etc/passwd")
        with self.assertRaises(ValueError):
            latest_release(self.serve({"message": "Not Found"}))
        with self.assertRaises(OSError):
            latest_release(garbage_server(self, NOT_HTTP))

    def test_the_console_only_asks_when_told_to(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("pqcsuite.latest_release") as ask:
                self.assertIsNone(App(Settings(audit_log=str(Path(d) / "a.jsonl"))).overview()["update"])
                ask.assert_not_called()
                ask.return_value = {"version": "0.2.0", "url": "u", "newer": True}
                app = App(Settings(audit_log=str(Path(d) / "a.jsonl"), check_updates=True))
                app.overview()
                self.assertTrue(wait(lambda: app.overview()["update"] is not None))
                self.assertEqual(ask.call_count, 1)


if __name__ == "__main__":
    unittest.main()
