"""Changes made on the customer's side reach the running services without anyone copying files or restarting them: a CRL
published by the CA, edited configuration files, endpoints that change grade, and new releases."""
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from cryptography import x509

from pqcsuite import JSON, PEM, ConfigWatch, latest_release, serve_http, tls
from pqcsuite.console import App, Settings
from pqcsuite.pki import CA, CAError, fetch_crl, follow_crl, shared
from pqcsuite.vpn import Peer, Site, validate
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


class CRLDistributionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.d = Path(self.tmp.name)
        self.ca = CA.init(d / "pki", "Root")
        self.ca.crl()
        _, self.rec = self.ca.issue("laptop", "client", out=d / "laptop")
        self.cas = x509.load_pem_x509_certificates((d / "pki" / "ca.crt").read_bytes())
        self.served = {"/crl.pem": lambda: (d / "pki" / "crl.pem").read_text()}
        httpd = serve_http("127.0.0.1:0", {"/crl.pem": (PEM, lambda: self.served["/crl.pem"]())})
        self.addCleanup(httpd.shutdown)
        self.url = f"http://127.0.0.1:{httpd.server_address[1]}/crl.pem"
        self.copy = d / "edge" / "crl.pem"

    def test_a_revocation_reaches_the_copy(self):
        self.assertTrue(fetch_crl(self.url, self.copy, self.cas))
        self.assertFalse(fetch_crl(self.url, self.copy, self.cas))
        self.ca.revoke(self.rec.serial)
        self.assertTrue(fetch_crl(self.url, self.copy, self.cas))
        self.assertIn(int(self.rec.serial, 16), revoked(self.copy))

    def test_forged_replayed_and_wrong_downloads_change_nothing(self):
        old = (self.d / "pki" / "crl.pem").read_text()
        time.sleep(1.1)
        self.ca.revoke(self.rec.serial)
        fetch_crl(self.url, self.copy, self.cas)
        kept = self.copy.read_bytes()
        other = CA.init(self.d / "other", "Other Root")
        cases = {"another CA": lambda: other.crl().decode(), "an older CRL": lambda: old, "not a CRL": lambda: "hello"}
        for name, body in cases.items():
            with self.subTest(name):
                self.served["/crl.pem"] = body
                with self.assertRaises(CAError):
                    fetch_crl(self.url, self.copy, self.cas)
                self.assertEqual(self.copy.read_bytes(), kept)
        with self.assertRaises(CAError):
            fetch_crl("file:///etc/passwd", self.copy, self.cas)

    def test_follow_keeps_the_copy_current_and_needs_a_first_copy(self):
        with self.assertRaises(CAError):
            follow_crl(self.url.replace("crl.pem", "nothing"), self.copy, self.d / "pki" / "ca.crt", 0.2)
        stop = follow_crl(self.url, self.copy, self.d / "pki" / "ca.crt", 0.2)
        self.addCleanup(stop.set)
        self.assertNotIn(int(self.rec.serial, 16), revoked(self.copy))
        self.ca.revoke(self.rec.serial)
        self.assertTrue(wait(lambda: int(self.rec.serial, 16) in revoked(self.copy)))

    def test_an_outage_keeps_the_last_copy_and_an_expired_copy_refuses_everyone(self):
        from pqcsuite.tls.server import Revocation
        stop = follow_crl(self.url, self.copy, self.d / "pki" / "ca.crt", 0.2)
        self.addCleanup(stop.set)
        kept = self.copy.read_bytes()
        self.served["/crl.pem"] = lambda: None
        with self.assertLogs("pqcsuite.crl", "ERROR") as logs:
            time.sleep(0.6)
        self.assertIn("cannot fetch the CRL", logs.output[0])
        self.assertEqual(self.copy.read_bytes(), kept)
        check = Revocation(str(self.copy), str(self.d / "pki" / "ca.crt"))
        check.check(int(self.rec.serial, 16))
        self.served["/crl.pem"] = lambda: (self.d / "pki" / "crl.pem").read_text()
        self.ca.revoke(self.rec.serial)
        self.assertTrue(wait(lambda: int(self.rec.serial, 16) in revoked(self.copy)))
        stop.set()
        self.copy.write_bytes(self.ca.crl(days=0))
        time.sleep(1.1)
        with self.assertRaisesRegex(CAError, "expired"):
            check.check(12345)

    def test_a_broken_http_answer_is_logged_and_the_follower_keeps_going(self):
        stop = follow_crl(self.url, self.copy, self.d / "pki" / "ca.crt", 0.2)
        self.addCleanup(stop.set)
        for answer in (b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n-----BEGIN", NOT_HTTP):
            with self.assertRaises(CAError):
                fetch_crl(garbage_server(self, answer) + "/crl.pem", self.copy, self.cas)
        self.ca.revoke(self.rec.serial)
        self.assertTrue(wait(lambda: int(self.rec.serial, 16) in revoked(self.copy)))

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


class ConfigWatchTest(unittest.TestCase):
    def test_changes_are_applied_and_broken_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "svc.toml"
            path.write_text("n = 1\n")
            seen = []

            def load(p):
                n = int(Path(p).read_text().split("=")[1])
                if n < 0:
                    raise ValueError("n must not be negative")
                return n
            w = ConfigWatch(path, load, seen.append, every=0.1)
            self.addCleanup(w.stop)
            time.sleep(0.05)
            path.write_text("n = 2\n")
            os.utime(path, (time.time() + 5, time.time() + 5))
            self.assertTrue(wait(lambda: seen == [2]))
            with self.assertLogs("pqcsuite", "ERROR") as logs:
                path.write_text("n = -1\n")
                os.utime(path, (time.time() + 10, time.time() + 10))
                self.assertTrue(wait(lambda: logs.output))
            self.assertEqual(seen, [2])
            self.assertIn("keeping the running configuration", logs.output[0])
            path.write_text("n = 3\n")
            w.poke()
            self.assertTrue(wait(lambda: seen == [2, 3]))


class ServeHTTPTest(unittest.TestCase):
    def test_the_console_shows_a_service_that_does_not_speak_http_as_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            app = App(Settings(audit_log=str(Path(d) / "a.jsonl"), edges=[garbage_server(self, NOT_HTTP)]))
            self.assertIn("error", app.edges()[0])

    def test_routes_health_and_missing_paths(self):
        httpd = serve_http("127.0.0.1:0", {"/status": (JSON, lambda: '{"up": 1}'), "/crl.pem": (PEM, lambda: None)})
        self.addCleanup(httpd.shutdown)
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        with urllib.request.urlopen(base + "/status", timeout=5) as r:
            self.assertEqual((r.headers["Content-Type"], json.load(r)), (JSON, {"up": 1}))
        with urllib.request.urlopen(base + "/healthz", timeout=5) as r:
            self.assertEqual(r.read(), b"ok\n")
        for path in ("/crl.pem", "/nope"):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(base + path, timeout=5)
            self.assertEqual(e.exception.code, 404)


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@unittest.skipIf(REASON, REASON)
class EdgeReloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.d = Path(self.tmp.name)
        self.ca = CA.init(d / "pki", "Root")
        self.ca.crl()
        self.srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=d / "srv")
        self.apps = {}
        for name in ("one", "two"):
            app = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
            app.name = name
            threading.Thread(target=app.serve_forever, daemon=True).start()
            self.addCleanup(app.shutdown)
            self.apps[name] = f"127.0.0.1:{app.server_address[1]}"

    def port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def route(self, name, port, app, **kw):
        from pqcsuite.tls.edge import Route
        return Route(name, "terminate", f"127.0.0.1:{port}", self.apps[app], cert=str(self.srv / "chain.pem"), key=str(self.srv / "key.pem"),
                     ca=str(self.d / "pki" / "ca.crt"), **kw)

    def get(self, port, who=None):
        ctx = tls.client_context(self.d / "pki" / "ca.crt", who and who / "chain.pem", who and who / "key.pem")
        with tls.connect("127.0.0.1", port, ctx, "localhost", 5) as c:
            c.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = b""
            while chunk := c.recv(timeout=5):
                data += chunk
        return data.rsplit(b"\r\n\r\n", 1)[-1].decode()

    def test_changed_routes_apply_and_untouched_ones_keep_running(self):
        from pqcsuite.tls.edge import Edge, reconcile
        a, b, c = self.port(), self.port(), self.port()
        edges = [Edge(r).bind() for r in (self.route("web", a, "one"), self.route("api", b, "one"))]
        for e in edges:
            threading.Thread(target=e.serve_forever, daemon=True).start()
        self.addCleanup(lambda: [e.stop(0) for e in list(edges)])
        api = edges[1]
        self.assertEqual(self.get(a), "one")
        reconcile(edges, [self.route("web", a, "two"), self.route("api", b, "one"), self.route("new", c, "two")])
        self.assertEqual(self.get(a), "two")
        self.assertEqual(self.get(c), "two")
        self.assertIs(next(e for e in edges if e.route.name == "api"), api)
        taken = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(taken.close)
        with self.assertLogs("pqcsuite", "ERROR"):
            reconcile(edges, [self.route("web", taken.getsockname()[1], "one"), self.route("api", b, "one")])
        self.assertEqual(self.get(a), "two")
        self.assertEqual(sorted(e.route.name for e in edges), ["api", "web"])
        with self.assertRaises((tls.TLSError, OSError)):
            self.get(c)

    def test_a_certificate_renewed_within_one_timestamp_tick_is_still_reloaded(self):
        from pqcsuite.tls.server import Server
        chain = self.srv / "chain.pem"
        s = Server(("127.0.0.1", 0), lambda: tls.server_context(chain, self.srv / "key.pem"), lambda c, a: None, watch=[chain])
        self.addCleanup(s.stop, 0)
        before = os.stat(chain).st_mtime_ns
        self.ca.renew(self.ca.records()[-1].serial, out=self.srv)
        os.utime(chain, ns=(before, before))
        self.assertTrue(s.reload_if_changed())

    def test_a_route_that_cannot_bind_leaves_no_crl_follower_behind(self):
        from pqcsuite.tls.edge import Edge
        httpd = serve_http("127.0.0.1:0", {"/crl.pem": (PEM, lambda: (self.d / "pki" / "crl.pem").read_text())})
        self.addCleanup(httpd.shutdown)
        taken = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(taken.close)
        followers = lambda: sum(t.name == "crl" and t.is_alive() for t in threading.enumerate())
        before = followers()
        route = self.route("web", taken.getsockname()[1], "one", crl=str(self.d / "edge-crl.pem"),
                           crl_url=f"http://127.0.0.1:{httpd.server_address[1]}/crl.pem", crl_every=5)
        with self.assertRaises(OSError):
            Edge(route).bind()
        self.assertTrue(wait(lambda: followers() == before, 10))

    def test_a_revocation_at_the_ca_reaches_the_edge(self):
        from pqcsuite.tls.edge import Edge
        who, rec = self.ca.issue("laptop", "client", out=self.d / "laptop")
        httpd = serve_http("127.0.0.1:0", {"/crl.pem": (PEM, lambda: (self.d / "pki" / "crl.pem").read_text())})
        self.addCleanup(httpd.shutdown)
        port = self.port()
        e = Edge(self.route("mtls", port, "one", require_client_cert=True, crl=str(self.d / "edge-crl.pem"),
                            crl_url=f"http://127.0.0.1:{httpd.server_address[1]}/crl.pem", crl_every=5)).start()
        self.addCleanup(e.stop, 0)
        self.assertEqual(self.get(port, who), "one")
        self.ca.revoke(rec.serial)

        def refused():
            try:
                return self.get(port, who) == ""
            except (tls.TLSError, OSError):
                return True
        self.assertTrue(wait(refused, 12))


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
