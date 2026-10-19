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
from pathlib import Path

from cryptography import x509

from acxelin_core.http import JSON, PEM, ConfigWatch, serve_http
from acxelin_core.pki import CA, CAError, fetch_crl, follow_crl, shared
from support import wait


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
        from acxelin_core.server import Revocation
        stop = follow_crl(self.url, self.copy, self.d / "pki" / "ca.crt", 0.2)
        self.addCleanup(stop.set)
        kept = self.copy.read_bytes()
        self.served["/crl.pem"] = lambda: None
        with self.assertLogs("acxelin_core", "ERROR") as logs:
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
            with self.assertLogs("acxelin_core", "ERROR") as logs:
                path.write_text("n = -1\n")
                os.utime(path, (time.time() + 10, time.time() + 10))
                self.assertTrue(wait(lambda: logs.output))
            self.assertEqual(seen, [2])
            self.assertIn("keeping the running configuration", logs.output[0])
            path.write_text("n = 3\n")
            w.poke()
            self.assertTrue(wait(lambda: seen == [2, 3]))


class ServeHTTPTest(unittest.TestCase):

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












if __name__ == "__main__":
    unittest.main()
