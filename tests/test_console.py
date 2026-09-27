import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from pqcsuite import vault
from pqcsuite.pki import CA
from pqcsuite.console import App, Settings, serve


class ConsoleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        CA.init(d / "pki", "Console Root")
        (d / "backups").mkdir()
        me = vault.Identity.generate()
        (d / "f").write_bytes(b"x" * 1000)
        vault.encrypt(d / "f", d / "backups" / "f.pqv", [me.public])
        self.app = App(Settings(listen="127.0.0.1:0", ca=str(d / "pki"), backups=[str(d / "backups")], edges=["http://127.0.0.1:1"],
                                audit_log=str(d / "audit.jsonl")), token="t0ken")
        self.httpd = serve(self.app)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.d = d

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def call(self, path, body=None, token="t0ken"):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), json.loads(r.read())

    def test_page_is_public_but_the_api_needs_the_token(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as r:
            self.assertIn(b"pqcsuite console", r.read())
            self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
            self.assertIn("script-src 'sha256-", r.headers["Content-Security-Policy"])
            self.assertNotIn("script-src 'self' 'unsafe-inline'", r.headers["Content-Security-Policy"])
        for token in ("", "wrong"):
            with self.assertRaises(urllib.error.HTTPError) as e:
                self.call("/api/overview", token=token)
            self.assertEqual(e.exception.code, 401)

    def test_repeated_wrong_tokens_are_slowed_down(self):
        codes = []
        for token in ["wrong"] * 10 + ["t0ken"]:
            try:
                codes.append(self.call("/api/overview", token=token)[0])
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        self.assertEqual(codes, [401] * 10 + [429])

    def test_a_silent_client_is_disconnected(self):
        import socket
        from pqcsuite import console
        self.addCleanup(setattr, console, "HTTP_IDLE", getattr(console, "HTTP_IDLE", None))
        console.HTTP_IDLE = 1
        httpd = serve(self.app)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        with socket.create_connection(httpd.server_address, timeout=5) as c:
            self.assertEqual(c.recv(1), b"")

    def test_a_negative_content_length_is_refused(self):
        import socket
        with socket.create_connection(self.httpd.server_address, timeout=5) as s:
            s.sendall(b"POST /api/scan HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t0ken\r\nContent-Length: -1\r\n\r\n")
            self.assertIn(b"400", s.recv(200).split(b"\r\n")[0])

    def test_overview_reports_every_area(self):
        _, headers, o = self.call("/api/overview")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(o["certificates"]["valid"], 0)
        self.assertEqual(o["edges"]["unreachable"], 1)
        self.assertEqual(o["backups"]["count"], 1)
        self.assertEqual(o["vpn"], {"tunnels": 0, "quantum_safe": 0, "remote_users": 0, "remote_online": 0})

    def test_issue_and_revoke_are_audited(self):
        _, _, r = self.call("/api/certificates/issue", {"kind": "server", "common_name": "api.acme", "names": "10.0.0.5", "days": 90})
        _, _, certs = self.call("/api/certificates")
        c = certs["certificates"][0]
        self.assertEqual((c["common_name"], c["names"], c["status"]), ("api.acme", ["api.acme", "10.0.0.5"], "valid"))
        self.call("/api/certificates/revoke", {"serial": r["serial"]})
        _, _, certs = self.call("/api/certificates")
        self.assertEqual(certs["certificates"][0]["status"], "revoked")
        actions = [json.loads(l)["action"] for l in (self.d / "audit.jsonl").read_text().splitlines()]
        self.assertEqual(actions, ["issue", "revoke"])

    def test_a_broken_edge_or_bug_is_an_answer_not_a_dropped_connection(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Odd(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"edge1": "not-a-dict"} if self.path.startswith("/a") else [1, 2]).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        odd = ThreadingHTTPServer(("127.0.0.1", 0), Odd)
        threading.Thread(target=odd.serve_forever, daemon=True).start()
        self.addCleanup(odd.server_close)
        self.addCleanup(odd.shutdown)
        port = odd.server_address[1]
        self.app.s.edges = [f"http://127.0.0.1:{port}/a", f"http://127.0.0.1:{port}/b"]
        _, _, edges = self.call("/api/edges")
        self.assertEqual([("error" in e) for e in edges], [True, True])
        self.app.backups = lambda: 1 / 0
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/backups")
        self.assertEqual(e.exception.code, 500)
        self.assertIn("console's log", json.loads(e.exception.read())["error"])

    def test_bad_requests_are_explained(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/certificates/issue", {"kind": "admin", "common_name": "x"})
        self.assertEqual(e.exception.code, 400)
        self.assertIn("kind", json.loads(e.exception.read())["error"])
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/nothing")
        self.assertEqual(e.exception.code, 404)
        for path, body, message in (("/api/certificates/revoke", {}, "missing field serial"),
                                    ("/api/scan", {"targets": ["127.0.0.1:1", ":443"]}, "expected host")):
            with self.assertRaises(urllib.error.HTTPError) as e:
                self.call(path, body)
            self.assertEqual(e.exception.code, 400)
            self.assertIn(message, json.loads(e.exception.read())["error"])
        self.assertEqual(self.call("/api/scan", {"targets": ["127.0.0.1:1"]})[2], {"started": 1})


if __name__ == "__main__":
    unittest.main()
