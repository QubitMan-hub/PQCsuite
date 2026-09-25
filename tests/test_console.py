import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from pqcsuite import vault
from pqcsuite.ca import CA
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
        for token in ("", "wrong"):
            with self.assertRaises(urllib.error.HTTPError) as e:
                self.call("/api/overview", token=token)
            self.assertEqual(e.exception.code, 401)

    def test_overview_reports_every_area(self):
        _, headers, o = self.call("/api/overview")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(o["certificates"]["valid"], 0)
        self.assertEqual(o["edges"]["unreachable"], 1)
        self.assertEqual(o["backups"]["count"], 1)
        self.assertEqual(o["vpn"], {"tunnels": 0, "quantum_safe": 0})

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

    def test_fleet_config_is_validated_and_audited(self):
        self.app.s.fleet = str(self.d / "fleet")
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/fleet/desired", {"name": "edge1", "config": "[[edge]]\nname = 'x'\nmode = 'sideways'\nlisten = '0.0.0.0:1'\ntarget = '1.2.3.4:5'\n"})
        self.assertIn("mode", json.loads(e.exception.read())["error"])
        self.call("/api/fleet/desired", {"name": "edge1", "config": ""})
        self.assertTrue((self.d / "fleet" / "desired" / "edge1.toml").exists())
        self.assertEqual(self.call("/api/fleet")[2], [])
        self.assertIn('"fleet_config"', (self.d / "audit.jsonl").read_text())

    def test_bad_requests_are_explained(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/certificates/issue", {"kind": "admin", "common_name": "x"})
        self.assertEqual(e.exception.code, 400)
        self.assertIn("kind", json.loads(e.exception.read())["error"])
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/nothing")
        self.assertEqual(e.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
