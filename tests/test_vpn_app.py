"""The VPN window's server: only its own page, on its own host name and origin, with the key from its address."""
import contextlib
import http.client
import io
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from pqcsuite import cli
from pqcsuite.vpn import app


class WindowServerTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.d = Path(tmp.name)
        self.window = app.App(folder=self.d, apply=False)
        self.httpd = app.serve(self.window)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.port = self.httpd.server_address[1]

    def call(self, path="/api/state", token=None, **headers):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}", "Authorization": f"Bearer {token or self.window.token}"} | headers)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def test_strangers_are_refused_and_cannot_lock_the_owner_out(self):
        self.assertEqual(self.call(), 200)
        self.assertEqual(self.call(Host=f"rebound.example:{self.port}"), 421)
        self.assertEqual(self.call(token="guess"), 401)
        for _ in range(20):
            self.assertEqual(self.call(token="guess", Origin="https://evil.example"), 403)
        self.assertEqual(self.call(), 200, "refused origins do not count towards the wrong-key lockout")
        self.assertEqual(self.call(Origin=f"http://localhost:{self.port}"), 200)

    def test_the_page_allows_only_its_own_script_and_no_framing(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/", headers={"Host": f"localhost:{self.port}"})
        r = c.getresponse()
        page = r.read()
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("script-src 'sha256-", csp)
        self.assertEqual(page.count(b"<script>"), 1)
        self.assertNotIn(self.window.token.encode(), page)

    def test_a_file_that_is_not_an_invitation_is_refused_and_not_kept(self):
        status, body = self.window.handle("POST", "/api/invitation", {"name": "x.pqcinvite", "text": "{\"pqcsuite_invite\": 1}"})
        self.assertEqual(status, 400)
        self.assertIn("not a PQC Suite invitation", body["error"])
        self.assertEqual(list(self.d.glob("*.pqcinvite")), [])
        self.assertEqual(self.window.handle("POST", "/api/connect", {"passphrase": "x"})[1]["error"][:24], "open the invitation file")


class SingleWindowTest(unittest.TestCase):
    def test_a_second_launch_reopens_the_running_window(self):
        with TemporaryDirectory() as d:
            held, running = app.claim(d, "wg0")
            with held:
                self.assertIsNone(running)
                self.assertEqual(app.claim(d, "wg0"), (None, None))
                (Path(d) / "wg0.app.url").write_text("http://127.0.0.1:5555/#key")
                out = io.StringIO()
                with mock.patch.object(app.App, "__init__", lambda s, *a, **k: setattr(s, "folder", Path(d))), \
                        mock.patch("webbrowser.open") as browser, contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
                    cli.main(["vpn", "app"])
                self.assertEqual(e.exception.code, 0)
                browser.assert_called_once_with("http://127.0.0.1:5555/#key")
                self.assertIn("already running", out.getvalue())
                with app.claim(d, "wg1")[0]:
                    pass
