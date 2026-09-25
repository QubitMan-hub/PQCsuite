import socket
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from pqcsuite import tls
from pqcsuite.ca import CA
from pqcsuite.fleet import Agent, Service, serve, validate_config
from pqcsuite.tls.http import HTTPError, request
from tests.test_tls import Upstream

try:
    tls.lib()
    REASON = None
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


def free_port():
    with socket.create_server(("127.0.0.1", 0)) as s:
        return s.getsockname()[1]


@unittest.skipIf(REASON, REASON)
class FleetTest(unittest.TestCase):
    def setUp(self):
        self.d = d = Path(tempfile.mkdtemp())
        self.ca = CA.init(d / "pki", "Fleet Root")
        fleet_cert, _ = self.ca.issue("localhost", "server", out=d / "fleet-cert")
        self.agent_dir, self.agent_rec = self.ca.issue("edge-berlin", "client", out=d / "agent")
        (d / "agent" / "ca.crt").write_bytes((d / "pki" / "ca.crt").read_bytes())
        self.edge_cert, _ = self.ca.issue("localhost", "server", out=d / "edge-cert")
        self.ca.crl()
        self.server = serve(d / "fleet", "127.0.0.1:0", fleet_cert / "chain.pem", fleet_cert / "key.pem", d / "pki" / "ca.crt", d / "pki" / "crl.pem")
        self.server.start()
        self.addCleanup(self.server.stop, 1)
        self.service = Service(d / "fleet")
        app = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        self.addCleanup(app.shutdown)
        self.upstream = app.server_address[1]
        self.agent = Agent(f"https://localhost:{self.server.port}", d / "agent", interval=1)
        self.addCleanup(self.agent.shutdown)

    def route(self, port):
        return (f'[[edge]]\nname = "web"\nmode = "terminate"\nlisten = "127.0.0.1:{port}"\ntarget = "127.0.0.1:{self.upstream}"\n'
                f'cert = "{self.edge_cert / "chain.pem"}"\nkey = "{self.edge_cert / "key.pem"}"\n')

    def fetch(self, port, path="/x"):
        ctx = tls.client_context(self.d / "pki" / "ca.crt")
        with tls.connect("127.0.0.1", port, ctx, "localhost", 5) as c:
            return request(c, "GET", path, "localhost")[2]

    def test_agent_runs_what_the_fleet_assigns(self):
        p1, p2 = free_port(), free_port()
        self.service.set_desired("edge-berlin", self.route(p1))
        self.agent.once()
        self.assertEqual(self.fetch(p1, "/a"), b"hello /a")
        a = self.service.agents()[0]
        self.assertTrue(a["online"])
        self.assertEqual((a["name"], a["certificate"]["serial"]), ("edge-berlin", self.agent_rec.serial))
        self.agent.once()
        self.assertTrue(self.service.agents()[0]["in_sync"])
        self.assertIn("web", self.service.agents()[0]["edges"])

        self.service.set_desired("edge-berlin", self.route(p2))
        self.agent.once()
        self.assertEqual(self.fetch(p2), b"hello /x")
        with self.assertRaises(OSError):
            self.fetch(p1)

    def test_broken_config_is_refused_twice(self):
        with self.assertRaises(ValueError):
            self.service.set_desired("edge-berlin", "[[edge]]\nname = 'x'\nmode = 'sideways'\nlisten = '0.0.0.0:1'\ntarget = '1.2.3.4:5'\n")
        p = free_port()
        self.service.set_desired("edge-berlin", self.route(p))
        self.agent.once()
        (self.d / "fleet" / "desired" / "edge-berlin.toml").write_text("this is not toml [")
        self.agent.once()
        self.assertEqual(self.fetch(p), b"hello /x")
        self.agent.once()
        a = self.service.agents()[0]
        self.assertFalse(a["in_sync"])
        self.assertIn("invalid", a["config_error"])

    def test_revoked_or_anonymous_agents_are_refused(self):
        self.agent.once()
        self.ca.revoke(self.agent_rec.serial, "keyCompromise")
        time.sleep(0.05)
        with self.assertRaises((tls.TLSError, HTTPError, OSError)):
            self.agent.once()
        ctx = tls.client_context(self.d / "pki" / "ca.crt")
        with self.assertRaises((tls.TLSError, OSError)):
            with tls.connect("127.0.0.1", self.server.port, ctx, "localhost", 5) as c:
                request(c, "POST", "/v1/report", "localhost", b"{}")

    def test_validate_config(self):
        self.assertEqual(validate_config(""), [])
        self.assertEqual(validate_config(self.route(1))[0].name, "web")


if __name__ == "__main__":
    unittest.main()
