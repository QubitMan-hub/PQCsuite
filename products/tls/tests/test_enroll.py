"""A machine enrolls over EST with a one-time token, then uses its certificate for mutual TLS (through the installed commands)."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from acxelin_core import tls
from acxelin_core.pki import CA
from acxelin_core.pki.est import fingerprint

import support_tls
from support_tls import REASON


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"nothing listens on {port}")


@unittest.skipIf(REASON, REASON)
class EnrollTest(unittest.TestCase):
    def test_est_enroll_then_mutual_tls(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ca = CA.init(d / "pki", "Root")
            est_dir, _ = ca.issue("ca.internal", "server", ["127.0.0.1"], out=d / "est")
            port = free_port()
            run = lambda *a, **kw: subprocess.run([sys.executable, "-m", "acxelin_tls", *map(str, a)], capture_output=True, text=True, timeout=60, **kw)
            server = subprocess.Popen([sys.executable, "-m", "acxelin_tls", "ca", "serve", "--dir", str(d / "pki"), "--listen", f"127.0.0.1:{port}",
                                       "--cert", str(est_dir / "chain.pem"), "--key", str(est_dir / "key.pem")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(server.wait, 10)
            self.addCleanup(server.terminate)
            wait_port(port)
            token = run("ca", "token", "--dir", d / "pki", "client", "laptop-7").stdout.strip().splitlines()[-1]
            fp = fingerprint(ca.cert)
            enroll = ["ca", "enroll", f"https://127.0.0.1:{port}", "--cn", "laptop-7", "--ca-fingerprint", fp, "--server-name", "ca.internal"]
            r = run(*enroll, "--out", d / "laptop", env={**os.environ, "ACXELIN_TLS_ENROLL_TOKEN": token})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotEqual(run(*enroll, "--token", token, "--out", d / "again").returncode, 0, "a token works once")
            before = (d / "laptop" / "cert.pem").read_bytes()
            r = run("ca", "enroll", f"https://127.0.0.1:{port}", "--renew", d / "laptop", "--server-name", "ca.internal")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotEqual((d / "laptop" / "cert.pem").read_bytes(), before)
            ctx = support_tls.client_context(d / "laptop" / "ca.crt", d / "laptop" / "chain.pem", d / "laptop" / "key.pem")
            with tls.connect("127.0.0.1", port, ctx, "ca.internal", 10) as c:
                self.assertIsNotNone(c.peer_certificate())
