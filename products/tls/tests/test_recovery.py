"""Disaster recovery: back the CA folder up with any tool, lose the machine, restore
it elsewhere, and carry on: existing clients still connect, a revoked one is still refused, new certificates can be issued and
revoked. The restore time is measured."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from acxelin_core import tls
from acxelin_core.pki import CA
from acxelin_core.server import Server
import support_tls
from support_tls import REASON


def cli(*args, cwd):
    r = subprocess.run([sys.executable, "-m", "acxelin_tls", *map(str, args)], cwd=cwd, capture_output=True, text=True, env={**os.environ, "ACXELIN_TLS_CA_PASSPHRASE": "ca-pass"})
    if r.returncode:
        raise AssertionError(f"acxelin-tls {' '.join(map(str, args))} failed: {r.stderr}")
    return r.stdout


@unittest.skipIf(REASON, REASON)
class RecoveryTest(unittest.TestCase):
    def test_lose_the_ca_machine_and_restore_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            cli("ca", "init", "--dir", "pki", "--name", "DR Root", "--encrypt", cwd=d)
            cli("ca", "issue", "--dir", "pki", "server", "localhost", "--san", "127.0.0.1", "--out", "srv", cwd=d)
            cli("ca", "issue", "--dir", "pki", "client", "alice", "--out", "alice", cwd=d)
            cli("ca", "issue", "--dir", "pki", "client", "mallory", "--out", "mallory", cwd=d)
            mallory = next(r for r in CA(d / "pki").records() if r.common_name == "mallory").serial
            cli("ca", "revoke", "--dir", "pki", mallory, cwd=d)
            shutil.copytree(d / "pki", d / "backup" / "pki")  # the operator's own backup of the CA folder, made with any tool

            shutil.rmtree(d / "pki")
            start = time.monotonic()
            shutil.copytree(d / "backup", d / "restored")
            root = d / "restored" / "pki"
            cli("ca", "list", "--dir", root, cwd=d)
            restore_s = time.monotonic() - start

            cafile = str(root / "ca.crt")
            make = lambda: support_tls.server_context(d / "srv" / "chain.pem", d / "srv" / "key.pem", cafile, True)
            s = Server(("127.0.0.1", 0), make, lambda conn, addr: conn.sendall(b"ok"), crl=str(root / "crl.pem"), ca=cafile, handshake_timeout=5)
            s.start()
            self.addCleanup(s.stop, 1)

            def connects(who):
                try:
                    ctx = support_tls.client_context(cafile, d / who / "chain.pem", d / who / "key.pem")
                    with tls.connect("127.0.0.1", s.port, ctx, "localhost", 5) as c:
                        return c.recv(timeout=5) == b"ok"
                except (tls.TLSError, OSError):
                    return False
            self.assertTrue(connects("alice"), "an existing client works against the restored CA")
            self.assertFalse(connects("mallory"), "a revocation made before the backup survives the restore")
            cli("ca", "issue", "--dir", root, "client", "bob", "--out", "bob", cwd=d)
            self.assertTrue(connects("bob"), "the restored CA issues certificates the edge trusts")
            bob = next(r for r in CA(root).records() if r.common_name == "bob").serial
            cli("ca", "revoke", "--dir", root, bob, cwd=d)
            time.sleep(0.05)
            self.assertFalse(connects("bob"), "the restored CA can revoke")
            self.assertLess(restore_s, 30, f"restoring the CA took {restore_s:.1f} s")


if __name__ == "__main__":
    unittest.main()
