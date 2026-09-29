"""Disaster recovery, with the commands docs/THREAT-MODEL.md gives: back the CA folder up with Vault, lose the machine, restore
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

from pqcsuite import tls
from pqcsuite.pki import CA
from pqcsuite.tls.server import Server
from tests.helpers import REASON


def cli(*args, cwd):
    r = subprocess.run([sys.executable, "-m", "pqcsuite", *map(str, args)], cwd=cwd, capture_output=True, text=True, env={**os.environ, "PQCSUITE_CA_PASSPHRASE": "ca-pass"})
    if r.returncode:
        raise AssertionError(f"pqcsuite {' '.join(map(str, args))} failed: {r.stderr}")
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
            cli("vault", "keygen", "ops", "--no-passphrase", cwd=d)
            cli("vault", "keygen", "offline", "--no-passphrase", cwd=d)
            cli("vault", "backup", "pki", "--to", "backups", "-r", "ops.pub", "-r", "offline.pub", cwd=d)
            archive = next((d / "backups").glob("*.pqv"))
            self.assertIn("nothing was written", cli("vault", "verify", archive, "--key", "offline.key", cwd=d))

            shutil.rmtree(d / "pki")
            start = time.monotonic()
            archive = next((d / "backups").glob("*.pqv"))
            cli("vault", "decrypt", archive, "--key", "offline.key", "-o", "restored", cwd=d)
            root = d / "restored" / "pki"
            cli("ca", "list", "--dir", root, cwd=d)
            restore_s = time.monotonic() - start

            cafile = str(root / "ca.crt")
            make = lambda: tls.server_context(d / "srv" / "chain.pem", d / "srv" / "key.pem", cafile, True)
            s = Server(("127.0.0.1", 0), make, lambda conn, addr: conn.sendall(b"ok"), crl=str(root / "crl.pem"), ca=cafile, handshake_timeout=5)
            s.start()
            self.addCleanup(s.stop, 1)

            def connects(who):
                try:
                    ctx = tls.client_context(cafile, d / who / "chain.pem", d / who / "key.pem")
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
