"""Races on shared state: the CA folder written by several processes at once (the CLI, the console and the enrollment server
may share it), two administrators in the console, and a revocation landing while clients are connecting."""
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509

from pqcsuite import tls
from pqcsuite.console import App, Settings
from pqcsuite.pki import CA, verify_crl
from pqcsuite.tls.server import Server
from tests.helpers import REASON


WORKER = textwrap.dedent("""
    import sys
    from pqcsuite.pki import CA
    ca = CA(sys.argv[1])
    for i in range(5):
        _, rec = ca.issue(f"p{sys.argv[2]}-{i}.test", "server")
        if i % 2:
            ca.revoke(rec.serial)
""")


def listed(root):
    return {format(r.serial_number, "x") for r in x509.load_pem_x509_crl((Path(root) / "crl.pem").read_bytes())}


class RaceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.root = self.d / "pki"
        self.ca = CA.init(self.root, "Root")

    def test_processes_issuing_and_revoking_at_once_lose_nothing(self):
        procs = [subprocess.Popen([sys.executable, "-c", WORKER, str(self.root), str(n)]) for n in range(6)]
        self.assertEqual([p.wait(120) for p in procs], [0] * 6)
        recs = CA(self.root).records()
        self.assertEqual(len(recs), 30)
        self.assertEqual(len({r.serial for r in recs}), 30)
        revoked = {r.serial for r in recs if r.status == "revoked"}
        self.assertEqual(len(revoked), 12)
        self.assertEqual(revoked, listed(self.root))
        verify_crl((self.root / "crl.pem").read_bytes(), x509.load_pem_x509_certificates((self.root / "ca.crt").read_bytes()))

    def test_enrollment_tokens_and_eab_keys_made_at_once_are_all_kept(self):
        worker = textwrap.dedent("""
            import sys
            from pqcsuite.pki import CA
            from pqcsuite.pki.acme import create_eab
            from pqcsuite.pki.est import create_token
            for i in range(5):
                create_token(CA(sys.argv[1]), f"t{sys.argv[2]}-{i}.test", "server")
                create_eab(sys.argv[1])
        """)
        procs = [subprocess.Popen([sys.executable, "-c", worker, str(self.root), str(n)]) for n in range(6)]
        self.assertEqual([p.wait(120) for p in procs], [0] * 6)
        from pqcsuite.pki.acme import eab_keys
        from pqcsuite.pki.est import _load_tokens
        self.assertEqual((len(_load_tokens(self.root)), len(eab_keys(self.root))), (30, 30))

    def test_renewing_and_revoking_the_same_certificate_at_once(self):
        for n in range(6):
            _, rec = self.ca.issue(f"race{n}.test", "server")
            with ThreadPoolExecutor(2) as pool:
                renewed = pool.submit(self.ca.renew, rec.serial)
                revoked = pool.submit(self.ca.revoke, rec.serial)
            self.assertIsNone(revoked.exception())
            if renewed.exception() is None:
                new = renewed.result()[1]
                self.assertEqual(self.ca.find(new.serial).status, "valid", "a renewal before the revocation keeps its new certificate")
            else:
                self.assertIn("revoked", str(renewed.exception()), "a renewal after the revocation must be refused")
            self.assertIn(rec.serial, listed(self.root))

    def test_two_console_administrators_at_once(self):
        app = App(Settings(ca=str(self.root), audit_log=str(self.d / "audit.jsonl")), token="t")

        def admin(who):
            done = []
            for i in range(6):
                status, out = app.handle("POST", "/api/certificates/issue", {"kind": "client", "common_name": f"{who}-{i}"})
                self.assertEqual(status, 200, out)
                done.append(out["serial"])
            for s in done[::2]:
                self.assertEqual(app.handle("POST", "/api/certificates/revoke", {"serial": s})[0], 200)
            return done
        with ThreadPoolExecutor(2) as pool:
            issued = [s for f in [pool.submit(admin, "ann"), pool.submit(admin, "bo")] for s in f.result()]
        recs = {r.serial: r for r in CA(self.root).records()}
        self.assertLessEqual(set(issued), set(recs))
        self.assertEqual(sum(r.status == "revoked" for r in recs.values()), 6)
        self.assertEqual(len((self.d / "audit.jsonl").read_text().splitlines()), 18)

    @unittest.skipIf(REASON, REASON)
    def test_no_handshake_succeeds_once_the_revocation_is_written(self):
        srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=self.d / "srv")
        who, rec = self.ca.issue("laptop", "client", out=self.d / "laptop")
        cafile = str(self.root / "ca.crt")

        def echo(conn, addr):
            conn.sendall(b"ok")
        make = lambda: tls.server_context(srv / "chain.pem", srv / "key.pem", cafile, True)
        s = Server(("127.0.0.1", 0), make, echo, crl=str(self.root / "crl.pem"), ca=cafile, handshake_timeout=5)
        s.start()
        self.addCleanup(s.stop, 1)
        ctx = tls.client_context(cafile, who / "chain.pem", who / "key.pem")
        results, stop, revoked_at = [], threading.Event(), []

        def hammer():
            while not stop.is_set():
                start = time.monotonic()
                try:
                    with tls.connect("127.0.0.1", s.port, ctx, "localhost", 5) as c:
                        ok = c.recv(timeout=5) == b"ok"
                except (tls.TLSError, OSError):
                    ok = False
                results.append((start, ok))
        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.5)
        self.ca.revoke(rec.serial)
        revoked_at.append(time.monotonic())
        time.sleep(1.0)
        stop.set()
        for t in threads:
            t.join()
        before = [ok for t0, ok in results if t0 < revoked_at[0] - 0.2]
        after = [ok for t0, ok in results if t0 > revoked_at[0]]
        self.assertTrue(before and all(before), "the client worked before the revocation")
        self.assertTrue(after)
        self.assertFalse(any(after), "a handshake that started after the CRL was written succeeded")


if __name__ == "__main__":
    unittest.main()
