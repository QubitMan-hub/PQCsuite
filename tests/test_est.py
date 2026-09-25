import tempfile
import time
import unittest
from pathlib import Path

from cryptography import x509

from pqcsuite import est, tls
from pqcsuite.ca import CA, CAError, generate

try:
    tls.lib()
    REASON = None
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


@unittest.skipIf(REASON, REASON)
class ESTTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.ca = CA.init(self.d / "pki", "Enrollment Root")
        srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=self.d / "srv")
        self.server = est.serve(self.d / "pki", "127.0.0.1:0", srv / "chain.pem", srv / "key.pem")
        self.server.start()
        self.addCleanup(self.server.stop, 1)
        self.url = f"https://localhost:{self.server.port}"
        self.cafile = self.d / "pki" / "ca.crt"

    def test_trust_bootstrap_by_fingerprint(self):
        got = est.fetch_ca(self.url, est.fingerprint(self.ca.cert), self.d / "ca.crt")
        self.assertEqual(got, self.ca.cert)
        with self.assertRaisesRegex(CAError, "do not trust"):
            est.fetch_ca(self.url, "00" * 32, self.d / "bad.crt")

    def test_enroll_once_with_a_token_bound_to_one_name(self):
        token = est.create_token(self.ca, "web1.acme", "server", ["10.0.0.7"])
        cert = est.enroll(self.url, token, "web1.acme", ["web1.acme", "10.0.0.7"], self.d / "web1", self.cafile)
        cert.verify_directly_issued_by(self.ca.cert)
        self.assertEqual((self.d / "web1" / "cert.pem").read_bytes().count(b"BEGIN"), 1)
        self.assertIn(b"PRIVATE KEY", (self.d / "web1" / "key.pem").read_bytes())
        with self.assertRaisesRegex(CAError, "401.*already used"):
            est.enroll(self.url, token, "web1.acme", [], self.d / "again", self.cafile)
        log = (self.d / "pki" / "est-audit.jsonl").read_text()
        self.assertIn('"enrolled"', log)

    def test_tokens_cannot_be_stretched_or_guessed(self):
        token = est.create_token(self.ca, "web2.acme", "server")
        with self.assertRaisesRegex(CAError, "403.*this token is for web2.acme"):
            est.enroll(self.url, token, "admin.acme", [], self.d / "x", self.cafile)
        with self.assertRaisesRegex(CAError, "403"):
            est.enroll(self.url, token, "web2.acme", ["web2.acme", "evil.acme"], self.d / "x", self.cafile)
        tid = token.split(".")[0]
        with self.assertRaisesRegex(CAError, "401"):
            est.enroll(self.url, f"{tid}.wrong-secret", "web2.acme", [], self.d / "x", self.cafile)
        expired = est.create_token(self.ca, "web3.acme", "server", hours=-1)
        with self.assertRaisesRegex(CAError, "401.*expired"):
            est.enroll(self.url, expired, "web3.acme", [], self.d / "x", self.cafile)
        self.assertNotIn(token.split(".")[1], (self.d / "pki" / "tokens.json").read_text())

    def test_renewal_in_place_keeps_identity(self):
        token = est.create_token(self.ca, "db.acme", "server")
        first = est.enroll(self.url, token, "db.acme", [], self.d / "db", self.cafile)
        self.assertIsNone(est.renew(self.url, self.d / "db", within_days=30))
        second = est.renew(self.url, self.d / "db")
        self.assertNotEqual(first.serial_number, second.serial_number)
        self.assertEqual(x509.load_pem_x509_certificate((self.d / "db" / "cert.pem").read_bytes()), second)
        self.ca.revoke(format(second.serial_number, "x"))
        time.sleep(0.05)
        with self.assertRaisesRegex(CAError, "403.*revoked"):
            est.renew(self.url, self.d / "db")

    def test_renewal_cannot_become_someone_else(self):
        token = est.create_token(self.ca, "app.acme", "server")
        est.enroll(self.url, token, "app.acme", [], self.d / "app", self.cafile)
        ctx = tls.client_context(self.cafile, self.d / "app" / "chain.pem", self.d / "app" / "key.pem")
        with self.assertRaisesRegex(CAError, "403.*keeps its identity"):
            est._call(self.url, ctx, "/simplereenroll", est._csr(generate("ML-DSA-65"), "ca-admin.acme", []), {})
        with self.assertRaisesRegex(CAError, "401"):
            est._call(self.url, tls.client_context(self.cafile), "/simplereenroll", est._csr(generate("ML-DSA-65"), "app.acme", []), {})


if __name__ == "__main__":
    unittest.main()
