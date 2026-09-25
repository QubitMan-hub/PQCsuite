import datetime as dt
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqcsuite import scan, tls
from pqcsuite.ca import CA
from pqcsuite.tls.openssl import Context
from pqcsuite.tls.server import Server

try:
    tls.lib()
    REASON = None
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


def rsa_cert(d):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=20)).sign(key, hashes.SHA256()))
    (d / "rsa.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "rsa.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return d / "rsa.pem", d / "rsa.key"


@unittest.skipIf(REASON, REASON)
class ScanTest(unittest.TestCase):
    def test_grades_and_report(self):
        d = Path(tempfile.mkdtemp())
        out, _ = CA.init(d / "pki", "Root").issue("localhost", "server", out=d / "srv")
        rcert, rkey = rsa_cert(d)
        servers = {
            "A": lambda: tls.server_context(out / "chain.pem", out / "key.pem", policy_name="strict"),
            "B": lambda: tls.server_context(out / "chain.pem", out / "key.pem", policy_name="transition"),
            "C": lambda: Context(True, "X25519:secp256r1", None, tls.CIPHERSUITES, rcert, rkey),
        }
        ports = {}
        for grade, make in servers.items():
            s = Server(("127.0.0.1", 0), make, lambda c, a: None)
            s.start()
            self.addCleanup(s.stop, 1)
            ports[grade] = s.port
        results = scan.scan([f"127.0.0.1:{p}" for p in ports.values()] + ["127.0.0.1:1"], timeout=3)
        by = {r["target"]: r for r in results}
        for grade, port in ports.items():
            self.assertEqual(by[f"127.0.0.1:{port}"]["grade"], grade)
        self.assertEqual(by["127.0.0.1:1"]["grade"], "F")
        self.assertEqual(by[f"127.0.0.1:{ports['A']}"]["certificate"]["key"], "ML-DSA-65")
        self.assertEqual(by[f"127.0.0.1:{ports['C']}"]["certificate"]["key"], "RSA-2048")
        self.assertEqual(by[f"127.0.0.1:{ports['B']}"]["negotiated"], "X25519MLKEM768")
        s = scan.summary(results)
        self.assertEqual((s["pq_key_exchange"], s["pq_certificates"], s["expiring_30d"]), (2, 2, 1))
        page = scan.report_html(results)
        self.assertIn("2/4", page)
        self.assertNotIn("<script", page)


if __name__ == "__main__":
    unittest.main()
