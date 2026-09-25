import datetime as dt
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pqcsuite.ca import CA, CAError, check_revocation, generate


class CATest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "pki"
        self.ca = CA.init(self.root, "Test Root", passphrase=b"root-pass")

    def tearDown(self):
        self.tmp.cleanup()

    def test_root_is_an_ml_dsa_ca(self):
        c = self.ca.cert
        self.assertEqual(c.signature_algorithm_oid.dotted_string, "2.16.840.1.101.3.4.3.19")
        self.assertTrue(c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertIn(b"ENCRYPTED", (self.root / "ca.key").read_bytes())
        with self.assertRaises(CAError):
            CA(self.root, b"wrong")
        with self.assertRaises(CAError):
            CA.init(self.root, "again")

    def test_server_certificate_chains_to_the_root(self):
        out, rec = self.ca.issue("api.example.com", "server", ["api.example.com", "10.0.0.5"])
        cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        cert.verify_directly_issued_by(self.ca.cert)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), ["api.example.com"])
        self.assertEqual([str(i) for i in san.get_values_for_type(x509.IPAddress)], ["10.0.0.5"])
        self.assertEqual(list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [ExtendedKeyUsageOID.SERVER_AUTH])
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual((out / "chain.pem").read_bytes().count(b"BEGIN CERTIFICATE"), 2)
        self.assertEqual(rec.algorithm, "ML-DSA-65")

    def test_client_certificate_and_validity_capped_by_root(self):
        _, rec = self.ca.issue("alice", "client", days=100000)
        self.assertLessEqual(dt.datetime.fromisoformat(rec.not_after), self.ca.cert.not_valid_after_utc)
        self.assertEqual(rec.names, [])

    def test_csr_is_signed_with_its_names(self):
        key = generate("ML-DSA-44")
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "edge")]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("edge.local")]), critical=False).sign(key, None))
        cert, rec = self.ca.sign_csr(csr.public_bytes(serialization.Encoding.PEM), "server")
        self.assertEqual(rec.names, ["edge.local"])
        self.assertEqual(rec.algorithm, "ML-DSA-44")
        cert.verify_directly_issued_by(self.ca.cert)

    def test_revocation_reaches_the_crl(self):
        out, rec = self.ca.issue("bob", "client")
        cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        check_revocation(cert, self.ca.crl(), self.ca.cert)
        crl = self.ca.revoke(rec.serial[:10], "keyCompromise")
        with self.assertRaisesRegex(CAError, "revoked"):
            check_revocation(cert, crl, self.ca.cert)
        with self.assertRaises(CAError):
            self.ca.revoke(rec.serial)
        self.assertEqual(self.ca.find(rec.serial).reason, "keyCompromise")

    def test_crl_from_another_ca_is_rejected(self):
        other = CA.init(Path(self.tmp.name) / "other", "Other")
        out, _ = self.ca.issue("carol", "client")
        cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        with self.assertRaisesRegex(CAError, "not signed"):
            check_revocation(cert, other.crl(), self.ca.cert)

    def test_renew_keeps_names_with_a_new_key(self):
        out1, r1 = self.ca.issue("svc", "server", ["svc.local"])
        out2, r2 = self.ca.renew(r1.serial)
        self.assertNotEqual(r1.serial, r2.serial)
        self.assertEqual(r2.names, ["svc", "svc.local"])
        self.assertNotEqual((out1 / "key.pem").read_bytes(), (out2 / "key.pem").read_bytes())
        self.assertEqual({r.common_name for r in self.ca.expiring(within_days=400)}, {"svc"})

    def test_bad_inputs_are_clear_errors(self):
        with self.assertRaisesRegex(CAError, "kind"):
            self.ca.issue("x", "admin")
        with self.assertRaisesRegex(CAError, "unknown algorithm"):
            self.ca.issue("x", "server", algorithm="RSA-2048")
        with self.assertRaisesRegex(CAError, "no certificate"):
            self.ca.find("ffff")


if __name__ == "__main__":
    unittest.main()
