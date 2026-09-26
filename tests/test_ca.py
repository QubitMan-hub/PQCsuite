import datetime as dt
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pqcsuite.pki import CA, CAError, check_revocation, generate


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

    def test_site_certificate_serves_and_connects(self):
        out, rec = self.ca.issue("hq.acme", "site", ["203.0.113.10"])
        cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        eku = list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        self.assertEqual(eku, [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
        self.assertEqual(rec.names, ["hq.acme", "203.0.113.10"])

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
        check_revocation(cert.serial_number, self.ca.crl(), self.ca.cert)
        crl = self.ca.revoke(rec.serial[:10], "keyCompromise")
        with self.assertRaisesRegex(CAError, "revoked"):
            check_revocation(cert.serial_number, crl, self.ca.cert)
        with self.assertRaises(CAError):
            self.ca.revoke(rec.serial)
        self.assertEqual(self.ca.find(rec.serial).reason, "keyCompromise")

    def test_concurrent_revocations_all_reach_the_crl(self):
        from concurrent.futures import ThreadPoolExecutor
        recs = [self.ca.issue(f"c{i}", "client")[1] for i in range(8)]
        with ThreadPoolExecutor(8) as pool:
            list(pool.map(lambda r: self.ca.revoke(r.serial), recs))
        crl = x509.load_pem_x509_crl((self.root / "crl.pem").read_bytes())
        self.assertEqual({format(r.serial_number, "x") for r in crl}, {r.serial for r in recs})

    def test_crl_from_another_ca_is_rejected(self):
        other = CA.init(Path(self.tmp.name) / "other", "Other")
        out, _ = self.ca.issue("carol", "client")
        cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        with self.assertRaisesRegex(CAError, "not signed"):
            check_revocation(cert.serial_number, other.crl(), self.ca.cert)

    def test_renew_keeps_names_with_a_new_key(self):
        out1, r1 = self.ca.issue("svc", "server", ["svc.local"])
        out2, r2 = self.ca.renew(r1.serial)
        self.assertNotEqual(r1.serial, r2.serial)
        self.assertEqual(r2.names, ["svc", "svc.local"])
        self.assertNotEqual((out1 / "key.pem").read_bytes(), (out2 / "key.pem").read_bytes())
        self.assertEqual({r.common_name for r in self.ca.expiring(within_days=400)}, {"svc"})

    def test_maintain_renews_in_place_and_refreshes_the_crl(self):
        out, soon = self.ca.issue("edge.local", "server", days=10, out=Path(self.tmp.name) / "edge")
        self.ca.issue("far.local", "server", days=300)
        self.ca.issue("locked.local", "server", days=5, passphrase=b"x", out=Path(self.tmp.name) / "locked")
        before = (out / "cert.pem").read_bytes()
        renewed, skipped = self.ca.maintain(renew_within=30)
        self.assertEqual([r.common_name for r in renewed], ["edge.local"])
        self.assertEqual([r.common_name for r in skipped], ["locked.local"])
        self.assertNotEqual((out / "cert.pem").read_bytes(), before)
        cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        self.assertGreater(cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc), dt.timedelta(days=300))
        self.assertEqual(self.ca.maintain(renew_within=30)[0], [], "a renewed certificate is not renewed again")
        crl = x509.load_pem_x509_crl((self.root / "crl.pem").read_bytes())
        self.assertGreater(crl.next_update_utc, dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=6))
        self.assertTrue(soon)

    def test_bad_inputs_are_clear_errors(self):
        with self.assertRaisesRegex(CAError, "kind"):
            self.ca.issue("x", "admin")
        with self.assertRaisesRegex(CAError, "unknown algorithm"):
            self.ca.issue("x", "server", algorithm="RSA-2048")
        with self.assertRaisesRegex(CAError, "no certificate"):
            self.ca.find("ffff")
        with self.assertRaisesRegex(CAError, "1 to 64"):
            self.ca.issue("", "client")
        with self.assertRaisesRegex(CAError, "not a valid host name"):
            self.ca.issue("bad name", "server")
        with self.assertRaisesRegex(CAError, "not a valid host name"):
            self.ca.issue("web", "server", names=["web", "-x.example"])
        with self.assertRaisesRegex(CAError, "not a certificate signing request"):
            self.ca.sign_csr(b"hello", "server")
        out, _ = self.ca.issue("*.corp.example", "server", names=["*.corp.example", "10.0.0.1", "::1"])
        self.assertTrue(out.name.startswith("_.corp.example-"))
        self.ca.issue("Ana María", "client")

    def test_issue_never_overwrites_a_key_and_revoked_certificates_are_not_renewed(self):
        out = Path(self.tmp.name) / "web"
        _, rec = self.ca.issue("web.example", "server", out=out)
        key = (out / "key.pem").read_bytes()
        with self.assertRaisesRegex(CAError, "already holds a key"):
            self.ca.issue("web.example", "server", out=out)
        self.assertEqual((out / "key.pem").read_bytes(), key)
        _, new = self.ca.renew(rec.serial, out=out)
        self.assertNotEqual((out / "key.pem").read_bytes(), key)
        self.ca.revoke(new.serial)
        with self.assertRaisesRegex(CAError, "is revoked"):
            self.ca.renew(new.serial, out=out)


if __name__ == "__main__":
    unittest.main()
