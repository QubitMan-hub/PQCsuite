"""EST enrollment never records a token's secret in its audit log or at rest."""
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from acxelin_core.https import HTTPError
from acxelin_core.pki import CA, generate
from acxelin_core.pki.est import Service, create_token
from cryptography.hazmat.primitives import serialization


def everything_under(d):
    return b"".join(p.read_bytes() for p in Path(d).rglob("*") if p.is_file())


class ESTSecretsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)

    def test_enrollment_audit_never_records_a_token_secret(self):
        ca = CA.init(self.d / "pki", "Root")
        token = create_token(ca, "dev.test", "client", [], 1)
        tid, secret = token.split(".", 1)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        key = generate("ML-DSA-44")
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dev.test")]))
               .sign(key, None).public_bytes(serialization.Encoding.DER))
        est = Service(ca)
        for auth in (f"{tid}:wrong{secret}", f"{tid}:{secret}", f"{tid}:{secret}"):
            try:
                est("POST", "/.well-known/est/simpleenroll", {"authorization": "Basic " + base64.b64encode(auth.encode()).decode()},
                    base64.b64encode(csr), None)
            except HTTPError:
                pass
        audit = (self.d / "pki" / "est-audit.jsonl").read_text()
        self.assertEqual([json.loads(line)["event"] for line in audit.splitlines()], ["enroll_refused", "enrolled", "enroll_refused"])
        self.assertNotIn(secret, audit)
        self.assertNotIn(secret.encode(), everything_under(self.d / "pki"))
        if os.name != "nt":
            self.assertEqual(os.stat(self.d / "pki" / "est-audit.jsonl").st_mode & 0o077, 0, "the audit log is owner-only")


if __name__ == "__main__":
    unittest.main()
