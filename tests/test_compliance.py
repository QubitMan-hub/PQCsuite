import tempfile
import unittest
from pathlib import Path

from pqcsuite import vault
from pqcsuite.readiness import compliance
from pqcsuite.pki import CA


class ComplianceTest(unittest.TestCase):
    def test_every_asset_type_is_classified(self):
        d = Path(tempfile.mkdtemp())
        ca = CA.init(d / "pki", "Root")
        ca.issue("api", "server")
        ca.issue("secret-site", "server", algorithm="ML-DSA-87")
        ca.issue("lapsed", "server")
        records = ca.records()
        records[-1].not_after = "2020-01-01T00:00:00+00:00"
        rows = compliance.certificates(records)
        rows += compliance.endpoints([
            {"target": "a:443", "grade": "A", "accepts": ["SecP384r1MLKEM1024"], "negotiated": "SecP384r1MLKEM1024", "cnsa2": True,
             "certificate": {"key": "ML-DSA-87"}},
            {"target": "b:443", "grade": "B", "accepts": ["X25519MLKEM768", "X25519"], "negotiated": "X25519MLKEM768", "cnsa2": False,
             "certificate": {"key": "ML-DSA-65"}},
            {"target": "c:443", "grade": "A", "accepts": ["X25519MLKEM768"], "negotiated": "X25519MLKEM768", "cnsa2": False,
             "certificate": {"key": "RSA-2048"}},
            {"target": "ssh://d:22", "protocol": "ssh", "grade": "C", "accepts": ["curve25519-sha256"], "negotiated": "curve25519-sha256",
             "cnsa2": False, "certificate": {"key": "ssh-ed25519"}},
            {"target": "e:443", "grade": "F", "accepts": [], "error": "refused", "certificate": None},
        ])
        high = {"state": "ESTABLISHED", "key_exchange": "ECP_384 + ML_KEM_1024", "encryption": "AES_GCM_16_256", "ppk": True,
                "children": [{"encryption": "AES_GCM_16_256"}]}
        rows += compliance.tunnels([{"peer": "hq", **high}, {"peer": "weak-ike", **high, "encryption": "AES_GCM_16_128"},
                                    {"peer": "weak-esp", **high, "children": [{"encryption": "AES_GCM_16_128"}]},
                                    {"peer": "old", "state": "ESTABLISHED", "key_exchange": "CURVE_25519", "encryption": "AES_GCM_16_256", "ppk": False}])
        me = vault.Identity.generate(cnsa2=True)
        (d / "f").write_bytes(b"x")
        vault.encrypt(d / "f", d / "f.pqv", [me.public])
        rows += compliance.backups([{"file": str(d / "f.pqv"), **vault.inspect(d / "f.pqv")}])
        by = {r["name"]: r for r in rows}
        self.assertEqual((by["secret-site"]["cnsa2"], by["api"]["cnsa2"]), ("compliant", "needs ML-DSA-87"))
        self.assertEqual([by[n]["status"] for n in ("a:443", "b:443", "c:443", "ssh://d:22", "e:443")], ["ready", "transition", "transition", "action", "action"])
        self.assertIn("RSA-2048 certificate: deprecated after 2030", by["c:443"]["nist_ir_8547"])
        self.assertEqual((by["hq"]["cnsa2"], by["old"]["status"]), ("compliant", "action"))
        self.assertEqual([by[n]["cnsa2"].split(" ")[0] for n in ("weak-ike", "weak-esp")], ["needs", "needs"])
        self.assertEqual((by["lapsed"]["status"], by["lapsed"]["cnsa2"]), ("action", "needs ML-DSA-87"))
        self.assertEqual((by["f"]["cnsa2"], by["f"]["cnsa2_deadline"]), ("compliant", 2033))
        rep = compliance.report(rows)
        self.assertEqual(rep["cnsa2_compliant"], 4)
        page = compliance.to_html(rep)
        self.assertIn("need action", page)
        self.assertNotIn("<script", page)


if __name__ == "__main__":
    unittest.main()
