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
        self.assertIn("unverified header", by["f"]["detail"])
        self.assertIs(by["f"]["evidence"]["authenticated"], False)
        rep = compliance.report(rows)
        self.assertEqual(rep["cnsa2_compliant"], 4)
        page = compliance.to_html(rep)
        self.assertIn("need action", page)
        self.assertIn("Backup classifications describe unverified headers", page)
        self.assertNotIn("<script", page)

    def test_wolfpack_scan_becomes_code_rows_that_cite_locations_and_callers(self):
        import json
        d = Path(tempfile.mkdtemp())
        props = lambda tier, **kw: [{"name": f"wolfpack:{k}", "value": v} for k, v in dict(tier=tier, **kw).items()]
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "payments"}}, "components": [
            {"type": "cryptographic-asset", "name": "RSA-1024", "evidence": {"occurrences": [{"location": "keys.py", "line": 7}]},
             "properties": props("critical", **{"nist-status": "Disallowed now", "recommendation": "ML-DSA-65",
                                                "code-impact": json.dumps({"callers": ["checkout.py#enroll"]})})},
            {"type": "cryptographic-asset", "name": "AES-256-GCM", "properties": props("ok")},
            {"type": "cryptographic-asset", "name": "<script>alert(1)</script>", "properties": props("medium", **{"code-impact": "{not json"})},
            {"type": "library", "name": "cryptography"}]}
        (d / "cbom.json").write_text(json.dumps(bom))
        (d / "findings.json").write_text(json.dumps({"patterns": [
            {"rule": "WPC001", "title": "Certificate verification switched off", "cwe": "CWE-295", "severity": "high", "file": "client.py", "line": 3, "fix": "verify"},
            {"rule": "WPC002", "title": "Secret written into source code", "cwe": "CWE-798", "severity": "low", "file": "tests/t.py", "line": 1, "fix": "x"}]}))
        rows = compliance.code(d)
        by = {r["name"]: r for r in rows}
        self.assertEqual([by[n]["status"] for n in ("RSA-1024", "AES-256-GCM", "<script>alert(1)</script>")], ["action", "ready", "transition"])
        self.assertIn("keys.py:7", by["RSA-1024"]["detail"])
        self.assertIn("checkout.py#enroll", by["RSA-1024"]["detail"])
        self.assertEqual((by["AES-256-GCM"]["cnsa2"], by["RSA-1024"]["cnsa2_deadline"]), ("compliant", 2033))
        self.assertIn("client.py:3", by["WPC001 Certificate verification switched off"]["detail"])
        self.assertFalse(any(r["name"].startswith("WPC002") for r in rows), "test-only patterns are not compliance rows")
        self.assertEqual(compliance.code(d / "cbom.json")[0]["name"], "RSA-1024")
        self.assertNotIn("<script>alert", compliance.to_html(compliance.report(rows)))

    def test_wolfpack_input_that_is_not_a_cbom_is_refused(self):
        d = Path(tempfile.mkdtemp())
        for name, data in (("cbom.json", b"[1, 2]"), ("bad.json", b"{not json"), ("other.json", b'{"bomFormat": "SPDX"}')):
            (d / name).write_bytes(data)
            with self.assertRaises(ValueError):
                compliance.code(d / name)
        big = d / "big.json"
        with open(big, "wb") as f:
            f.truncate(compliance.LIMIT + 1)
        with self.assertRaisesRegex(ValueError, "larger than"):
            compliance.code(big)


if __name__ == "__main__":
    unittest.main()
