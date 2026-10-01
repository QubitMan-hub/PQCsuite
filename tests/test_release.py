"""The release gate: a release is refused when any required job failed, is missing or was skipped."""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import release_readiness as rr  # noqa: E402

BENCH = {f"tls_handshake_{g}": {"median_ms": 1, "p95_ms": 2} for g in ("X25519MLKEM768", "X25519")} | {
    "ca_issue_ML-DSA-65": {"median_ms": 1}, "vault_64MiB": {"encrypt_MiB_s": 1, "decrypt_MiB_s": 1},
    "load": {"clients": 32, "seconds": 10, "connections_per_s": 400, "median_ms": 70, "p99_ms": 90, "errors": 0}}
EVIDENCE = {"tests": "1 run", "tests_exit_code": 0, "fuzz_tests": 1, "hostile_tests": 1, "openssl": "OpenSSL 3.5", "python": "3.13", "sbom_components": 1,
            "benchmark": BENCH}


def green():
    names = [f"{c}{i})" if c.endswith("(") else c for g in rr.GATES.values() for _, c, n in g for i in range(n)]
    return {n: {"name": n, "status": "completed", "conclusion": "success", "html_url": "u"} for n in names}


class GateTest(unittest.TestCase):
    def test_all_green_passes_and_says_what_is_not_validated(self):
        ok, text = rr.report("v1.0.0", "abc", EVIDENCE, green())
        self.assertTrue(ok)
        self.assertIn("## Not yet validated", text)
        self.assertIn("Independent security", text)

    def test_failed_or_missing_local_evidence_blocks_green_ci(self):
        for status in (1, 2, 5, None):
            evidence = dict(EVIDENCE, tests_exit_code=status)
            ok, text = rr.report("v1.0.0", "abc", evidence, green())
            self.assertFalse(ok)
            self.assertIn("must not be released", text)

    def test_a_failed_missing_or_skipped_job_blocks_the_release(self):
        for change in ("failure", "skipped", None):
            with self.subTest(change=change):
                runs = green()
                if change:
                    runs["ci/docker"]["conclusion"] = change
                else:
                    del runs["ci/vpn"]
                ok, text = rr.report("v1.0.0", "abc", EVIDENCE, runs)
                self.assertFalse(ok)
                self.assertIn("must not be released", text)


class EvidenceTest(unittest.TestCase):
    def test_function_style_failures_and_empty_suites_block_evidence(self):
        import json
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            (root / "scripts" / "benchmark.py").write_text("print('{}')")
            (root / "sbom.json").write_text('{"components": []}')
            for code, expected in (("def test_customer_flow(): assert True", True),
                                   ("def test_customer_flow(): assert False", False), ("", False)):
                with self.subTest(code=code), mock.patch.object(rr, "ROOT", root), \
                        mock.patch("pqcsuite.tls.lib", return_value=mock.Mock(version="test TLS version")):
                    (root / "test_customer.py").write_text(code)
                    self.assertEqual(rr.evidence(root / "evidence.json", root / "sbom.json"), expected)
                    result = json.loads((root / "evidence.json").read_text())
                    self.assertEqual(result["tests_exit_code"] == 0, expected)


class SinceTest(unittest.TestCase):
    def test_new_dependencies_and_new_cryptography_are_listed(self):
        from unittest import mock
        sbom = lambda **v: {"components": [{"name": n, "version": x} for n, x in v.items()]}
        cbom = lambda *names: {"components": [{"name": n, "type": "cryptographic-asset"} for n in names]}
        old = {"-sbom.json": sbom(cryptography="49.0", cffi="2.0", pqcsuite="0.1"), "-cbom.json": cbom("RSA", "ML-DSA")}
        with mock.patch.object(rr, "previous", return_value={"tag_name": "v1.0.0"}), \
                mock.patch.object(rr, "asset", side_effect=lambda rel, suffix: old[suffix]):
            text = rr.since("v1.1.0", sbom(cryptography="50.0", pycparser="3.0", pqcsuite="0.2"), cbom("ML-DSA", "DES"))
        self.assertIn("+ pycparser 3.0; - cffi 2.0; cryptography 49.0 to 50.0", text)
        self.assertIn("+ DES; - RSA", text)
        self.assertNotIn("pqcsuite", text)
        with mock.patch.object(rr, "previous", return_value=None):
            self.assertIn("First release", rr.since("v1.0.0", {}, {}))

class BaseImageTest(unittest.TestCase):
    def test_every_build_and_ci_container_uses_the_pinned_python_base(self):
        root = Path(__file__).resolve().parent.parent
        base = re.search(r"^ARG BASE=(\S+)$", (root / "Dockerfile").read_text(), re.M).group(1)
        self.assertRegex(base, r"@sha256:[0-9a-f]{64}$", "the base image is pinned by digest")
        for f in ("docker/vpn-gateway.Dockerfile", ".github/workflows/ci.yml", ".github/workflows/release.yml", ".github/workflows/soak.yml"):
            with self.subTest(f):
                uses = re.findall(r"python:3\.\d+-slim-\w+(?:@sha256:[0-9a-f]{64})?", (root / f).read_text())
                self.assertTrue(uses)
                self.assertEqual(set(uses), {base}, f"{f} must use the same pinned base as the Dockerfile")


if __name__ == "__main__":
    unittest.main()
