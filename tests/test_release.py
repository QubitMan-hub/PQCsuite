"""The release gate: a release is refused when any required job failed, is missing or was skipped."""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import release_readiness as rr  # noqa: E402

BENCH = {f"tls_handshake_{g}": {"median_ms": 1, "p95_ms": 2} for g in ("X25519MLKEM768", "X25519")} | {
    "ca_issue_ML-DSA-65": {"median_ms": 1}, "vault_64MiB": {"encrypt_MiB_s": 1, "decrypt_MiB_s": 1}}
EVIDENCE = {"tests": "1 run", "fuzz_tests": 1, "hostile_tests": 1, "openssl": "OpenSSL 3.5", "python": "3.13", "sbom_components": 1,
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


class BaseImageTest(unittest.TestCase):
    def test_every_build_and_ci_container_uses_the_pinned_python_base(self):
        root = Path(__file__).resolve().parent.parent
        base = re.search(r"^ARG BASE=(\S+)$", (root / "Dockerfile").read_text(), re.M).group(1)
        self.assertRegex(base, r"@sha256:[0-9a-f]{64}$", "the base image is pinned by digest")
        for f in ("docker/vpn-gateway.Dockerfile", ".github/workflows/ci.yml", ".github/workflows/release.yml"):
            with self.subTest(f):
                uses = re.findall(r"python:3\.\d+-slim-\w+(?:@sha256:[0-9a-f]{64})?", (root / f).read_text())
                self.assertTrue(uses)
                self.assertEqual(set(uses), {base}, f"{f} must use the same pinned base as the Dockerfile")


if __name__ == "__main__":
    unittest.main()
