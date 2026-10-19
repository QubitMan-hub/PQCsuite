"""Secrets stay secret: CA and key passphrases and enrollment token secrets never appear in command output, logs or files at rest, including on the error paths."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CA_PASS, KEY_PASS, TOKEN = "ca-pass-7f3e91", "key-pass-2b8c44", "console-token-9d1a07"


def everything_under(d):
    return b"".join(p.read_bytes() for p in Path(d).rglob("*") if p.is_file())


class SecretsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)

    def run_cli(self, *args, ok=True):
        env = {**os.environ, "ACXELIN_TLS_CA_PASSPHRASE": CA_PASS, "KEY_PASS": KEY_PASS}
        r = subprocess.run([sys.executable, "-m", "acxelin_tls", "--log-json", "-v", *map(str, args)], cwd=self.d, capture_output=True, text=True, env=env)
        if ok and r.returncode:
            raise AssertionError(r.stderr)
        return r.stdout + r.stderr

    def test_passphrases_and_token_secrets_never_leave_where_they_belong(self):
        out = self.run_cli("ca", "init", "--dir", "pki", "--name", "Root", "--encrypt")
        out += self.run_cli("ca", "issue", "--dir", "pki", "server", "api.test", "--out", "api", "--key-passphrase-env", "KEY_PASS")
        token = self.run_cli("ca", "token", "--dir", "pki", "client", "dev.test").strip().splitlines()[-1]
        secret = token.split(".", 1)[1]
        out += self.run_cli("ca", "list", "--dir", "pki") + self.run_cli("ca", "crl", "--dir", "pki")
        out += self.run_cli("ca", "maintain", "--dir", "pki") + self.run_cli("doctor", "--ca", "pki", ok=False)
        env = {**os.environ, "ACXELIN_TLS_CA_PASSPHRASE": "wrong-" + CA_PASS}
        out += subprocess.run([sys.executable, "-m", "acxelin_tls", "ca", "issue", "--dir", "pki", "client", "x"], cwd=self.d,
                              capture_output=True, text=True, env=env).stderr
        at_rest = everything_under(self.d)
        for s in (CA_PASS, KEY_PASS, secret):
            with self.subTest(secret=s):
                self.assertNotIn(s, out)
                self.assertNotIn(s.encode(), at_rest)
        self.assertNotIn("PRIVATE KEY", out)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", (self.d / "api" / "key.pem").read_bytes())


if __name__ == "__main__":
    unittest.main()
