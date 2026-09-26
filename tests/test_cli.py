"""The command line fails with one clear line and exit code 1, never a traceback or a silent success."""
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from pqcsuite import tls
from pqcsuite.cli import main
from pqcsuite.pki import CA

try:
    tls.lib()
    REASON = None
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


class CLITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.ca = CA.init(self.d / "pki", "Root")
        self.srv, _ = self.ca.issue("localhost", "server", ["localhost", "127.0.0.1"], out=self.d / "srv")

    def tearDown(self):
        self.tmp.cleanup()

    def fails(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e:
            main([str(a) for a in argv])
        self.assertEqual(e.exception.code, 1, err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        return err.getvalue()

    @unittest.skipIf(REASON, REASON)
    def test_edge_start_up_errors(self):
        edge = ["tls", "edge", "--listen", "127.0.0.1:0", "--target", "127.0.0.1:1"]
        self.assertIn("nope.pem", self.fails(*edge, "--cert", self.d / "nope.pem", "--key", self.srv / "key.pem"))
        self.assertIn("needs the CA", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--require-client-cert"))
        self.assertIn("ML-DSA-87", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--policy", "cnsa2"))

    def test_config_files_name_what_is_missing_or_wrong(self):
        cfg = self.d / "c.toml"
        cfg.write_text('[[edge]]\nname = "a"\nlisten = "127.0.0.1:0"\n')
        self.assertIn("missing mode, target", self.fails("tls", "edge", "--config", cfg))
        cfg.write_text('[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\nmax_connections = "lots"\n')
        self.assertIn("max_connections must be a whole number", self.fails("tls", "edge", "--config", cfg))
        cfg.write_text('[site]\nname = "x"\n')
        self.assertIn("[site]: missing address", self.fails("vpn", "up", "--config", cfg))
        cfg.write_text('[wireguard]\nname = "x"\n')
        self.assertIn("[wireguard]: missing endpoint", self.fails("vpn", "gateway", "--config", cfg))

    def test_nothing_to_do_is_an_error(self):
        empty = self.d / "hosts.txt"
        empty.write_text("# nothing yet\n")
        self.assertIn("no targets", self.fails("readiness", "scan", empty))
        self.assertIn("nothing to report on", self.fails("readiness", "report"))
        self.assertIn("no CA at", self.fails("console", "--ca", self.d / "nowhere", "--listen", "127.0.0.1:0"))

    def test_bundles_never_invent_a_ca_or_leave_half_a_folder(self):
        self.assertIn("no CA at", self.fails("tls", "bundle", "nginx", "--host", "web.example", "--ca", self.d / "typo", "--out", self.d / "b1"))
        self.assertFalse((self.d / "typo").exists())
        self.assertIn("not a valid host name", self.fails("tls", "bundle", "nginx", "--host", "bad host", "--out", self.d / "b2"))
        self.assertFalse((self.d / "b2").exists())

    def test_vault_never_overwrites_keys_or_archives(self):
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.d)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e:
            main(["vault", "keygen", "ops", "--no-passphrase"])
        self.assertEqual(e.exception.code, 0)
        self.assertIn("already exists", self.fails("vault", "keygen", "ops", "--no-passphrase"))
        Path("f.txt").write_text("x")
        Path("f.pqv").write_text("keep me")
        self.assertIn("already exists", self.fails("vault", "encrypt", "f.txt", "-o", "f.pqv", "-r", "ops.pub"))
        self.assertEqual(Path("f.pqv").read_text(), "keep me")


if __name__ == "__main__":
    unittest.main()
