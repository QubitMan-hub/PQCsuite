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
from tests.helpers import REASON


class CLITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.ca = CA.init(self.d / "pki", "Root")
        self.srv, _ = self.ca.issue("localhost", "server", ["localhost", "127.0.0.1"], out=self.d / "srv")

    def fails(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e:
            main([str(a) for a in argv])
        self.assertEqual(e.exception.code, 1, err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        return err.getvalue()

    def test_json_logs_keep_the_traceback(self):
        import json
        import logging
        import sys
        from pqcsuite.cli import JSONFormatter
        try:
            1 / 0
        except ZeroDivisionError:
            r = logging.LogRecord("x", logging.ERROR, __file__, 1, "handler failed", None, sys.exc_info())
        self.assertIn("ZeroDivisionError", json.loads(JSONFormatter().format(r))["exception"])

    @unittest.skipIf(REASON, REASON)
    def test_edge_start_up_errors(self):
        edge = ["tls", "edge", "--listen", "127.0.0.1:0", "--target", "127.0.0.1:1"]
        self.assertIn("nope.pem", self.fails(*edge, "--cert", self.d / "nope.pem", "--key", self.srv / "key.pem"))
        self.assertIn("needs the CA", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--require-client-cert"))
        self.assertIn("ML-DSA-87", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--policy", "cnsa2"))
        self.assertTrue((self.d / "pki" / "crl.pem").is_file())
        self.assertIn("ca crl", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--require-client-cert",
                                           "--ca", self.d / "pki" / "ca.crt", "--crl", self.d / "nope-crl.pem"))
        self.assertIn("fixed listen port", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--workers", "2"))

    @unittest.skipIf(REASON, REASON)
    def test_connect_prints_a_reply_that_arrives_in_pieces(self):
        import time
        from pqcsuite.tls.server import Server

        def reply(conn, addr):
            conn.recv(timeout=5)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
            time.sleep(0.3)
            conn.sendall(b'{"allergies": ["penicillin"]}')
        s = Server(("127.0.0.1", 0), lambda: tls.server_context(self.srv / "chain.pem", self.srv / "key.pem"), reply)
        s.start()
        self.addCleanup(s.stop, 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main(["tls", "connect", f"127.0.0.1:{s.port}", "--server-name", "localhost", "--ca", str(self.d / "pki" / "ca.crt"), "--send", "GET /"])
        self.assertEqual(e.exception.code, 0)
        self.assertIn("penicillin", out.getvalue())

    @unittest.skipIf(REASON, REASON)
    def test_network_errors_are_in_words(self):
        import socket
        from pqcsuite.readiness.scan import probe
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        ca = ["--ca", self.d / "pki" / "ca.crt"]
        self.assertIn("--server-name nosuch.invalid", self.fails("tls", "connect", "nosuch.invalid:443", *ca))
        self.assertIn("connection refused", self.fails("tls", "connect", f"127.0.0.1:{closed}", *ca))
        self.assertEqual(probe(f"127.0.0.1:{closed}", timeout=10)["error"], "connection refused (nothing is listening on that port)")
        self.assertIn("No such file or directory: ", self.fails("readiness", "scan", self.d / "none.txt"))
        self.assertIn("0 to 65535", self.fails("tls", "connect", "127.0.0.1:99999", *ca))
        self.assertIn("0 to 65535", self.fails("readiness", "probe", "127.0.0.1:70000"))

    def test_scan_targets_as_people_write_them(self):
        from pqcsuite.readiness.scan import endpoint
        cases = {"bank.example": ("tls", "bank.example", 443), "bank.example:8443": ("tls", "bank.example", 8443),
                 "https://bank.example/login": ("tls", "bank.example", 443), "[2001:db8::1]": ("tls", "2001:db8::1", 443),
                 "[2001:db8::1]:8443": ("tls", "2001:db8::1", 8443), "ssh://bank.example": ("ssh", "bank.example", 22),
                 "ssh://bank.example:2222": ("ssh", "bank.example", 2222)}
        for target, want in cases.items():
            self.assertEqual(endpoint(target), want, target)
        for bad in (":443", "bank.example:https"):
            self.assertRaises(ValueError, endpoint, bad)

    def test_passphrase_prompts_without_a_terminal_say_what_to_do(self):
        from unittest import mock
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.d)
        with mock.patch("sys.stdin", io.StringIO("")):
            self.assertIn("--no-passphrase", self.fails("vault", "keygen", "ops"))
            for flags in ((), ("--encrypt",)):
                self.assertIn("--no-encrypt", self.fails("ca", "init", "--name", "T", "--dir", "ca2", *flags))
        self.assertFalse((self.d / "ops.key").exists() or (self.d / "ca2" / "ca.crt").exists())

    def test_the_ca_key_is_encrypted_unless_asked_not_to(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"PQCSUITE_CA_PASSPHRASE": "pw"}), contextlib.redirect_stdout(io.StringIO()):
            for argv in (["--dir", self.d / "enc"], ["--dir", self.d / "plain", "--no-encrypt"]):
                with self.assertRaises(SystemExit) as e:
                    main(["ca", "init", "--name", "T", *map(str, argv)])
                self.assertEqual(e.exception.code, 0)
        self.assertIn(b"ENCRYPTED", (self.d / "enc" / "ca.key").read_bytes())
        self.assertNotIn(b"ENCRYPTED", (self.d / "plain" / "ca.key").read_bytes())

    @unittest.skipIf(REASON, REASON)
    def test_the_one_minute_tour_shows_post_quantum_in_and_classical_out(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main(["try"])
        self.assertEqual(e.exception.code, 0, out.getvalue())
        for seen in ("X25519MLKEM768", "ML-DSA-65", "knows nothing about post-quantum", "refused, as it should be"):
            self.assertIn(seen, out.getvalue())

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
        text = '[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\n'
        for data in (b"\xef\xbb\xbf" + text.encode(), b"\xff\xfe" + text.encode("utf-16-le")):
            cfg.write_bytes(data)
            self.assertIn("terminate needs cert and key", self.fails("tls", "edge", "--config", cfg))
        cfg.write_bytes(b"\x80\x81 not text")
        self.assertIn("is not UTF-8 text", self.fails("tls", "edge", "--config", cfg))
        targets = self.d / "t.txt"
        targets.write_bytes(b"\xef\xbb\xbfbank.example\r\n# note\r\nssh://gw\r\n")
        from pqcsuite.readiness.scan import load_targets
        self.assertEqual(load_targets([str(targets)]), ["bank.example", "ssh://gw"])

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

    def test_a_backup_that_one_key_opens_is_refused_unless_asked_for(self):
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.d)

        def run(*argv):
            with self.assertRaises(SystemExit) as e:
                main([str(a) for a in argv])
            self.assertEqual(e.exception.code, 0)
        with contextlib.redirect_stdout(io.StringIO()):
            for name in ("ops", "recovery"):
                run("vault", "keygen", name, "--no-passphrase")
        Path("data").mkdir()
        (Path("data") / "a.txt").write_text("records")
        self.assertIn("recovery key", self.fails("vault", "backup", "data", "--to", "one", "-r", "ops.pub"))
        self.assertFalse(Path("one").exists() and any(Path("one").iterdir()), "nothing is written when refused")
        self.assertIn("recovery key", self.fails("vault", "backup", "data", "--to", "one", "-r", "ops.pub", "-r", "ops.pub"))
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            run("vault", "backup", "data", "--to", "one", "-r", "ops.pub", "--no-recovery-key")
            run("vault", "backup", "data", "--to", "two", "-r", "ops.pub", "-r", "recovery.pub")
            run("vault", "encrypt", "data", "-o", "loose.pqv", "-r", "ops.pub")
        self.assertIn("only one key", err.getvalue(), "encrypting to one key goes ahead, with a warning")

        archive = next(Path("two").glob("*.pqv"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            run("vault", "verify", archive, "--key", "recovery.key")
        self.assertIn("restores data (1 file(s), 7 bytes); every chunk authenticated; opens for 2 key(s)", out.getvalue())
        self.assertEqual(sorted(p.name for p in Path(".").iterdir() if p.name.startswith("data")), ["data"], "a drill writes nothing")
        blob = bytearray(archive.read_bytes())
        blob[-5] ^= 1
        archive.write_bytes(bytes(blob))
        self.assertIn("modified", self.fails("vault", "verify", archive, "--key", "recovery.key"))

        from pqcsuite import checks
        messages = lambda folder: " ".join(m for _, m in checks.backups(folder))
        self.assertIn("single key", messages("one"), "an archive only one key opens is flagged")
        self.assertIn("at least two keys", messages("two"))
        self.assertEqual(checks.backups("empty-folder")[0][0], "fail")
        os.utime(next(Path("one").glob("*.pqv")), (0, 0))
        self.assertIn("(more than 2)", messages("one"))


if __name__ == "__main__":
    unittest.main()
