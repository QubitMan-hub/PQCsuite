"""Acxelin TLS's commands fail with one clear line and exit code 1, never a traceback or a silent success."""
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from acxelin_core.pki import CA

from acxelin_tls.cli import main
from support_tls import REASON, server_context


class CommandTest(unittest.TestCase):
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

    @unittest.skipIf(REASON, REASON)
    def test_edge_start_up_errors(self):
        edge = ["edge", "--listen", "127.0.0.1:0", "--target", "127.0.0.1:1"]
        self.assertIn("nope.pem", self.fails(*edge, "--cert", self.d / "nope.pem", "--key", self.srv / "key.pem"))
        self.assertIn("needs the CA", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--require-client-cert"))
        self.assertIn("ML-DSA-87", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--policy", "cnsa2"))
        self.assertTrue((self.d / "pki" / "crl.pem").is_file())
        self.assertIn("ca crl", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--require-client-cert",
                                           "--ca", self.d / "pki" / "ca.crt", "--crl", self.d / "nope-crl.pem"))
        self.assertIn("fixed listen port", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--workers", "2"))

    def test_passphrase_prompts_without_a_terminal_say_what_to_do(self):
        from unittest import mock
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.d)
        with mock.patch("sys.stdin", io.StringIO("")):
            for flags in ((), ("--encrypt",)):
                self.assertIn("--no-encrypt", self.fails("ca", "init", "--name", "T", "--dir", "ca2", *flags))
        self.assertFalse((self.d / "ops.key").exists() or (self.d / "ca2" / "ca.crt").exists())

    @unittest.skipIf(REASON, REASON)
    def test_connect_prints_a_reply_that_arrives_in_pieces(self):
        import time
        from acxelin_core.server import Server

        def reply(conn, addr):
            conn.recv(timeout=5)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
            time.sleep(0.3)
            conn.sendall(b'{"allergies": ["penicillin"]}')
        s = Server(("127.0.0.1", 0), lambda: server_context(self.srv / "chain.pem", self.srv / "key.pem"), reply)
        s.start()
        self.addCleanup(s.stop, 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main(["connect", f"127.0.0.1:{s.port}", "--server-name", "localhost", "--ca", str(self.d / "pki" / "ca.crt"), "--send", "GET /"])
        self.assertEqual(e.exception.code, 0)
        self.assertIn("penicillin", out.getvalue())

    def test_bundles_never_invent_a_ca_or_leave_half_a_folder(self):
        self.assertIn("no CA at", self.fails("bundle", "nginx", "--host", "web.example", "--ca", self.d / "typo", "--out", self.d / "b1"))
        self.assertFalse((self.d / "typo").exists())
        self.assertIn("not a valid host name", self.fails("bundle", "nginx", "--host", "bad host", "--out", self.d / "b2"))
        self.assertFalse((self.d / "b2").exists())

    @unittest.skipIf(REASON, REASON)
    def test_the_one_minute_tour_shows_post_quantum_in_and_classical_out(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main(["try"])
        self.assertEqual(e.exception.code, 0, out.getvalue())
        for seen in ("X25519MLKEM768", "ML-DSA-65", "knows nothing about post-quantum", "refused, as it should be"):
            self.assertIn(seen, out.getvalue())

    @unittest.skipIf(REASON, REASON)
    def test_network_errors_are_in_words(self):
        import socket
        from pqcsuite.readiness.scan import probe
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        ca = ["--ca", self.d / "pki" / "ca.crt"]
        self.assertIn("--server-name nosuch.invalid", self.fails("connect", "nosuch.invalid:443", *ca))
        self.assertIn("connection refused", self.fails("connect", f"127.0.0.1:{closed}", *ca))
        self.assertEqual(probe(f"127.0.0.1:{closed}", timeout=10)["error"], "connection refused (nothing is listening on that port)")
        self.assertIn("0 to 65535", self.fails("connect", "127.0.0.1:99999", *ca))

    def test_the_ca_key_is_encrypted_unless_asked_not_to(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"ACXELIN_TLS_CA_PASSPHRASE": "pw"}), contextlib.redirect_stdout(io.StringIO()):
            for argv in (["--dir", self.d / "enc"], ["--dir", self.d / "plain", "--no-encrypt"]):
                with self.assertRaises(SystemExit) as e:
                    main(["ca", "init", "--name", "T", *map(str, argv)])
                self.assertEqual(e.exception.code, 0)
        self.assertIn(b"ENCRYPTED", (self.d / "enc" / "ca.key").read_bytes())
        self.assertNotIn(b"ENCRYPTED", (self.d / "plain" / "ca.key").read_bytes())
