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
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        ca = ["--ca", self.d / "pki" / "ca.crt"]
        self.assertIn("--server-name nosuch.invalid", self.fails("connect", "nosuch.invalid:443", *ca))
        self.assertIn("connection refused", self.fails("connect", f"127.0.0.1:{closed}", *ca))
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


class CommandProblemsTest(CommandTest):
    def test_config_files_name_what_is_missing_or_wrong(self):
        cfg = self.d / "c.toml"
        cfg.write_text('[[edge]]\nname = "a"\nlisten = "127.0.0.1:0"\n')
        self.assertIn("missing mode, target", self.fails("edge", "--config", cfg))
        base = 'mode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\n'
        for extra, words in (('max_connections = "lots"\n', "max_connections must be a whole number"), ("max_connections = true\n", "max_connections must be a whole number"),
                             ("idle_timeout = nan\n", "idle_timeout must be a finite number"), ("idle_timeout = inf\n", "idle_timeout must be a finite number"),
                             ("idle_timeout = -inf\n", "idle_timeout must be a finite number")):
            cfg.write_text("[[edge]]\n" + base + extra)
            self.assertIn(words, self.fails("edge", "--config", cfg))
        text = "[[edge]]\n" + base
        for data in (b"\xef\xbb\xbf" + text.encode(), b"\xff\xfe" + text.encode("utf-16-le")):
            cfg.write_bytes(data)
            self.assertIn("terminate needs cert and key", self.fails("edge", "--config", cfg))
        cfg.write_bytes(b"\x80\x81 not text")
        self.assertIn("is not UTF-8 text", self.fails("edge", "--config", cfg))

    def test_numbers_that_must_be_positive_are_refused_in_words(self):
        for argv in (("ca", "crl", "--days", "0"), ("ca", "maintain", "--crl-days", "-1"), ("ca", "token", "server", "web", "--hours", "0")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
                main([*argv, "--dir", str(self.d / "nowhere")])
            self.assertIn("expected a number above 0", err.getvalue(), argv)

    def test_first_steps_are_explained(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main([])
        self.assertEqual(e.exception.code, 0)
        self.assertIn("acxelin-tls try", out.getvalue())
        cfg = self.d / "edge.toml"
        cfg.write_text('[[route]]\nlisten = "0.0.0.0:443"\n')
        self.assertIn("found [[route]]", self.fails("edge", "--config", cfg))


def test_guided_enrollment_keeps_secrets_out_of_output_and_requires_trust(tmp_path, capsys):
    import datetime as dt
    from types import SimpleNamespace
    from unittest.mock import patch

    import pytest
    args = ["ca", "enroll", "--guide", "--out", str(tmp_path / "device")]
    cert = SimpleNamespace(serial_number=1, not_valid_after_utc=dt.datetime.now(dt.timezone.utc))
    with patch("sys.stdin.isatty", return_value=True), patch("acxelin_tls.checks.prerequisites", return_value=[]), \
            patch("builtins.input", side_effect=["https://ca.example:9443", "device-1", "a" * 64]), \
            patch("getpass.getpass", side_effect=["PRIVATE_TOKEN", "PRIVATE_PASSWORD", "PRIVATE_PASSWORD"]), \
            patch.dict(os.environ, {"ACXELIN_TLS_ENROLL_TOKEN": "", "PQCSUITE_ENROLL_TOKEN": ""}), \
            patch("acxelin_core.pki.est.fetch_ca") as fetch, patch("acxelin_core.pki.est.enroll", return_value=cert) as enroll:
        with pytest.raises(SystemExit) as result:
            main(args)
        assert result.value.code == 0
        assert fetch.call_args.args[1] == "a" * 64
        assert enroll.call_args.kwargs["passphrase"] == b"PRIVATE_PASSWORD"
        assert enroll.call_args.args[1] == "PRIVATE_TOKEN"
        assert "PRIVATE_" not in capsys.readouterr().out
    with patch("sys.stdin.isatty", return_value=False), patch("acxelin_core.pki.est.enroll") as enroll:
        with pytest.raises(SystemExit) as result:
            main(args)
        assert result.value.code != 0
        enroll.assert_not_called()


def test_prerequisites_rows_have_the_shape_the_commands_read():
    from acxelin_tls import checks
    rows = checks.prerequisites()
    assert rows and all(set(r) == {"product", "level", "message", "action"} and r["level"] in ("ok", "warn", "fail") for r in rows)


def test_doctor_does_not_contradict_the_openssl_message(capsys):
    from unittest.mock import patch
    too_old = ("this machine's OpenSSL 3.0.13 is too old: post-quantum TLS needs OpenSSL 3.5 or newer. Or start the program with "
               "LD_LIBRARY_PATH set to its lib folder (ACXELIN_OPENSSL cannot help here: this process has already loaded the system OpenSSL).")
    with patch("acxelin_core.openssl.available", return_value=too_old), contextlib.suppress(SystemExit):
        main(["doctor"])
    line = next(x for x in capsys.readouterr().out.splitlines() if x.startswith("FAIL"))
    assert ".." not in line and line.count("ACXELIN_OPENSSL") == 1 and line.endswith("run `acxelin-tls doctor` again")
