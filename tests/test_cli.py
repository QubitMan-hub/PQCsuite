"""The command line fails with one clear line and exit code 1, never a traceback or a silent success."""
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from pqcsuite.cli import main
from pqcsuite.pki import CA


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




    def test_every_option_explains_itself(self):
        import argparse
        from pqcsuite.cli import parser
        missing = []

        def walk(p, path):
            for a in p._actions:
                if isinstance(a, argparse._SubParsersAction):
                    for name, sub in a.choices.items():
                        walk(sub, [*path, name])
                elif not a.help:
                    missing.append(" ".join([*path, "/".join(a.option_strings) or a.dest]))
        walk(parser(), ["pqcsuite"])
        self.assertEqual(missing, [])

    def test_first_steps_are_explained(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main([])
        self.assertEqual(e.exception.code, 0)
        self.assertIn("pqcsuite try", out.getvalue())


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
        self.assertIn("lists at least two recipients", messages("two"))
        self.assertIn("unverified metadata", messages("two"))
        self.assertEqual(checks.backups("empty-folder")[0][0], "fail")
        os.utime(next(Path("one").glob("*.pqv")), (0, 0))
        self.assertIn("(more than 2)", messages("one"))

    def test_vault_metadata_and_signature_trust_are_distinguished(self):
        import json
        from pqcsuite import vault
        me = vault.Identity.generate()
        me.save(self.d / "me.key", None)
        (self.d / "data.txt").write_text("private records")
        archive = self.d / "signed.pqv"
        vault.encrypt(self.d / "data.txt", archive, [me.public], vault.load_signer(self.srv / "cert.pem", self.srv / "key.pem"))

        def run(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as result:
                main([str(a) for a in args])
            self.assertEqual(result.exception.code, 0)
            return out.getvalue()

        self.assertIn("integrity and the claimed signer are unverified", run("vault", "inspect", archive))
        self.assertEqual(json.loads(run("vault", "inspect", archive, "--json"))["signed_by"], "CN=localhost")
        untrusted = run("vault", "verify", archive, "--key", self.d / "me.key")
        self.assertIn("certificate issuer was not checked", untrusted)
        self.assertIn("Pass --ca", untrusted)
        trusted = run("vault", "verify", archive, "--key", self.d / "me.key", "--ca", self.ca.root / "ca.crt")
        self.assertNotIn("issuer was not checked", trusted)


if __name__ == "__main__":
    unittest.main()


def test_setup_preserves_existing_config_and_separates_optional_tls(tmp_path, capsys):
    import pytest
    from pqcsuite.console import Settings
    out = tmp_path/'private/console.toml'
    with pytest.raises(SystemExit) as result:
        main(['setup', '--project', str(tmp_path), '--out', str(out)])
    assert result.value.code == 0
    settings = Settings.load(out)
    assert settings.listen == '127.0.0.1:8900'
    assert settings.project_roots == [str(tmp_path.resolve())]
    original = out.read_bytes()
    with pytest.raises(SystemExit) as result:
        main(['setup', '--project', str(tmp_path), '--out', str(out)])
    assert result.value.code != 0 and out.read_bytes() == original
    if os.name != 'nt':
        assert out.stat().st_mode & 0o777 == 0o600
    capsys.readouterr()
    with pytest.raises(SystemExit) as result:
        main(['doctor', '--json', '--product', 'vault'])
    import json
    report = json.loads(capsys.readouterr().out)
    assert result.value.code == 0 and report['checks'][0]['product'] == 'vault'
