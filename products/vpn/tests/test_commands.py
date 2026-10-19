"""Every `acxelin-vpn` command explains itself and fails in words, and the whole invite-then-join journey runs with no other
Acxelin product, nor the old suite, importable."""
import contextlib
import io
import re
import subprocess
import sys
from pathlib import Path

import pytest

from acxelin_vpn import cli
from support_vpn import REASON


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), pytest.raises(SystemExit) as e:
        cli.main(list(argv))
    return e.value.code, out.getvalue()


def commands():
    sub = next(a for a in cli.parser()._actions if a.dest == "cmd").choices
    for name, p in sub.items():
        nested = next((a for a in p._actions if a.dest == "ca_cmd"), None)
        yield from ([(name, n) for n in nested.choices] if nested else [(name,)])


def test_every_command_has_help():
    found = list(commands())
    expected = {"doctor", "up", "status", "check", "invite", "join", "app", "desktop", "gateway", "connect", "install", "disconnect",
                "uninstall", "console", "inventory"} | {f"ca {c}" for c in ("init", "issue", "revoke", "crl", "maintain", "list", "serve")}
    assert {" ".join(c) for c in found} == expected
    for c in found:
        code, text = run(*c, "--help")
        assert code == 0 and "usage: acxelin-vpn" in text and len(text) > 120, c


def test_no_command_prints_where_to_start():
    code, text = run()
    assert code == 0 and "Start here" in text and "acxelin-vpn join" in text


@pytest.mark.parametrize("argv,words", [
    (("invite", "bob", "--enroll", "http://ca.example:9443", "--gateway", "vpn.example:7443"), "--enroll must be the https:// address"),
    (("join", "no-such.acxinvite", "--no-apply"), "could not be read"),
    (("ca", "list", "--dir", "no-such-ca"), "no-such-ca"),
    (("status", "--vici", "unix:///no/such/charon.vici"), r"cannot reach charon|acxelin-vpn\[vpn\]"),
    (("up", "--config", "no-such.toml"), "no-such.toml"),
], ids=["invite-http", "join-missing", "ca-missing", "status-no-charon", "up-missing"])
def test_errors_are_one_line_in_words(argv, words, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, text = run(*argv)
    assert code == 1 and text.startswith("error: ") and re.search(words, text) and "Traceback" not in text and text.count("\n") == 1


@pytest.mark.skipif(REASON, reason=REASON or "")
def test_invite_then_join_needs_no_other_product():
    """The gateway, enrollment service, invitation and join of the end-to-end test, in a Python where Acxelin TLS, Acxelin
    Readiness and the suite cannot be imported."""
    test = Path(__file__).with_name("test_wireguard.py")
    code = ("import sys\nfor m in ('acxelin_tls', 'acxelin_readiness', 'pqcsuite'): sys.modules[m] = None\nimport pytest\n"
            f"sys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', {str(test) + '::GatewayTest::test_invite_then_join_enrolls_and_agrees_keys_in_one_step'!r}]))")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300, cwd=test.parent)
    assert r.returncode == 0 and "1 passed" in r.stdout, r.stdout + r.stderr
