import json
import os

from acxelin_readiness import cli


def test_grade_writes_json_and_html_and_an_unreachable_endpoint_is_f(tmp_path):
    out = tmp_path / "g.json"
    assert cli.main(["grade", "127.0.0.1:1", "--json", str(out), "--html", str(tmp_path / "g.html"), "--timeout", "1"]) == 0
    [row] = json.loads(out.read_text())["endpoints"]
    assert row["grade"] == "F" and row.get("error")
    assert "Acxelin Readiness" in (tmp_path / "g.html").read_text()


def test_doctor_says_whether_full_handshakes_are_available(capsys):
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    expected = "available" if os.environ.get("ACXELIN_OPENSSL") else ""
    assert "full TLS handshakes (OpenSSL 3.5+):" in out and expected in out


def run(*args):
    import subprocess
    import sys
    p = subprocess.run([sys.executable, "-m", "acxelin_readiness", *args], capture_output=True, text=True)
    return p.returncode, p.stderr


def test_target_problems_are_reported_in_words_and_exit_1(tmp_path):
    code, err = run("grade", str(tmp_path / "none.txt"))
    assert code == 1 and "No such file or directory: " in err and "Traceback" not in err
    code, err = run("grade", "127.0.0.1:70000")
    assert code == 1 and "0 to 65535" in err and "Traceback" not in err
    empty = tmp_path / "hosts.txt"
    empty.write_text("# nothing yet\n")
    for argv in (("grade", str(empty)), ("report", "--targets", str(empty))):
        code, err = run(*argv)
        assert code == 1 and "no targets" in err and "Traceback" not in err
    typo = tmp_path / "typo.txt"
    typo.write_text("bank.example\nbad host # typo\n")
    code, err = run("grade", "ok.example", str(typo))
    assert code == 1 and f"{typo}:2: 'bad host'" in err


def test_console_container_flag_listens_on_every_interface_and_opens_no_browser(monkeypatch, tmp_path):
    from acxelin_readiness import console
    seen = {}
    monkeypatch.setattr(console, "run", lambda home, port, open_browser, host: seen.update(home=home, open=open_browser, host=host) or 0)
    assert cli.main(["console", "--container", "--home", str(tmp_path)]) == 0
    assert seen == {"home": tmp_path, "open": False, "host": "0.0.0.0"}
    assert cli.main(["console", "--no-browser", "--home", str(tmp_path)]) == 0 and seen["host"] == "127.0.0.1"


def test_no_arguments_shows_where_to_start(capsys):
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "Start here" in out and "acxelin-readiness scan" in out and "acxelin-readiness console" in out
