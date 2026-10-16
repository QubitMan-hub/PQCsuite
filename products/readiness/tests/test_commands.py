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
    expected = "available" if os.environ.get("PQCSUITE_OPENSSL") or os.environ.get("ACXELIN_OPENSSL") else ""
    assert "full TLS handshakes (OpenSSL 3.5+):" in out and expected in out
