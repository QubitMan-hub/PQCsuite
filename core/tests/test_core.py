import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from acxelin_core import config, console, files, http


@dataclass
class Settings:
    name: str
    port: int = 1
    tags: list = field(default_factory=list)


def test_config_reports_unknown_missing_and_mistyped_settings():
    assert config.build(Settings, {"name": "a"}, "x").name == "a"
    for doc, words in (({"name": "a", "nope": 1}, "unknown settings nope"), ({}, "missing name"), ({"name": "a", "port": "1"}, "port must be a whole number")):
        with pytest.raises(ValueError, match=words):
            config.build(Settings, doc, "x")


def test_config_reads_utf16_and_bom_text(tmp_path):
    for data in ('name = "a"\n'.encode("utf-16"), b'\xef\xbb\xbfname = "a"\n'):
        (tmp_path / "c.toml").write_bytes(data)
        assert config.read_toml(tmp_path / "c.toml") == {"name": "a"}


def test_files_write_secret_is_owner_only(tmp_path):
    files.write(tmp_path / "s", b"x", secret=True)
    assert (tmp_path / "s").read_bytes() == b"x"
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "s").stat().st_mode) == 0o600


def test_hostport_takes_the_default_host_from_the_caller():
    assert http.hostport(":80", "127.0.0.1") == ("127.0.0.1", 80)
    assert http.hostport("[::1]:9", "0.0.0.0") == ("::1", 9)
    with pytest.raises(ValueError):
        http.hostport("host:99999")


def test_serve_http_answers_healthz_and_routes():
    server = http.serve_http("127.0.0.1:0", {"/x": (http.JSON, lambda: '{"a": 1}')})
    port = server.server_address[1]
    assert urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz").read() == b"ok\n"
    assert json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/x").read()) == {"a": 1}
    server.shutdown()


def test_backoff_policy_comes_from_the_caller():
    for limit in (2, 5):
        b = console.Backoff(limit=limit, window=60)
        for _ in range(limit):
            b.failed("1.2.3.4")
        assert b.blocked("1.2.3.4") and not b.blocked("5.6.7.8")


# The console access contract (spec: "Console access and security").

def test_ticket_is_single_use_and_expires():
    s = console.Sessions(ticket_ttl=0.2)
    t = s.ticket()
    assert s.redeem(t) and not s.redeem(t)
    late = s.ticket()
    time.sleep(0.3)
    assert s.redeem(late) is None


def test_redeemed_ticket_gives_a_session_token_that_authorises():
    s = console.Sessions()
    token = s.redeem(s.ticket())
    assert len(token) >= 43 and s.authorised(f"Bearer {token}")
    assert not s.authorised("Bearer wrong") and not s.authorised(None)


@pytest.mark.parametrize("host,origin,site,status", [
    ("127.0.0.1:8900", None, None, None),
    ("localhost:9000", "http://localhost:9000", "same-origin", None),
    ("[::1]:8900", None, None, None),
    ("evil.example:8900", None, None, 421),
    ("127.0.0.1.evil.example", None, None, 421),
    ("localhost:8900", "http://evil.example", None, 403),
    ("localhost:8900", "http://localhost:8901", None, 403),
    ("localhost:8900", None, "cross-site", 403),
])
def test_request_checks_refuse_foreign_hosts_origins_and_cross_site(host, origin, site, status):
    headers = {"Host": host, **({"Origin": origin} if origin else {}), **({"Sec-Fetch-Site": site} if site else {})}
    assert console.refusal(headers) == (None if status is None else status)


def test_console_page_flow_issues_no_cookie_and_keeps_secrets_out_of_logs(tmp_path, caplog):
    caplog.set_level("DEBUG")
    html = b"<!doctype html><title>t</title><script>1</script>"
    app = console.App(html, {("GET", "/api/status"): lambda body: (200, {"ok": True})})
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/")
        assert "Set-Cookie" not in page.headers and "sha256-" in page.headers["Content-Security-Policy"]
        ticket = app.sessions.ticket()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/session", json.dumps({"ticket": ticket}).encode(), {"Content-Type": "application/json"})
        answer = urllib.request.urlopen(req)
        token = json.loads(answer.read())["token"]
        assert "Set-Cookie" not in answer.headers
        api = urllib.request.Request(f"http://127.0.0.1:{port}/api/status", headers={"Authorization": f"Bearer {token}"})
        assert json.loads(urllib.request.urlopen(api).read()) == {"ok": True}
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/status?token={token}"))
        assert e.value.code == 401
        assert ticket not in caplog.text and token not in caplog.text
    finally:
        server.shutdown()


def test_lockout_after_ten_wrong_tokens_per_address():
    app = console.App(b"<script>1</script>", {})
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    codes = []
    try:
        for _ in range(11):
            try:
                urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/x", headers={"Authorization": "Bearer no"}))
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        assert codes[:10] == [401] * 10 and codes[10] == 429
    finally:
        server.shutdown()


def test_link_prints_only_to_an_interactive_terminal(capsys):
    s = console.Sessions()
    assert console.link(s, 8900, tty=False) is None and capsys.readouterr().out == ""
    url = console.link(s, 8900, tty=True)
    assert url.startswith("http://127.0.0.1:8900/#") and "?" not in url and url in capsys.readouterr().out


def test_automation_token_file_is_owner_only(tmp_path):
    token = console.new_automation_token(tmp_path / "console.token")
    assert (tmp_path / "console.token").read_text().strip() == token
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "console.token").stat().st_mode) == 0o600


def test_core_imports_no_product_and_loads_no_openssl_on_import():
    code = "import sys, acxelin_core, acxelin_core.config, acxelin_core.files, acxelin_core.http, acxelin_core.console, acxelin_core.pki;" \
           "bad=[m for m in sys.modules if m.split('.')[0] in ('pqcsuite','acxelin_readiness','acxelin_tls','acxelin_vpn','acxelin_vault','wolfpack')];" \
           "assert not bad, bad; assert 'acxelin_core.openssl' not in sys.modules"
    import subprocess
    assert subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parent).returncode == 0
