"""Who did what: invitations, enrollments and revocations land in one owner-only log next to the certificate authority, whether
made from the command line or the console, and the console's People page shows them; a computer's kill-switch changes land
in the same kind of log on that computer. No token, key or passphrase is ever written to either."""
import http.client
import json
import os
import stat
from datetime import datetime, timezone

import pytest
from acxelin_core import console as core
from acxelin_core.pki import CA
from acxelin_core.pki import est
from acxelin_core.pki.est import Service

from acxelin_vpn import audit, cli, console as vc
from acxelin_vpn.wireguard import Client

PASS = "audit-ca-pass-77c1"


def run(*argv):
    with pytest.raises(SystemExit) as e:
        cli.main(list(argv))
    return e.value.code


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_the_command_line_records_invitations_and_revocations_next_to_the_ca(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ACXELIN_VPN_CA_PASSPHRASE", PASS)
    pki = tmp_path / "pki"
    ca = CA.init(pki, "VPN Root", passphrase=PASS.encode())
    _, rec = ca.issue("bob", "client", out=tmp_path / "bob", passphrase=None)
    monkeypatch.chdir(tmp_path)
    assert run("invite", "alice", "--dir", str(pki), "--enroll", "https://ca.example:9443", "--gateway", "vpn.example:7443") == 0
    assert run("ca", "revoke", rec.serial[:12], "--dir", str(pki), "--reason", "keyCompromise") == 0
    log = pki / "audit.jsonl"
    got = lines(log)
    assert [(x["action"], x["name"]) for x in got] == [("invite", "alice"), ("revoke", "bob")]
    assert got[1]["serial"] == rec.serial and got[1]["reason"] == "keyCompromise" and got[0]["expires"]
    token = json.loads((tmp_path / "alice.acxinvite").read_text())["token"]
    assert token not in log.read_text() and PASS not in log.read_text()
    if os.name != "nt":
        assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_recent_merges_enrollments_newest_first(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    ca = CA.init(pki, "VPN Root")
    at = iter(datetime(2026, 10, 20, 9, m, tzinfo=timezone.utc) for m in (1, 2))
    monkeypatch.setattr(est, "now", lambda: next(at))
    audit.record(pki, "invite", name="alice", expires="2026-10-21T00:00:00+00:00", time="2026-10-20T09:00:00Z")
    Service(ca).audit("enrolled", serial="ab12", common_name="alice", kind="client", token="t-1")
    Service(ca).audit("enroll_refused", reason="token used or expired", token="t-2", common_name="mallory")
    audit.record(pki, "revoke", name="alice", serial="ab12", reason="unspecified", time="2026-10-20T09:03:00Z")
    got = audit.recent(pki)
    assert [(x["action"], x["name"]) for x in got] == [("revoke", "alice"), ("enrollment refused", "mallory"), ("enroll", "alice"), ("invite", "alice")]
    assert all(x["time"].endswith("Z") and "token" not in x for x in got) and "t-1" not in json.dumps(got) and "t-2" not in json.dumps(got)
    assert audit.recent(tmp_path / "nothing-here") == []


def test_the_people_page_shows_what_the_command_line_did_and_the_console_writes_to_the_same_log(tmp_path):
    home = tmp_path / "home"
    ca = CA.init(home / "ca", "VPN Root")
    audit.record(home / "ca", "invite", name="carol", expires="2026-10-21T00:00:00+00:00")
    ca.issue("dave", "client", out=tmp_path / "dave")
    app = vc.build(home)
    srv = core.serve(app)
    token = app.sessions.redeem(app.sessions.ticket())

    def call(path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
        c.request("GET" if body is None else "POST", f"/api/{path}", None if body is None else json.dumps(body),
                  {"Host": f"127.0.0.1:{srv.server_address[1]}", "Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        r = c.getresponse()
        return r.status, json.loads(r.read())
    try:
        assert call("people/revoke", {"name": "dave"})[0] == 200
        acts = call("people")[1]["activity"]
    finally:
        srv.shutdown()
    assert [(a["action"], a["name"]) for a in acts[:2]] == [("revoke", "dave"), ("invite", "carol")]
    assert [x["action"] for x in lines(home / "ca/audit.jsonl")] == ["invite", "revoke"]


class Tunnel:
    up_ = False

    def __init__(self, folder):
        self.folder = folder

    def routes(self, routes):
        return routes

    def up(self, text):
        self.up_ = True

    def down(self):
        self.up_ = False

    def wg(self):
        return self

    def set_psk(self, *a):
        pass

    def device(self):
        return "wg0"


class KillSwitch:
    def on(self, *a):
        pass

    def off(self):
        pass


def test_kill_switch_changes_are_recorded_on_the_computer_once_per_change(tmp_path):
    CA.init(tmp_path / "ca", "VPN Root").issue("alice", "client", out=tmp_path / "alice")
    c = Client("192.0.2.7:7443", tmp_path / "alice", tunnel=Tunnel(tmp_path / "state"), kill_switch=KillSwitch())
    (tmp_path / "state").mkdir()
    full = {"address": "10.99.0.2/24", "routes": ["0.0.0.0/0"], "dns": [], "endpoint": "203.0.113.1:51820", "gateway_public": "A" * 43 + "="}
    for _ in range(3):
        c.apply(full, "B" * 43 + "=")
    c.apply(full | {"routes": ["10.99.0.0/24"]}, "C" * 43 + "=")
    c.close()
    got = lines(tmp_path / "state/audit.jsonl")
    assert [x["action"] for x in got] == ["kill switch on", "kill switch off"]
    assert got[0]["device"] == "alice" and "B" * 43 not in (tmp_path / "state/audit.jsonl").read_text()
    assert c.status()["kill_switch_changed"]["action"] == "kill switch off"
