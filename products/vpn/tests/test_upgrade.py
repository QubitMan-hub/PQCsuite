"""Upgrading from PQC Suite 0.4.3: the wire protocol is unchanged, the suite's names are still read with a warning, and the
suite's kill switch and service are replaced without a moment where traffic leaks or two of them are left behind."""
import json
import logging

import pytest

from acxelin_vpn import app, join, legacy, platforms
from acxelin_vpn.charon import ppk_pattern
from acxelin_vpn.controller import LABEL as IPSEC_LABEL, context
from acxelin_vpn.platforms import LinuxKillSwitch, MacKillSwitch, WGError
from acxelin_vpn.policies import POLICY
from acxelin_vpn.wireguard import LABEL as WG_LABEL

INVITE = {"name": "alice", "enroll": "https://ca.example:9443", "ca_fingerprint": "ab" * 32, "gateway": "vpn.example:7443",
          "expires": "2099-01-01T00:00:00+00:00", "token": "t"}


def test_the_wire_protocol_is_the_suites():
    assert (IPSEC_LABEL, WG_LABEL) == ("EXPORTER-pqcsuite-ipsec-v1", "EXPORTER-pqcsuite-wireguard-v1")
    assert context("hq.acme", "branch.acme", "0123456789ab") == b"branch.acme|hq.acme|0123456789ab"
    assert ppk_pattern("hq.acme", "branch.acme") == "branch.acme.hq.acme.ppk.pqcsuite"
    assert (POLICY.groups, POLICY.sigalgs) == ("X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768", "mldsa87:mldsa65:mldsa44")


def test_an_invitation_from_the_suite_still_joins_with_a_warning(tmp_path, caplog):
    old = tmp_path / "alice.pqcinvite"
    old.write_text(json.dumps({"pqcsuite_invite": 1} | INVITE))
    with caplog.at_level(logging.WARNING):
        inv = join.read(old)
    assert inv["acxelin_invite"] == 1 and "pqcsuite_invite" not in inv and inv["name"] == "alice"
    assert "PQC Suite" in caplog.text and "acxelin-vpn invite" in caplog.text
    with pytest.raises(ValueError, match="not an Acxelin VPN invitation"):
        join.parse(json.dumps({"other": 1} | INVITE))


def test_the_app_finds_both_kinds_of_invitation_newest_first(tmp_path):
    (tmp_path / "a.pqcinvite").write_text("{}")
    newer = tmp_path / "b.acxinvite"
    newer.write_text("{}")
    assert app.App(folder=tmp_path).invitation == newer
    newer.unlink()
    assert app.App(folder=tmp_path).invitation == tmp_path / "a.pqcinvite"


def test_the_suites_folder_and_variables_are_read_until_the_new_ones_exist(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("ACXELIN_WIREGUARD_GO", raising=False)
    monkeypatch.setenv("PQCSUITE_WIREGUARD_GO", "/opt/wg-go")
    assert legacy.home() == tmp_path / ".acxelin-vpn"
    (tmp_path / ".pqcsuite" / "vpn").mkdir(parents=True)
    with caplog.at_level(logging.WARNING):
        assert legacy.home() == tmp_path / ".pqcsuite" / "vpn"
        assert legacy.env("WIREGUARD_GO") == "/opt/wg-go"
    assert "PQCSUITE_WIREGUARD_GO" in caplog.text and "ACXELIN_WIREGUARD_GO" in caplog.text
    (tmp_path / ".acxelin-vpn").mkdir()
    monkeypatch.setenv("ACXELIN_WIREGUARD_GO", "/usr/bin/wireguard-go")
    assert legacy.home() == tmp_path / ".acxelin-vpn" and legacy.env("WIREGUARD_GO") == "/usr/bin/wireguard-go"


class Iptables:
    """iptables' OUTPUT chain and user chains, enough to say at every step whether a packet to elsewhere would leave."""
    def __init__(self, chains=None):
        self.chains = {"OUTPUT": []} | (chains or {})
        self.history = []

    def __call__(self, cmd):
        tool, op, *rest = cmd
        if tool != "iptables":
            raise WGError("no IPv6 here")
        c = self.chains
        if op == "-N":
            c[rest[0]] = []
        elif op == "-A":
            c[rest[0]].append(rest[1:])
        elif op == "-I":
            c[rest[0]].insert(int(rest[1]) - 1, rest[2:])
        elif op == "-D":
            if rest[1:] not in c[rest[0]]:
                raise WGError("no such rule")
            c[rest[0]].remove(rest[1:])
        elif op in ("-F", "-X"):
            if rest[0] not in c:
                raise WGError("no such chain")
            if op == "-F":
                c[rest[0]] = []
            else:
                c.pop(rest[0])
        elif op == "-E":
            c[rest[1]] = c.pop(rest[0])
            c["OUTPUT"] = [r if r != ["-j", rest[0]] else ["-j", rest[1]] for r in c["OUTPUT"]]
        self.history.append(self.blocked())
        return ""

    def blocked(self):
        """Would a packet to an unrelated address be rejected right now?"""
        for rule in self.chains["OUTPUT"]:
            chain = self.chains.get(rule[-1], [])
            if chain and chain[-1] == ["-j", "REJECT"]:
                return True
        return False


def test_an_upgrade_swaps_the_suites_linux_kill_switch_without_a_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(platforms, "ipv6", lambda: False)
    fw = Iptables({"PQCSUITE-KILLSWITCH": [["-o", "wg0", "-j", "ACCEPT"], ["-j", "REJECT"]]})
    fw.chains["OUTPUT"] = [["-j", "PQCSUITE-KILLSWITCH"]]
    ks = LinuxKillSwitch(tmp_path, fw)
    ks.on("wg0", (["203.0.113.1"], 51820), (["203.0.113.1"], 7443))
    assert all(fw.history), "traffic could leave during the swap"
    assert fw.chains["OUTPUT"] == [["-j", "ACXELIN-KILLSWITCH"]] and "PQCSUITE-KILLSWITCH" not in fw.chains
    ks.off()
    assert fw.chains == {"OUTPUT": []}


def test_off_also_lifts_a_kill_switch_the_suite_left_behind(tmp_path):
    fw = Iptables({"PQCSUITE-KILLSWITCH": [["-j", "REJECT"]]})
    fw.chains["OUTPUT"] = [["-j", "PQCSUITE-KILLSWITCH"]]
    LinuxKillSwitch(tmp_path, fw).off()
    assert fw.chains == {"OUTPUT": []}


class Pf:
    def __init__(self, old_token):
        self.anchors, self.tokens, self.history = {"com.apple/pqcsuite": "old rules"}, {old_token}, []

    def __call__(self, cmd):
        args = cmd[1:]
        if args[0] == "-a" and args[2] == "-f":
            self.anchors[args[1]] = "rules"
        elif args[0] == "-a" and args[2] == "-F":
            self.anchors.pop(args[1], None)
        elif args == ["-E"]:
            self.tokens.add("new")
            self.history.append(self.enabled())
            return "Token : new\n"
        elif args[0] == "-X":
            self.tokens.discard(args[1])
        self.history.append(self.enabled())
        return ""

    def enabled(self):
        return bool(self.tokens) and bool(self.anchors)


def test_an_upgrade_swaps_the_suites_mac_anchor_and_releases_its_pf_reference(tmp_path, monkeypatch):
    old = tmp_path / "old"
    old.mkdir()
    (old / "killswitch.token").write_text("old-token")
    monkeypatch.setattr(MacKillSwitch, "OLD_FOLDER", old)
    pf = Pf("old-token")
    ks = MacKillSwitch(tmp_path, pf)
    ks.on("utun4", (["203.0.113.1"], 51820), (["203.0.113.1"], 7443))
    assert all(pf.history), "pf was off, or had no rules, during the swap"
    assert set(pf.anchors) == {"com.apple/acxelin-vpn"} and pf.tokens == {"new"} and not (old / "killswitch.token").exists()
    ks.off()
    assert pf.anchors == {} and pf.tokens == set()


def test_installing_the_service_removes_the_suites(tmp_path, monkeypatch):
    paths = {name: tmp_path / f"{name}.service" for name in (platforms.SERVICE, platforms.OLD_SERVICE)}
    real = platforms.service
    monkeypatch.setattr(platforms, "service", lambda argv, kind=None, name=platforms.SERVICE: (paths[name], *real(argv, "Linux", name)[1:]))
    paths[platforms.OLD_SERVICE].write_text("old")
    ran = []
    platforms.install(["acxelin-vpn", "connect"], ran.append)
    assert not paths[platforms.OLD_SERVICE].exists() and paths[platforms.SERVICE].exists()
    assert ran[0] == ["systemctl", "disable", "--now", "pqcsuite-vpn"] and ["systemctl", "enable", "--now", "acxelin-vpn"] in ran
    ran.clear()
    platforms.install(["acxelin-vpn", "connect"], ran.append)
    assert ["systemctl", "disable", "--now", "pqcsuite-vpn"] not in ran, "nothing to remove once the suite's service is gone"
