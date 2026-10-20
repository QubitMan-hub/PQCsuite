"""What ships to run Acxelin VPN as a service: every systemd unit, the gateway image's entrypoint and the desktop package start
commands that exist, with the files they name, so a typo in a unit fails here and not on a customer's gateway."""
import configparser
import shlex
from pathlib import Path

import pytest

from acxelin_vpn import cli

ROOT = Path(__file__).resolve().parents[1]
UNITS = sorted((ROOT / "deploy/systemd").iterdir())


def unit(path):
    p = configparser.ConfigParser(strict=False, interpolation=None)
    p.optionxform = str
    p.read_string(path.read_text())
    return p


def parses(argv):
    return cli.parser().parse_args(argv)


def test_the_units_the_plan_names_are_all_there():
    assert {u.name for u in UNITS} == {"acxelin-vpn-ipsec.service", "acxelin-vpn-wireguard.service", "strongswan-pqc.service",
                                       "acxelin-vpn-enroll.service", "acxelin-vpn-ca-maintain.service", "acxelin-vpn-ca-maintain.timer"}


@pytest.mark.parametrize("path", [u for u in UNITS if u.suffix == ".service" and u.name != "strongswan-pqc.service"], ids=lambda u: u.name)
def test_each_service_runs_a_real_command_on_the_file_it_waits_for(path):
    s = unit(path)
    exe, *argv = shlex.split(s["Service"]["ExecStart"])
    assert exe == "/opt/acxelin-vpn/bin/acxelin-vpn"
    a = parses(argv)
    wanted = s["Unit"]["ConditionPathExists"]
    named = getattr(a, "config", None) or f"{a.dir}/ca.crt"
    assert named == wanted, (named, wanted)
    assert s["Service"].get("NoNewPrivileges") == "yes" and s["Service"].get("PrivateTmp") == "yes"


def test_the_ipsec_controller_starts_after_strongswan_and_the_timer_runs_maintenance():
    ipsec = unit(ROOT / "deploy/systemd/acxelin-vpn-ipsec.service")["Unit"]
    assert "strongswan-pqc.service" in ipsec["Requires"] and "strongswan-pqc.service" in ipsec["After"]
    assert unit(ROOT / "deploy/systemd/acxelin-vpn-ca-maintain.timer")["Timer"]["OnCalendar"] == "daily"
    assert "maintain" in unit(ROOT / "deploy/systemd/acxelin-vpn-ca-maintain.service")["Service"]["ExecStart"]


def test_the_gateway_image_runs_a_real_command_and_starts_charon_only_for_up():
    docker = (ROOT / "deploy/Dockerfile").read_text()
    cmd = next(line for line in docker.splitlines() if line.startswith("CMD "))
    assert parses(__import__("json").loads(cmd[4:])).cmd == "up"
    entry = (ROOT / "deploy/entrypoint.sh").read_text()
    assert 'if [ "${1:-}" = up ]' in entry and 'exec acxelin-vpn "$@"' in entry
    assert "STRONGSWAN=6.1.0" in docker and "STRONGSWAN_SHA256=" in docker
    assert "COPY --from=strongswan /etc/strongswan.d /etc/strongswan.d" in docker, "without its plugin settings charon loads nothing and exits"


def test_the_desktop_package_opens_the_desktop_app_and_starts_at_login_in_the_tray():
    launcher = (ROOT / "packaging/launcher.py").read_text()
    assert 'main(sys.argv[1:] or ["desktop"])' in launcher
    assert parses(["desktop", "--background"]).cmd == "desktop"
    build = (ROOT / "packaging/build.py").read_text()
    assert '"" desktop --background"' in build


def test_doctor_reports_the_machine_as_json_for_the_package_check(capsys):
    with pytest.raises(SystemExit):
        cli.main(["doctor", "--json"])
    report = __import__("json").loads(capsys.readouterr().out)
    assert report["version"] == "1.0.0" and report["checks"][0]["product"] == "key agreement"
