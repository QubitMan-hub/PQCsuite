"""The built-wheel install test: Acxelin VPN's wheels installed into a fresh environment outside the repository, with no index
and no editable installs, then a CA, an invitation and the console from the installed copy. Slow; runs when
ACXELIN_INSTALL_TEST=1 (always in CI)."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(os.environ.get("ACXELIN_INSTALL_TEST") != "1", reason="set ACXELIN_INSTALL_TEST=1")


def test_wheels_install_alone_and_the_product_works(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from wheelhouse import build
    house = build("vpn", tmp_path / "wheelhouse", "[vpn]")
    env_dir = tmp_path / "env"
    venv.create(env_dir, with_pip=True)
    bin_ = env_dir / ("Scripts" if os.name == "nt" else "bin")
    clean = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV")}
    run = lambda *cmd: subprocess.run(cmd, cwd=tmp_path, env=clean, capture_output=True, text=True, check=True)
    run(str(bin_ / "python"), "-m", "pip", "install", "--quiet", "--no-index", "--find-links", str(house), "acxelin-vpn[vpn]")
    installed = {d["name"].lower(): d for d in json.loads(run(str(bin_ / "python"), "-m", "pip", "list", "--format", "json", "-v").stdout)}
    assert {"acxelin-vpn", "acxelin-core", "vici"} <= set(installed)
    assert not any("editable_project_location" in d for d in installed.values())
    assert not set(installed) & {"pqcsuite", "acxelin-readiness", "acxelin-tls", "acxelin-vault"}
    cli = str(bin_ / "acxelin-vpn")
    assert run(cli, "--version").stdout.strip() == "acxelin-vpn 1.0.0"
    doctor = subprocess.run([cli, "doctor", "--json"], cwd=tmp_path, env=clean, capture_output=True, text=True)
    assert doctor.returncode in (0, 3), doctor.stderr  # 3: this machine's OpenSSL is older than 3.5, and doctor says so
    assert json.loads(doctor.stdout)["checks"][0]["product"] == "key agreement"
    pki = tmp_path / "pki"
    run(cli, "ca", "init", "--name", "Wheel VPN Root", "--dir", str(pki), "--no-encrypt")
    run(cli, "ca", "issue", "server", "vpn.example.invalid", "--dir", str(pki), "--out", str(tmp_path / "gw"))
    run(cli, "invite", "alice", "--dir", str(pki), "--enroll", "https://ca.example.invalid:9443", "--gateway", "vpn.example.invalid:7443",
        "--out", str(tmp_path / "alice.acxinvite"))
    assert (tmp_path / "alice.acxinvite").stat().st_size > 100
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen([cli, "console", "--no-browser", "--port", str(port), "--home", str(tmp_path / "home")], cwd=tmp_path, env=clean,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).read().decode()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("the console did not start")
        assert "Acxelin VPN" in page and "data:font/woff2;base64," in page and "sessionStorage" in page
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2)
        assert refused.value.code == 401
    finally:
        server.terminate()
        server.wait(10)
