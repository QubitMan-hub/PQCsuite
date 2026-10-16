"""The built-wheel install test: wheels installed into a fresh environment outside the repository, with no index and no
editable installs, then the product's smoke journey. Slow; runs when ACXELIN_INSTALL_TEST=1 (always in CI)."""
import json
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(os.environ.get("ACXELIN_INSTALL_TEST") != "1", reason="set ACXELIN_INSTALL_TEST=1")


def test_wheels_install_alone_and_the_product_works(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from wheelhouse import build
    house = build("readiness", tmp_path / "wheelhouse")
    env_dir = tmp_path / "env"
    venv.create(env_dir, with_pip=True)
    bin_ = env_dir / ("Scripts" if os.name == "nt" else "bin")
    clean = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV")}
    run = lambda *cmd: subprocess.run(cmd, cwd=tmp_path, env=clean, capture_output=True, text=True, check=True)
    run(str(bin_ / "python"), "-m", "pip", "install", "--quiet", "--no-index", "--find-links", str(house), "acxelin-readiness")
    installed = {d["name"].lower(): d for d in json.loads(run(str(bin_ / "python"), "-m", "pip", "list", "--format", "json", "-v").stdout)}
    assert "acxelin-readiness" in installed and "acxelin-core" in installed
    assert not any("editable_project_location" in d for d in installed.values())
    assert not set(installed) & {"pqcsuite", "wolfpack-cbom", "acxelin-tls", "acxelin-vpn", "acxelin-vault"}
    where = run(str(bin_ / "python"), "-c", "import acxelin_readiness, acxelin_core; print(acxelin_readiness.__file__); print(acxelin_core.__file__)").stdout.split()
    assert all(str(env_dir) in w for w in where), where
    project = tmp_path / "project"
    shutil.copytree(ROOT / "tests/golden/readiness/project", project)
    run(str(bin_ / "acxelin-readiness"), "scan", str(project), "-o", str(tmp_path / "out"), "-q")
    bom = json.loads((tmp_path / "out/cbom.json").read_text())
    assert bom["specVersion"] == "1.6" and any(c["name"].startswith("RSA") for c in bom["components"])
    report = (tmp_path / "out/report.html").read_text()
    assert "@font-face" in report and "Acxelin Readiness" in report
    assert "full TLS handshakes" in run(str(bin_ / "acxelin-readiness"), "doctor").stdout
    assert run(str(bin_ / "acxelin-readiness"), "--version").stdout.strip() == "1.0.0"
    # the console starts from the installed wheel: its page, fonts and script ship, and nothing works without a session
    import socket
    import time
    import urllib.error
    import urllib.request
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen([str(bin_ / "acxelin-readiness"), "console", "--no-browser", "--port", str(port), "--home", str(tmp_path / "home")],
                              cwd=tmp_path, env=clean, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).read().decode()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("the console did not start")
        assert "Acxelin Readiness" in page and "data:font/woff2;base64," in page and "sessionStorage" in page
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2)
        assert refused.value.code == 401
        assert (tmp_path / "home/console.token").exists()
    finally:
        server.terminate()
        server.wait(10)
