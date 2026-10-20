"""The built-wheel install test: wheels installed into a fresh environment outside the repository, with no index and no editable
installs, then the product's smoke journey. Slow; runs when ACXELIN_INSTALL_TEST=1 (always in CI)."""
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
from acxelin_tls import __version__

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(os.environ.get("ACXELIN_INSTALL_TEST") != "1", reason="set ACXELIN_INSTALL_TEST=1")


def test_wheels_install_alone_and_the_product_works(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from wheelhouse import build
    house = build("tls", tmp_path / "wheelhouse")
    env_dir = tmp_path / "env"
    venv.create(env_dir, with_pip=True)
    bin_ = env_dir / ("Scripts" if os.name == "nt" else "bin")
    clean = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV")}
    run = lambda *cmd: subprocess.run(cmd, cwd=tmp_path, env=clean, capture_output=True, text=True, check=True)
    run(str(bin_ / "python"), "-m", "pip", "install", "--quiet", "--no-index", "--find-links", str(house), "acxelin-tls")
    installed = {d["name"].lower(): d for d in json.loads(run(str(bin_ / "python"), "-m", "pip", "list", "--format", "json", "-v").stdout)}
    assert "acxelin-tls" in installed and "acxelin-core" in installed
    assert not any("editable_project_location" in d for d in installed.values())
    assert not set(installed) & {"acxelin-readiness", "acxelin-vpn"}
    where = run(str(bin_ / "python"), "-c", "import acxelin_tls, acxelin_core; print(acxelin_tls.__file__); print(acxelin_core.__file__)").stdout.split()
    assert all(str(env_dir) in w for w in where), where
    lic = run(str(bin_ / "python"), "-c", "import importlib.metadata as m\nfor d in ('acxelin-tls', 'acxelin-core'):\n"
              "    dist = m.distribution(d); print(any(f.name == 'LICENSE' for f in dist.files), 'Proprietary' in ' '.join(dist.metadata.get_all('Classifier')))").stdout
    assert lic.split() == ["True", "True", "True", "True"], lic
    cli = str(bin_ / "acxelin-tls")
    assert run(cli, "--version").stdout.strip() == f"acxelin-tls {__version__}"
    # the CA commands work from the wheel, with no other product
    pki = tmp_path / "pki"
    run(cli, "ca", "init", "--name", "Wheel CA", "--dir", str(pki), "--no-encrypt")
    run(cli, "ca", "issue", "server", "web.example.invalid", "--dir", str(pki), "--out", str(tmp_path / "web"))
    assert "web.example.invalid" in run(cli, "ca", "list", "--dir", str(pki)).stdout
    # the console starts from the installed wheel: its page, fonts and script ship, and nothing works without a session
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
        assert "Acxelin TLS" in page and "data:font/woff2;base64," in page and "sessionStorage" in page
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2)
        assert refused.value.code == 401
        assert (tmp_path / "home/console.token").exists()
    finally:
        server.terminate()
        server.wait(10)
